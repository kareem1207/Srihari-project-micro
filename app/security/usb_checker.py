"""Read-only verification of an administrator-approved USB Wi-Fi adapter."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

STATUS_APPROVED = "approved"
STATUS_NOT_DETECTED = "not_detected"
STATUS_NOT_APPROVED = "not_approved"
STATUS_UNKNOWN = "unknown"

_WIFI_PHYSICAL_MEDIA = {1, 9}  # Wireless LAN and Native 802.11 (NDIS)
_WIFI_DESCRIPTION = re.compile(r"\b(wi[ -]?fi|wireless|802\.11)\b", re.IGNORECASE)
_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
    $adapters = @(Get-CimInstance -Namespace 'root/StandardCimv2' `
        -ClassName 'MSFT_NetAdapter' -ErrorAction Stop |
        Select-Object InterfaceName, InterfaceDescription, PNPDeviceID,
                      NdisPhysicalMedium, HardwareInterface, Virtual)
    ConvertTo-Json -InputObject $adapters -Compress -Depth 3
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""


@dataclass(frozen=True)
class USBAdapterStatus:
    """Result of one adapter verification attempt."""

    status: str
    detected: bool
    approved: bool
    adapter_name: str | None = None
    interface_name: str | None = None
    interface_description: str | None = None
    device_id: str | None = None
    connection_type: str = "unknown"
    reason: str = ""
    error: str | None = None


class USBAdapterChecker:
    """Enumerate Windows network adapters and compare USB Wi-Fi devices to policy.

    ``adapter_provider`` is injectable so policy and classification behavior can
    be exercised without Windows APIs or physical adapter hardware.
    """

    def __init__(
        self,
        policy_path: str | Path | None = None,
        adapter_provider: Callable[[], Iterable[Mapping[str, Any]]] | None = None,
    ) -> None:
        project_root = Path(__file__).resolve().parents[2]
        self.policy_path = Path(policy_path) if policy_path else (
            project_root / "config" / "device_policy.json"
        )
        self._adapter_provider = adapter_provider or self._enumerate_windows_adapters

    def check(self) -> USBAdapterStatus:
        """Return the current status without changing any device configuration."""
        logger.info("Enumerating Windows network adapters for USB Wi-Fi verification")
        try:
            records = list(self._adapter_provider())
        except Exception as exc:
            logger.error("Network adapter enumeration failed: %s", exc)
            return self._unknown(f"Unable to enumerate network adapters: {exc}", error=str(exc))

        logger.info("Network adapter enumeration returned %d adapter(s)", len(records))
        usb_wifi: list[dict[str, str | None]] = []
        uncertain_wifi: list[dict[str, str | None]] = []

        for record in records:
            if not isinstance(record, Mapping):
                logger.error("Network adapter enumeration returned an invalid record")
                return self._unknown("Windows returned adapter data in an unexpected format.")

            details = self._adapter_details(record)
            if details is None:
                continue
            category, adapter = details
            if category == "usb_wifi":
                usb_wifi.append(adapter)
            elif category == "uncertain_wifi":
                uncertain_wifi.append(adapter)

        for adapter in usb_wifi:
            logger.info(
                "Detected USB Wi-Fi adapter: name=%r interface=%r device_id=%r",
                adapter["adapter_name"], adapter["interface_name"], adapter["device_id"],
            )

        if not usb_wifi:
            if uncertain_wifi:
                adapter = uncertain_wifi[0]
                if adapter.get("connection_type") == "USB":
                    reason = (
                        "A USB network adapter was found, but Windows did not expose "
                        "enough information to confirm that it is Wi-Fi."
                    )
                else:
                    reason = (
                        "A possible Wi-Fi adapter was found, but Windows did not expose "
                        "enough bus information to confirm that it is connected through USB."
                    )
                logger.warning("USB adapter connection type is unknown: %s", reason)
                return self._unknown(reason, adapter=adapter)
            logger.info("No USB-connected Wi-Fi adapter was detected")
            return USBAdapterStatus(
                status=STATUS_NOT_DETECTED,
                detected=False,
                approved=False,
                connection_type="unknown",
                reason="No USB-connected Wi-Fi adapter was detected.",
            )

        try:
            approvals = self._load_approvals()
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            logger.error("USB adapter policy could not be read: %s", exc)
            return self._unknown(f"Unable to read the USB adapter policy: {exc}", error=str(exc))

        approved_adapter = next(
            (adapter for adapter in usb_wifi if self._matches_policy(adapter, approvals)),
            None,
        )
        if approved_adapter is not None:
            logger.info("USB Wi-Fi adapter approval decision: approved")
            return self._result(
                STATUS_APPROVED,
                approved=True,
                adapter=approved_adapter,
                reason="The detected USB Wi-Fi adapter matches the local device policy.",
            )

        adapter = usb_wifi[0]
        if not any(self._has_identity(entry) for entry in approvals):
            reason = "A USB Wi-Fi adapter is detected, but no approved adapter is configured."
        else:
            reason = "A USB Wi-Fi adapter is detected, but it does not match the local device policy."
        logger.warning("USB Wi-Fi adapter approval decision: not approved (%s)", reason)
        return self._result(
            STATUS_NOT_APPROVED,
            approved=False,
            adapter=adapter,
            reason=reason,
        )

    def _enumerate_windows_adapters(self) -> list[dict[str, Any]]:
        if os.name != "nt":
            raise OSError("USB Wi-Fi adapter enumeration is supported on Windows only.")

        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL_SCRIPT],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or "PowerShell adapter query failed."
            raise RuntimeError(message)

        try:
            data = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise ValueError("PowerShell returned invalid adapter data.") from exc
        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list) and all(isinstance(item, dict) for item in data):
            return data
        raise ValueError("PowerShell returned adapter data in an unexpected format.")

    def _load_approvals(self) -> list[dict[str, str]]:
        if not self.policy_path.exists():
            logger.warning("USB adapter policy file is missing: %s", self.policy_path)
            return []

        with self.policy_path.open("r", encoding="utf-8") as policy_file:
            policy = json.load(policy_file)
        if not isinstance(policy, dict):
            raise ValueError("The device policy must be a JSON object.")
        approvals = policy.get("approved_usb_wifi_adapters")
        if not isinstance(approvals, list):
            raise ValueError("approved_usb_wifi_adapters must be a JSON list.")

        normalized: list[dict[str, str]] = []
        for entry in approvals:
            if not isinstance(entry, dict):
                raise ValueError("Each approved adapter entry must be a JSON object.")
            name = entry.get("name", "")
            device_id = entry.get("device_id", "")
            if not isinstance(name, str) or not isinstance(device_id, str):
                raise ValueError("Adapter name and device_id values must be strings.")
            normalized.append({"name": name.strip(), "device_id": device_id.strip()})
        return normalized

    @staticmethod
    def _adapter_details(
        record: Mapping[str, Any],
    ) -> tuple[str, dict[str, str | None]] | None:
        name = USBAdapterChecker._get(record, "InterfaceDescription")
        interface = USBAdapterChecker._get(record, "InterfaceName")
        device_id = USBAdapterChecker._get(record, "PNPDeviceID", "PnPDeviceID")
        medium = USBAdapterChecker._get(record, "NdisPhysicalMedium")
        virtual = USBAdapterChecker._get(record, "Virtual")
        hardware = USBAdapterChecker._get(record, "HardwareInterface")

        if virtual is True or hardware is False:
            return None

        normalized_device_id = str(device_id or "").strip().upper()
        is_usb = normalized_device_id.startswith("USB\\")
        has_bus_identity = bool(normalized_device_id)
        adapter = {
            "adapter_name": str(name or interface or "Unknown adapter"),
            "interface_name": str(interface) if interface else None,
            "interface_description": str(name) if name else None,
            "device_id": str(device_id) if device_id else None,
            "connection_type": "USB" if is_usb else "unknown",
        }

        try:
            medium_id = int(medium) if medium is not None else None
        except (TypeError, ValueError):
            medium_id = None
        description = " ".join(str(value or "") for value in (name, interface))
        description_says_wifi = bool(_WIFI_DESCRIPTION.search(description))
        is_wifi = medium_id in _WIFI_PHYSICAL_MEDIA or description_says_wifi
        medium_is_known_non_wifi = medium_id is not None and medium_id not in (0, *_WIFI_PHYSICAL_MEDIA)

        if medium_is_known_non_wifi:
            return None
        if not is_wifi:
            if is_usb and medium_id in (None, 0):
                return "uncertain_wifi", adapter
            return None
        if is_usb:
            return "usb_wifi", adapter
        if not has_bus_identity:
            return "uncertain_wifi", adapter
        return None

    @staticmethod
    def _get(record: Mapping[str, Any], *names: str) -> Any:
        wanted = {name.casefold() for name in names}
        for key, value in record.items():
            if str(key).casefold() in wanted:
                return value
        return None

    @staticmethod
    def _has_identity(entry: Mapping[str, str]) -> bool:
        return bool(entry.get("name", "").strip() or entry.get("device_id", "").strip())

    @staticmethod
    def _matches_policy(adapter: Mapping[str, str | None], approvals: list[dict[str, str]]) -> bool:
        adapter_names = {
            str(adapter.get(key) or "").strip().casefold()
            for key in ("adapter_name", "interface_name", "interface_description")
        }
        adapter_device_id = str(adapter.get("device_id") or "").strip().casefold()
        for entry in approvals:
            if not USBAdapterChecker._has_identity(entry):
                continue
            configured_name = entry["name"].casefold()
            configured_device_id = entry["device_id"].casefold()
            if configured_name and configured_name not in adapter_names:
                continue
            if configured_device_id and configured_device_id != adapter_device_id:
                continue
            return True
        return False

    @staticmethod
    def _result(
        status: str,
        approved: bool,
        adapter: Mapping[str, str | None],
        reason: str,
    ) -> USBAdapterStatus:
        return USBAdapterStatus(
            status=status,
            detected=True,
            approved=approved,
            adapter_name=adapter["adapter_name"],
            interface_name=adapter["interface_name"],
            interface_description=adapter["interface_description"],
            device_id=adapter["device_id"],
            connection_type="USB",
            reason=reason,
        )

    @staticmethod
    def _unknown(
        reason: str,
        adapter: Mapping[str, str | None] | None = None,
        error: str | None = None,
    ) -> USBAdapterStatus:
        adapter = adapter or {}
        return USBAdapterStatus(
            status=STATUS_UNKNOWN,
            detected=False,
            approved=False,
            adapter_name=adapter.get("adapter_name"),
            interface_name=adapter.get("interface_name"),
            interface_description=adapter.get("interface_description"),
            device_id=adapter.get("device_id"),
            connection_type=str(adapter.get("connection_type") or "unknown"),
            reason=reason,
            error=error,
        )
