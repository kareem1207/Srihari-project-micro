"""Unit tests for USB Wi-Fi adapter classification and local approval policy."""
import json
import tempfile
import unittest
from pathlib import Path

from app.security.usb_checker import (
    STATUS_APPROVED,
    STATUS_NOT_APPROVED,
    STATUS_NOT_DETECTED,
    STATUS_UNKNOWN,
    USBAdapterChecker,
)


class USBAdapterCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.policy_path = Path(self.temp_dir.name) / "device_policy.json"
        self.adapter = {
            "InterfaceName": "Wi-Fi 3",
            "InterfaceDescription": "USB Wireless Network Adapter",
            "PNPDeviceID": r"USB\VID_1234&PID_5678\DEVICE001",
            "NdisPhysicalMedium": 9,
            "HardwareInterface": True,
            "Virtual": False,
        }

    def write_policy(self, approvals: list[dict[str, str]]) -> None:
        self.policy_path.write_text(
            json.dumps({"approved_usb_wifi_adapters": approvals}),
            encoding="utf-8",
        )

    def checker(self, records, error: Exception | None = None) -> USBAdapterChecker:
        def provider():
            if error is not None:
                raise error
            return records

        return USBAdapterChecker(self.policy_path, adapter_provider=provider)

    def test_no_adapter_is_not_detected(self) -> None:
        self.write_policy([])
        result = self.checker([]).check()
        self.assertEqual(result.status, STATUS_NOT_DETECTED)
        self.assertFalse(result.detected)
        self.assertFalse(result.approved)

    def test_present_adapter_without_policy_match_is_not_approved(self) -> None:
        self.write_policy([{"name": "Different adapter", "device_id": "USB\\OTHER"}])
        result = self.checker([self.adapter]).check()
        self.assertEqual(result.status, STATUS_NOT_APPROVED)
        self.assertTrue(result.detected)
        self.assertFalse(result.approved)
        self.assertEqual(result.device_id, self.adapter["PNPDeviceID"])

    def test_matching_device_id_is_approved(self) -> None:
        self.write_policy([{"name": "", "device_id": self.adapter["PNPDeviceID"]}])
        result = self.checker([self.adapter]).check()
        self.assertEqual(result.status, STATUS_APPROVED)
        self.assertTrue(result.detected)
        self.assertTrue(result.approved)
        self.assertEqual(result.adapter_name, self.adapter["InterfaceDescription"])

    def test_provider_error_returns_unknown_without_raising(self) -> None:
        result = self.checker([], error=RuntimeError("CIM query failed")).check()
        self.assertEqual(result.status, STATUS_UNKNOWN)
        self.assertFalse(result.detected)
        self.assertFalse(result.approved)
        self.assertIn("CIM query failed", result.reason)
        self.assertEqual(result.error, "CIM query failed")

    def test_empty_approval_values_do_not_approve_adapter(self) -> None:
        self.write_policy([{"name": "", "device_id": ""}])
        result = self.checker([self.adapter]).check()
        self.assertEqual(result.status, STATUS_NOT_APPROVED)
        self.assertTrue(result.detected)
        self.assertFalse(result.approved)
        self.assertIn("no approved adapter is configured", result.reason)

    def test_internal_wifi_adapter_is_not_a_usb_adapter(self) -> None:
        self.write_policy([])
        internal_adapter = {
            **self.adapter,
            "PNPDeviceID": r"PCI\VEN_1234&DEV_5678",
        }
        result = self.checker([internal_adapter]).check()
        self.assertEqual(result.status, STATUS_NOT_DETECTED)

    def test_wifi_adapter_without_bus_identity_is_unknown(self) -> None:
        self.write_policy([])
        adapter_without_pnp_id = {key: value for key, value in self.adapter.items() if key != "PNPDeviceID"}
        result = self.checker([adapter_without_pnp_id]).check()
        self.assertEqual(result.status, STATUS_UNKNOWN)
        self.assertIn("enough bus information", result.reason)


if __name__ == "__main__":
    unittest.main()
