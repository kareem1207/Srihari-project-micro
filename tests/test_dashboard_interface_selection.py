"""Dashboard interface-selection tests without device access or packet capture."""
import os
import time
import unittest
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication, QComboBox, QLabel, QListWidget, QPushButton

from app.security.network_monitor import NetworkInterface
from app.security.usb_checker import STATUS_APPROVED, USBAdapterStatus
from app.ui.dashboard_window import DashboardWindow


class DashboardInterfaceSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_approved_interface_becomes_the_default_selection(self) -> None:
        first = NetworkInterface("WAN Miniport", r"\\Device\\NPF_WAN", approved=False)
        approved = NetworkInterface(
            "Wi-Fi 2", r"\\Device\\NPF_USB",
            description="Realtek RTL8188CU Wireless LAN 802.11n USB 2.0 Network Adapter",
            approved=True,
        )
        dashboard = SimpleNamespace(
            network_interface_combo=QComboBox(),
            network_error_label=QLabel(),
            start_monitoring_button=QPushButton(),
            refresh_interfaces_button=QPushButton(),
            network_monitor=SimpleNamespace(selection_error=None),
        )

        DashboardWindow._interfaces_loaded(dashboard, [first, approved])

        self.assertIs(dashboard.network_interface_combo.currentData(), approved)
        self.assertIn("APPROVED", dashboard.network_interface_combo.currentText())
        self.assertTrue(dashboard.start_monitoring_button.isEnabled())

    def test_no_approved_interface_uses_fail_closed_placeholder(self) -> None:
        unapproved = NetworkInterface("WAN Miniport", r"\\Device\\NPF_WAN", approved=False)
        dashboard = SimpleNamespace(
            network_interface_combo=QComboBox(),
            network_error_label=QLabel(),
            start_monitoring_button=QPushButton(),
            refresh_interfaces_button=QPushButton(),
            network_monitor=SimpleNamespace(
                selection_error="The approved USB adapter was found, but its Scapy interface could not be matched."
            ),
        )

        DashboardWindow._interfaces_loaded(dashboard, [unapproved])

        self.assertIsNone(dashboard.network_interface_combo.currentData())
        self.assertIn("No approved USB Wi-Fi interface", dashboard.network_interface_combo.currentText())
        self.assertFalse(dashboard.start_monitoring_button.isEnabled())
        self.assertIn("could not be matched", dashboard.network_error_label.text())

    def test_start_refuses_an_unapproved_interface_without_queueing_capture(self) -> None:
        unapproved = NetworkInterface("WAN Miniport", r"\\Device\\NPF_WAN", approved=False)
        dashboard = SimpleNamespace(
            network_interface_combo=QComboBox(),
            network_error_label=QLabel(),
            start_monitoring_button=QPushButton(),
            stop_monitoring_button=QPushButton(),
            queued=False,
        )
        dashboard.network_interface_combo.addItem("WAN Miniport [not approved]", unapproved)
        dashboard._run_network_action = lambda *_args, **_kwargs: setattr(dashboard, "queued", True)

        DashboardWindow.start_network_monitoring(dashboard)

        self.assertFalse(dashboard.queued)
        self.assertFalse(dashboard.start_monitoring_button.isEnabled())
        self.assertIn("approved USB Wi-Fi", dashboard.network_error_label.text())

    def test_system_status_is_not_verified_while_usb_check_is_pending_or_unknown(self) -> None:
        dashboard = self._system_status_dashboard(active=False)

        DashboardWindow._refresh_system_status(dashboard)
        self.assertEqual(dashboard.system_status_label.text(), "Not verified")
        self.assertIn("verification is pending", dashboard.system_status_details_label.text())

        dashboard._latest_usb_status = USBAdapterStatus(
            status="unknown",
            detected=False,
            approved=False,
            reason="Adapter status could not be determined.",
        )
        DashboardWindow._refresh_system_status(dashboard)

        self.assertEqual(dashboard.system_status_label.text(), "Not verified")
        self.assertIn("could not be determined", dashboard.system_status_details_label.text())

    def test_system_status_does_not_treat_usb_approval_or_monitoring_as_full_verification(self) -> None:
        dashboard = self._system_status_dashboard(active=False)
        dashboard._latest_usb_status = USBAdapterStatus(
            status=STATUS_APPROVED,
            detected=True,
            approved=True,
        )

        DashboardWindow._refresh_system_status(dashboard)
        self.assertEqual(dashboard.system_status_label.text(), "Partially verified")
        self.assertIn("overall system verification is not implemented", dashboard.system_status_details_label.text())

        dashboard.network_monitor.active = True
        DashboardWindow._refresh_system_status(dashboard)
        self.assertEqual(dashboard.system_status_label.text(), "Partially verified")
        self.assertIn("network monitoring are active", dashboard.system_status_details_label.text())
        self.assertNotEqual(dashboard.system_status_label.text(), "Verified")

    def test_system_status_refreshes_after_a_failed_usb_check(self) -> None:
        dashboard = self._system_status_dashboard(active=True)
        dashboard._latest_usb_status = USBAdapterStatus(
            status=STATUS_APPROVED,
            detected=True,
            approved=True,
        )
        DashboardWindow._refresh_system_status(dashboard)
        self.assertEqual(dashboard.system_status_label.text(), "Partially verified")

        failed = USBAdapterStatus(
            status="not_approved",
            detected=True,
            approved=False,
            reason="The adapter does not match the local policy.",
        )
        DashboardWindow._display_usb_status(dashboard, failed)

        self.assertEqual(dashboard.system_status_label.text(), "Not verified")
        self.assertIn("does not match", dashboard.system_status_details_label.text())

    def test_periodic_ids_refresh_does_not_reload_event_history(self) -> None:
        service = SimpleNamespace(
            model_status="LOADED",
            inference_enabled=False,
            status_message="unused",
            flows_checked=0,
            detections=0,
            events=(),
            analysis_active=False,
            load_recent_events=lambda limit: self.fail("refresh must not read SQLite"),
        )
        dashboard = SimpleNamespace(
            ids_service=service,
            network_monitor=SimpleNamespace(is_active=lambda: False),
            ids_model_status_label=QLabel(),
            ids_inference_status_label=QLabel(),
            ids_monitoring_status_label=QLabel(),
            ids_flow_count_label=QLabel(),
            ids_detection_count_label=QLabel(),
            ids_latest_event_label=QLabel(),
            ids_event_log=QListWidget(),
            start_ids_button=QPushButton(),
            stop_ids_button=QPushButton(),
            _persisted_events=(),
        )

        DashboardWindow._refresh_ids_snapshot(dashboard)
        DashboardWindow._refresh_ids_snapshot(dashboard)

        self.assertEqual(dashboard.ids_event_log.item(0).text(), "No saved prediction events yet.")

    def test_asynchronous_history_load_failure_is_reported_without_raising(self) -> None:
        class FailingService:
            def load_recent_events(self, limit: int):
                raise OSError("temporary database unavailable")

        class Harness:
            def __init__(self) -> None:
                self.ids_service = FailingService()
                self._thread_pool = QThreadPool()
                self._event_history_worker = None
                self.result = object()
                self.error = None

            def _recent_events_loaded(self, result, error) -> None:
                self.result = result
                self.error = error

        dashboard = Harness()
        DashboardWindow._load_recent_events(dashboard)
        dashboard._thread_pool.waitForDone(1000)
        for _ in range(20):
            self.application.processEvents()
            if dashboard.error is not None:
                break
            time.sleep(0.01)

        self.assertIsNone(dashboard.result)
        self.assertIsInstance(dashboard.error, OSError)

    @staticmethod
    def _system_status_dashboard(active: bool) -> SimpleNamespace:
        monitor = SimpleNamespace(active=active)
        monitor.is_active = lambda: monitor.active
        dashboard = SimpleNamespace(
            _latest_usb_status=None,
            network_monitor=monitor,
            system_status_label=QLabel(),
            system_status_details_label=QLabel(),
            usb_refresh_button=QPushButton(),
            usb_status_label=QLabel(),
            usb_details_label=QLabel(),
        )
        dashboard._refresh_system_status = lambda: DashboardWindow._refresh_system_status(dashboard)
        return dashboard


if __name__ == "__main__":
    unittest.main()
