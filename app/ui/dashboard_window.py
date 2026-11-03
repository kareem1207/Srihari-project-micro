"""Placeholder SecureWork AI dashboard."""
import logging

from PySide6.QtCore import QObject, QRunnable, Qt, Signal, Slot, QThreadPool, QTimer
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton,
    QListWidget, QScrollArea, QVBoxLayout, QWidget,
)
from app.ml.predict import DEFAULT_MODEL_PATH
from app.security.flow_aggregator import LiveFlowAggregator
from app.security.ids_service import FeatureCompatibilityError, IDSService
from app.security.network_monitor import NetworkInterface, NetworkMonitor
from app.security.usb_checker import USBAdapterChecker, USBAdapterStatus, STATUS_APPROVED

logger = logging.getLogger(__name__)


class _USBCheckSignals(QObject):
    finished = Signal(object)


class _USBCheckWorker(QRunnable):
    def __init__(self, checker: USBAdapterChecker) -> None:
        super().__init__()
        self.checker = checker
        self.signals = _USBCheckSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self.checker.check()
        except Exception as exc:
            logger.exception("Unexpected USB adapter status check failure")
            result = USBAdapterStatus(
                status="unknown",
                detected=False,
                approved=False,
                reason=f"Unable to check the USB Wi-Fi adapter: {exc}",
                error=str(exc),
            )
        self._emit_finished(result)

    def _emit_finished(self, result: USBAdapterStatus) -> None:
        try:
            self.signals.finished.emit(result)
        except RuntimeError:
            # The dashboard may close while this best-effort status check runs.
            logger.debug("Discarding USB status result after dashboard teardown")


class _ActionSignals(QObject):
    finished = Signal(object, object)


class _ActionWorker(QRunnable):
    def __init__(self, action) -> None:
        super().__init__()
        self.action = action
        self.signals = _ActionSignals()

    @Slot()
    def run(self) -> None:
        try:
            self._emit_finished(self.action(), None)
        except Exception as exc:
            self._emit_finished(None, exc)

    def _emit_finished(self, result, error) -> None:
        try:
            self.signals.finished.emit(result, error)
        except RuntimeError:
            # The dashboard may close while a non-destructive worker completes.
            logger.debug("Discarding background action result after dashboard teardown")


class DashboardWindow(QMainWindow):
    def __init__(
        self,
        on_logout,
        usb_checker: USBAdapterChecker | None = None,
        network_monitor: NetworkMonitor | None = None,
    ) -> None:
        super().__init__()
        self._on_logout = on_logout
        self._usb_checker = usb_checker or USBAdapterChecker()
        self.network_monitor = network_monitor or NetworkMonitor(usb_checker=self._usb_checker)
        self.ids_service = IDSService(DEFAULT_MODEL_PATH)
        self.flow_aggregator = LiveFlowAggregator(on_flow_completed=self.ids_service.inspect_completed_flow)
        self._packet_callback = self.flow_aggregator.process_packet
        self.network_monitor.add_packet_callback(self._packet_callback)
        self._usb_worker: _USBCheckWorker | None = None
        self._ids_model_worker: _ActionWorker | None = None
        self._action_workers: set[_ActionWorker] = set()
        self._event_history_worker: _ActionWorker | None = None
        self._persisted_events = ()
        self._latest_usb_status: USBAdapterStatus | None = None
        self._active_action_worker: _ActionWorker | None = None
        self._active_action_success = None
        self._network_action_busy = False
        self._logout_pending = False
        self._close_pending = False
        self._thread_pool = QThreadPool.globalInstance()
        self.setWindowTitle("SecureWork AI | Dashboard")
        self.setMinimumSize(720, 520)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(36, 32, 36, 32)
        layout.setSpacing(18)

        title = QLabel("SecureWork AI")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Workspace security overview")
        subtitle.setObjectName("muted")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        ids_card = QFrame()
        ids_card.setObjectName("statusCard")
        ids_layout = QVBoxLayout(ids_card)
        ids_heading = QLabel("Intrusion Detection System")
        ids_heading.setObjectName("cardHeading")
        self.ids_model_status_label = QLabel("Model: Checking saved artifact...")
        self.ids_model_status_label.setObjectName("statusValue")
        self.ids_inference_status_label = QLabel(
            "Live IDS inference unavailable: feature compatibility incomplete."
        )
        self.ids_inference_status_label.setWordWrap(True)
        self.ids_monitoring_status_label = QLabel("Monitoring: STOPPED")
        self.ids_flow_count_label = QLabel("Completed flows checked: 0")
        self.ids_detection_count_label = QLabel("Attack signals: unavailable (inference disabled)")
        self.ids_latest_event_label = QLabel("Latest event: none; no compatible live predictions")
        self.ids_latest_event_label.setWordWrap(True)
        self.ids_event_log = QListWidget()
        self.ids_event_log.setMaximumHeight(110)
        self.ids_event_log.addItem("No prediction events; live inference is unavailable.")
        ids_buttons = QHBoxLayout()
        self.start_ids_button = QPushButton("Start IDS Analysis")
        self.stop_ids_button = QPushButton("Stop IDS Analysis")
        self.start_ids_button.setEnabled(False)
        self.stop_ids_button.setEnabled(False)
        self.start_ids_button.setToolTip("Disabled until all model features have verified live semantics.")
        self.stop_ids_button.setToolTip("No compatible live IDS analysis is active.")
        self.start_ids_button.clicked.connect(self.start_ids_analysis)
        self.stop_ids_button.clicked.connect(self.stop_ids_analysis)
        ids_buttons.addWidget(self.start_ids_button)
        ids_buttons.addWidget(self.stop_ids_button)
        for widget in (
            ids_heading,
            self.ids_model_status_label,
            self.ids_inference_status_label,
            self.ids_monitoring_status_label,
            self.ids_flow_count_label,
            self.ids_detection_count_label,
            self.ids_latest_event_label,
        ):
            ids_layout.addWidget(widget)
        ids_layout.addWidget(QLabel("Recent IDS events"))
        ids_layout.addWidget(self.ids_event_log)
        ids_layout.addLayout(ids_buttons)
        layout.addWidget(ids_card)

        system_card = QFrame()
        system_card.setObjectName("statusCard")
        system_layout = QVBoxLayout(system_card)
        system_heading = QLabel("System Status")
        system_heading.setObjectName("cardHeading")
        self.system_status_label = QLabel("Not verified")
        self.system_status_label.setObjectName("statusValue")
        self.system_status_details_label = QLabel()
        self.system_status_details_label.setObjectName("muted")
        self.system_status_details_label.setWordWrap(True)
        system_layout.addWidget(system_heading)
        system_layout.addWidget(self.system_status_label)
        system_layout.addWidget(self.system_status_details_label)
        layout.addWidget(system_card)

        usb_card = QFrame()
        usb_card.setObjectName("statusCard")
        usb_layout = QVBoxLayout(usb_card)
        usb_header = QHBoxLayout()
        usb_heading = QLabel("USB Wi-Fi Adapter")
        usb_heading.setObjectName("cardHeading")
        self.usb_refresh_button = QPushButton("Refresh")
        self.usb_refresh_button.setObjectName("secondaryButton")
        self.usb_refresh_button.clicked.connect(self.refresh_usb_status)
        usb_header.addWidget(usb_heading)
        usb_header.addStretch(1)
        usb_header.addWidget(self.usb_refresh_button)
        self.usb_status_label = QLabel("Status: CHECKING")
        self.usb_status_label.setObjectName("statusValue")
        self.usb_details_label = QLabel("Windows adapter information is being checked.")
        self.usb_details_label.setObjectName("muted")
        self.usb_details_label.setWordWrap(True)
        usb_layout.addLayout(usb_header)
        usb_layout.addWidget(self.usb_status_label)
        usb_layout.addWidget(self.usb_details_label)
        layout.addWidget(usb_card)

        network_card = QFrame()
        network_card.setObjectName("statusCard")
        network_layout = QVBoxLayout(network_card)
        network_heading = QLabel("Network Monitoring")
        network_heading.setObjectName("cardHeading")
        self.network_status_label = QLabel("Status: STOPPED")
        self.network_status_label.setObjectName("statusValue")
        self.network_interface_combo = QComboBox()
        self.network_interface_combo.setMinimumContentsLength(32)
        self.network_interface_label = QLabel("Interface: None selected")
        self.network_interface_label.setObjectName("muted")
        self.network_packet_count_label = QLabel("Packets: 0")
        self.network_flow_count_label = QLabel("Flows: 0")
        self.network_error_label = QLabel(" ")
        self.network_error_label.setObjectName("message")
        self.network_error_label.setWordWrap(True)
        network_buttons = QHBoxLayout()
        self.start_monitoring_button = QPushButton("Start Monitoring")
        self.stop_monitoring_button = QPushButton("Stop Monitoring")
        self.refresh_interfaces_button = QPushButton("Refresh Interface")
        self.start_monitoring_button.clicked.connect(self.start_network_monitoring)
        self.stop_monitoring_button.clicked.connect(self.stop_network_monitoring)
        self.refresh_interfaces_button.clicked.connect(self.refresh_network_interfaces)
        network_buttons.addWidget(self.start_monitoring_button)
        network_buttons.addWidget(self.stop_monitoring_button)
        network_buttons.addWidget(self.refresh_interfaces_button)
        network_layout.addWidget(network_heading)
        network_layout.addWidget(self.network_status_label)
        network_layout.addWidget(self.network_interface_combo)
        network_layout.addWidget(self.network_interface_label)
        network_layout.addWidget(self.network_packet_count_label)
        network_layout.addWidget(self.network_flow_count_label)
        network_layout.addWidget(self.network_error_label)
        network_layout.addLayout(network_buttons)
        layout.addWidget(network_card)

        layout.addStretch(1)
        logout = QPushButton("Logout")
        logout.setObjectName("secondaryButton")
        logout.clicked.connect(self._request_logout)
        layout.addWidget(logout, alignment=Qt.AlignRight)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(central)
        self.setCentralWidget(scroll_area)

        self._network_timer = QTimer(self)
        self._network_timer.timeout.connect(self._refresh_network_snapshot)
        self._network_timer.start(400)
        self._load_ids_model()
        self._load_recent_events()
        self._refresh_system_status()
        self.refresh_usb_status()
        self.refresh_network_interfaces()

    def _load_ids_model(self) -> None:
        self._ids_model_worker = _ActionWorker(self.ids_service.load_model)
        self._ids_model_worker.signals.finished.connect(self._ids_model_loaded)
        self._thread_pool.start(self._ids_model_worker)

    @Slot(object, object)
    def _ids_model_loaded(self, result, error) -> None:
        self._ids_model_worker = None
        if error is not None:
            logger.error("IDS model status check failed: %s", error)
        self._refresh_ids_snapshot()
    def _load_recent_events(self) -> None:
        """Load persisted event history without blocking the UI."""
        self._event_history_worker = _ActionWorker(
            lambda: self.ids_service.load_recent_events(limit=100)
        )
        self._event_history_worker.signals.finished.connect(
            self._recent_events_loaded
        )
        self._thread_pool.start(self._event_history_worker)

    @Slot(object, object)
    def _recent_events_loaded(self, result, error) -> None:
        self._event_history_worker = None

        if error is not None:
            logger.error("Failed to load dashboard event history: %s", error)
            self._persisted_events = ()
        else:
            self._persisted_events = tuple(result or ())

        self._refresh_ids_snapshot()
    def refresh_usb_status(self) -> None:
        """Refresh once on demand without blocking the dashboard event loop."""
        self._latest_usb_status = None
        self.usb_refresh_button.setEnabled(False)
        self.usb_status_label.setText("Status: CHECKING")
        self.usb_details_label.setText("Windows adapter information is being checked.")
        self._refresh_system_status()
        worker = _USBCheckWorker(self._usb_checker)
        worker.signals.finished.connect(self._display_usb_status)
        self._usb_worker = worker
        self._thread_pool.start(worker)

    @Slot(object)
    def _display_usb_status(self, result: USBAdapterStatus) -> None:
        self._latest_usb_status = result
        self.usb_refresh_button.setEnabled(True)
        self.usb_status_label.setText(f"Status: {result.status.replace('_', ' ').upper()}")

        details = []
        if result.adapter_name:
            details.append(f"Adapter: {result.adapter_name}")
        if result.interface_name:
            details.append(f"Interface: {result.interface_name}")
        if result.reason:
            details.append(result.reason)
        self.usb_details_label.setText("\n".join(details) or "No adapter details available.")
        if result.status == STATUS_APPROVED:
            self.usb_status_label.setStyleSheet("color: #16794b;")
        elif result.status == "unknown":
            self.usb_status_label.setStyleSheet("color: #9a6700;")
        else:
            self.usb_status_label.setStyleSheet("color: #b42318;")
        self._refresh_system_status()

    def _refresh_system_status(self) -> None:
        """Render the limited checks currently available without overstating assurance."""
        usb_status = self._latest_usb_status
        if usb_status is None:
            status = "Not verified"
            details = "USB adapter verification is pending; overall system verification is not implemented."
        elif usb_status.status != STATUS_APPROVED or not usb_status.approved:
            status = "Not verified"
            details = "USB adapter verification did not succeed; overall system verification is not implemented."
            if usb_status.reason:
                details = f"{details} {usb_status.reason}"
        elif self.network_monitor.is_active():
            status = "Partially verified"
            details = (
                "The approved USB adapter and network monitoring are active; "
                "overall system verification is not implemented."
            )
        else:
            status = "Partially verified"
            details = "The USB adapter is approved; overall system verification is not implemented."

        self.system_status_label.setText(status)
        self.system_status_label.setStyleSheet("color: #9a6700;")
        self.system_status_details_label.setText(details)

    def refresh_network_interfaces(self) -> None:
        self.refresh_interfaces_button.setEnabled(False)
        self._run_network_action(self.network_monitor.discover_interfaces, self._interfaces_loaded)

    def _interfaces_loaded(self, interfaces: list[NetworkInterface]) -> None:
        self.network_interface_combo.clear()
        approved_index: int | None = None
        if not interfaces:
            self.network_interface_combo.addItem("No network interfaces discovered", None)
        else:
            for index, interface in enumerate(interfaces):
                approval = "APPROVED" if interface.approved else "not approved"
                description = f" | {interface.description}" if interface.description else ""
                self.network_interface_combo.addItem(
                    f"{interface.display_name}{description} [{approval}]",
                    interface,
                )
                if interface.approved and approved_index is None:
                    approved_index = index
        if approved_index is not None:
            # Scapy may list WAN Miniports before the approved USB adapter.
            # This is only a UI default; start_capture verifies approval again.
            self.network_interface_combo.setCurrentIndex(approved_index)
            self.network_error_label.setText(self.network_monitor.selection_error or " ")
        else:
            # Do not leave QComboBox's implicit first-item selection pointing at
            # an unapproved interface when the USB adapter has no safe match.
            self.network_interface_combo.insertItem(
                0,
                "No approved USB Wi-Fi interface available",
                None,
            )
            self.network_interface_combo.setCurrentIndex(0)
            self.network_error_label.setText(
                self.network_monitor.selection_error
                or "No approved USB Wi-Fi interface could be matched for monitoring."
            )
        self.start_monitoring_button.setEnabled(approved_index is not None)
        self.refresh_interfaces_button.setEnabled(True)

    def start_network_monitoring(self) -> None:
        selected = self.network_interface_combo.currentData()
        if not isinstance(selected, NetworkInterface) or not selected.approved:
            self.network_error_label.setText(
                "Select an approved USB Wi-Fi interface before starting monitoring."
            )
            self.start_monitoring_button.setEnabled(False)
            return
        self.start_monitoring_button.setEnabled(False)
        self.stop_monitoring_button.setEnabled(False)
        self._run_network_action(
            lambda: self._start_capture(selected if isinstance(selected, NetworkInterface) else ""),
            self._capture_started,
        )

    def _start_capture(self, selected: NetworkInterface | str) -> NetworkInterface:
        self.flow_aggregator.reset()
        self.ids_service.reset_session()
        return self.network_monitor.start_capture(selected)

    def _capture_started(self, _interface: NetworkInterface) -> None:
        self.network_error_label.setText(" ")

    def stop_network_monitoring(self) -> None:
        if self._network_action_busy:
            return
        self.start_monitoring_button.setEnabled(False)
        self.stop_monitoring_button.setEnabled(False)
        self._run_network_action(self._stop_capture_and_finalize)

    def _stop_capture_and_finalize(self) -> tuple:
        self.ids_service.stop_analysis()
        self.network_monitor.stop_capture()
        return self.flow_aggregator.finalize_all("monitor_stopped")

    def start_ids_analysis(self) -> None:
        if not self.network_monitor.is_active():
            self.network_error_label.setText("Start network monitoring before IDS analysis.")
            return
        try:
            self.ids_service.start_analysis()
        except FeatureCompatibilityError as exc:
            self.ids_inference_status_label.setText(str(exc))
        self._refresh_ids_snapshot()

    def stop_ids_analysis(self) -> None:
        self.ids_service.stop_analysis()
        self._refresh_ids_snapshot()

    def _run_network_action(self, action, on_success=None) -> None:
        if self._network_action_busy:
            return
        self._network_action_busy = True
        worker = _ActionWorker(action)
        self._action_workers.add(worker)
        self._active_action_worker = worker
        self._active_action_success = on_success
        worker.signals.finished.connect(self._network_action_finished)
        self._thread_pool.start(worker)

    @Slot(object, object)
    def _network_action_finished(self, result, error) -> None:
        worker = self._active_action_worker
        self._action_workers.discard(worker)
        self._active_action_worker = None
        self._network_action_busy = False
        if error is not None:
            logger.error("Network monitoring action failed: %s", error)
            self.network_error_label.setText(str(error))
        elif self._active_action_success is not None:
            self._active_action_success(result)
        self._active_action_success = None

        self._refresh_network_snapshot()
        if self._logout_pending:
            self._continue_logout()
        elif self._close_pending:
            self._continue_close()

    def _refresh_network_snapshot(self) -> None:
        status = self.network_monitor.status
        self.network_status_label.setText(f"Status: {status}")
        self.network_packet_count_label.setText(f"Packets: {self.network_monitor.packet_count}")
        self.network_flow_count_label.setText(f"Flows: {self.network_monitor.flow_count}")
        selected = self.network_monitor.selected_interface
        if selected is not None:
            self.network_interface_label.setText(f"Interface: {selected.display_name}")
        elif self.network_interface_combo.currentData() is not None:
            selected_item = self.network_interface_combo.currentData()
            if isinstance(selected_item, NetworkInterface):
                self.network_interface_label.setText(f"Interface: {selected_item.display_name}")
        if status == "ERROR" and self.network_monitor.last_error:
            self.network_error_label.setText(self.network_monitor.last_error)
        active = self.network_monitor.is_active()
        selected_item = self.network_interface_combo.currentData()
        can_start = isinstance(selected_item, NetworkInterface) and selected_item.approved
        if not self._network_action_busy:
            self.start_monitoring_button.setEnabled(not active and can_start)
            self.stop_monitoring_button.setEnabled(active)
            self.refresh_interfaces_button.setEnabled(not active)
        self._refresh_system_status()
        self._refresh_ids_snapshot()

    def _refresh_ids_snapshot(self) -> None:
        status = self.ids_service.model_status

        if status == "LOADED":
            model_text = "Model: loaded (live inference gated)"
        elif status == "MISSING":
            model_text = "Model: unavailable (artifact missing)"
        elif status == "ERROR":
            model_text = "Model: unavailable (load or schema error)"
        else:
            model_text = f"Model: {status.lower()}"

        self.ids_model_status_label.setText(model_text)

        if not self.ids_service.inference_enabled:
            if status == "LOADED":
                self.ids_inference_status_label.setText(
                    "Live IDS inference unavailable: feature compatibility incomplete."
                )
            else:
                self.ids_inference_status_label.setText(
                    self.ids_service.status_message
                )
        else:
            self.ids_inference_status_label.setText(
                "Live IDS inference ready; start it while monitoring is active."
            )

        self.ids_monitoring_status_label.setText(
            f"Monitoring: {'RUNNING' if self.network_monitor.is_active() else 'STOPPED'}"
        )
        self.ids_flow_count_label.setText(
            f"Completed flows checked: {self.ids_service.flows_checked}"
        )

        if self.ids_service.inference_enabled:
            self.ids_detection_count_label.setText(
                f"Suspicious prediction signals: {self.ids_service.detections}"
            )
        else:
            self.ids_detection_count_label.setText(
                "Attack signals: unavailable (inference disabled)"
            )

        # Merge persisted history with current-session events.
        # The same event may exist in both sources.
        persisted = getattr(self, "_persisted_events", ())
        current = self.ids_service.events
        combined = {}

        for item in tuple(persisted) + tuple(current):
            key = (item.timestamp, item.flow_id)
            combined[key] = item

        events = sorted(
            combined.values(),
            key=lambda item: item.timestamp,
        )
        event = events[-1] if events else None

        if event is None:
            self.ids_latest_event_label.setText(
                "Latest event: none; no saved prediction events."
            )
            rendered = ["No saved prediction events yet."]
        else:
            probability = (
                f" | attack probability {event.attack_probability:.3f}"
                if event.attack_probability is not None
                else ""
            )
            self.ids_latest_event_label.setText(
                f"Latest event: {event.severity} / {event.prediction}"
                f"{probability} - "
                f"{event.source_ip}:{event.source_port} to "
                f"{event.destination_ip}:{event.destination_port}"
            )

            rendered = [
                f"{item.timestamp} | {item.severity} | "
                f"{item.prediction} | "
                f"{item.source_ip}:{item.source_port} to "
                f"{item.destination_ip}:{item.destination_port}"
                for item in events[-5:]
            ]

        existing = [
            self.ids_event_log.item(index).text()
            for index in range(self.ids_event_log.count())
        ]

        if rendered != existing:
            self.ids_event_log.clear()
            self.ids_event_log.addItems(rendered)

        capture_active = self.network_monitor.is_active()
        self.start_ids_button.setEnabled(
            self.ids_service.inference_enabled and capture_active
        )
        self.stop_ids_button.setEnabled(
            self.ids_service.analysis_active
        )
    def _request_logout(self) -> None:
        self._logout_pending = True
        self._continue_logout()

    def _continue_logout(self) -> None:
        if self._network_action_busy:
            return
        if self.network_monitor.is_active():
            self.stop_network_monitoring()
            return
        self._logout_pending = False
        self._on_logout()

    def _continue_close(self) -> None:
        if self._network_action_busy:
            return
        if self.network_monitor.is_active():
            self.stop_network_monitoring()
            return
        self._close_pending = False
        self.close()

    def closeEvent(self, event) -> None:
        if self._network_action_busy or self.network_monitor.is_active():
            event.ignore()
            self._close_pending = True
            if not self._network_action_busy:
                self._continue_close()
            return
        self.ids_service.stop_analysis()
        self.flow_aggregator.finalize_all("dashboard_closed")
        self.network_monitor.remove_packet_callback(self._packet_callback)
        event.accept()
