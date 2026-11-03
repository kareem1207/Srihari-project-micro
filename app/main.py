"""Application entry point for SecureWork AI."""
import logging
import sys
from PySide6.QtWidgets import QApplication
from app.security.network_monitor import NetworkMonitor
from app.security.usb_checker import USBAdapterChecker
from app.ui.dashboard_window import DashboardWindow
from app.ui.login_window import LoginWindow
from app.utils.logging_config import configure_logging


STYLESHEET = """
QWidget { background: #f4f7fb; color: #17243a; font-family: 'Segoe UI'; font-size: 14px; }
QMainWindow { background: #f4f7fb; }
QLabel#pageTitle { font-size: 27px; font-weight: 700; color: #102a43; }
QLabel#muted { color: #64748b; }
QFrame#panel, QFrame#statusCard { background: white; border: 1px solid #dce5ef; border-radius: 12px; }
QFrame#securityBox { background: #edf6ff; border: 1px solid #c7e1fa; border-radius: 10px; }
QLabel#cardHeading { font-weight: 600; color: #334e68; }
QLabel#statusValue { font-size: 16px; font-weight: 600; color: #16794b; }
QLabel#message { color: #b42318; min-height: 20px; }
QLineEdit { background: white; border: 1px solid #cbd5e1; border-radius: 7px; padding: 10px; }
QLineEdit:focus { border: 1px solid #2673c9; }
QPushButton { background: #1769aa; color: white; border: 0; border-radius: 7px; padding: 11px 18px; font-weight: 600; }
QPushButton:hover { background: #12578e; }
QPushButton#secondaryButton { background: #e7eef6; color: #243b53; }
"""


class SecureWorkApplication:
    def __init__(self, app: QApplication) -> None:
        self.app = app
        self.usb_checker = USBAdapterChecker()
        self.network_monitor = NetworkMonitor(usb_checker=self.usb_checker)
        self.login_window = LoginWindow(self.show_dashboard)
        self.dashboard_window = None

    def show_dashboard(self) -> None:
        self.login_window.hide()
        self.dashboard_window = DashboardWindow(
            self.logout,
            usb_checker=self.usb_checker,
            network_monitor=self.network_monitor,
        )
        self.dashboard_window.show()

    def logout(self) -> None:
        logging.getLogger(__name__).info("User logged out")
        if self.network_monitor.is_active():
            self.network_monitor.stop_capture()
        if self.dashboard_window is not None:
            self.dashboard_window.close()
            self.dashboard_window = None
        self.login_window.password.clear()
        self.login_window.show()

    def shutdown(self) -> None:
        """Ensure no capture worker remains when the application exits."""
        if self.network_monitor.is_active():
            self.network_monitor.stop_capture()


def main() -> int:
    configure_logging()
    logger = logging.getLogger(__name__)
    app = QApplication(sys.argv)
    app.setApplicationName("SecureWork AI")
    app.setStyleSheet(STYLESHEET)
    application = SecureWorkApplication(app)
    app.aboutToQuit.connect(application.shutdown)
    application.login_window.show()
    logger.info("SecureWork AI started")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
