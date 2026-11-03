"""Login screen for the SecureWork AI prototype."""
import logging
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QFormLayout, QLabel, QLineEdit, QMainWindow, QPushButton,
    QVBoxLayout, QWidget,
)
from app.security.auth import AccountStoreStatus, account_store_status, authenticate

logger = logging.getLogger(__name__)


class LoginWindow(QMainWindow):
    def __init__(self, on_login_success) -> None:
        super().__init__()
        self._on_login_success = on_login_success
        self.setWindowTitle("SecureWork AI | Sign in")
        self.setMinimumSize(480, 560)

        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(42, 36, 42, 36)
        outer.setSpacing(20)
        outer.addStretch(1)

        title = QLabel("SecureWork AI")
        title.setObjectName("pageTitle")
        title.setAlignment(Qt.AlignCenter)
        subtitle = QLabel("Secure workspace for your personal device")
        subtitle.setObjectName("muted")
        subtitle.setAlignment(Qt.AlignCenter)
        outer.addWidget(title)
        outer.addWidget(subtitle)

        form_card = QFrame()
        form_card.setObjectName("panel")
        form = QFormLayout(form_card)
        form.setContentsMargins(24, 24, 24, 24)
        form.setSpacing(14)
        self.username = QLineEdit()
        self.username.setPlaceholderText("Enter your username")
        self.username.setText("")
        self.password = QLineEdit()
        self.password.setPlaceholderText("Enter your password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.returnPressed.connect(self._login)
        form.addRow("Username", self.username)
        form.addRow("Password", self.password)
        outer.addWidget(form_card)

        self.message = QLabel(" ")
        self.message.setObjectName("message")
        self.message.setAlignment(Qt.AlignCenter)
        outer.addWidget(self.message)
        login_button = QPushButton("Login")
        login_button.clicked.connect(self._login)
        outer.addWidget(login_button)

        security = QFrame()
        security.setObjectName("securityBox")
        security_layout = QVBoxLayout(security)
        security_title = QLabel("Security status")
        security_title.setObjectName("cardHeading")
        security_copy = QLabel("Local prototype • Monitoring features are not active")
        security_copy.setObjectName("muted")
        security_copy.setWordWrap(True)
        security_layout.addWidget(security_title)
        security_layout.addWidget(security_copy)
        outer.addWidget(security)
        outer.addStretch(1)
        self.setCentralWidget(central)
        self._show_account_store_status()

    def _show_account_store_status(self) -> None:
        status = account_store_status()
        if status is AccountStoreStatus.MISSING:
            self.message.setText("No local account is configured. Run the documented provisioning command.")
        elif status is AccountStoreStatus.UNAVAILABLE:
            self.message.setText("Local account storage is unavailable. Contact the administrator.")

    def _login(self) -> None:
        if authenticate(self.username.text().strip(), self.password.text()):
            logger.info("Local user authenticated successfully")
            self.message.setText(" ")
            self._on_login_success()
        else:
            logger.warning("Failed local login attempt")
            self.message.setText("Incorrect username or password.")
