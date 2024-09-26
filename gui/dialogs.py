# gui/dialogs.py
from PyQt5.QtWidgets import (
    QDialog, QLabel, QVBoxLayout, QPushButton, QTextBrowser,
    QMessageBox, QLineEdit, QHBoxLayout, QCheckBox, QInputDialog
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIntValidator  # Korrekt import från QtGui
from utils.resources import apply_style

class InactivityTimeoutDialog(QDialog):
    def __init__(self, current_timeout, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Inaktivitetstid")
        self.setFixedSize(400, 200)

        layout = QVBoxLayout()
        label = QLabel("Ange tid (i sekunder) innan lösenordet krävs igen:")
        label.setWordWrap(True)
        self.timeout_edit = QLineEdit(str(current_timeout))
        self.timeout_edit.setValidator(QIntValidator(30, 99999))  # Använd QIntValidator från QtGui
        self.timeout_edit.setFixedHeight(30)

        buttons_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Avbryt")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addStretch()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        layout.addWidget(label)
        layout.addWidget(self.timeout_edit)
        layout.addStretch()
        layout.addLayout(buttons_layout)
        self.setLayout(layout)

        apply_style(self)

    def accept(self):
        self.timeout = int(self.timeout_edit.text())
        super().accept()

class AboutDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Om CryptApp")
        self.setFixedSize(600, 600)

        text_browser = QTextBrowser()
        text_browser.setReadOnly(True)
        text_browser.setHtml("""
        <h2>CryptApp</h2>
        <p>CryptApp är en applikation för säker kryptering och dekryptering av filer och meddelanden.</p>
        <h3>Hur fungerar det?</h3>
        <p>Applikationen använder asymmetrisk kryptering med RSA (4096 bitar) och symmetrisk kryptering med AES-256 GCM.</p>
        <p>När du krypterar en fil eller ett meddelande används mottagarens publika nyckel. Endast mottagaren, som har den korresponderande privata nyckeln, kan dekryptera innehållet.</p>
        <h3>Profiler</h3>
        <p>Du kan hantera flera profiler, vilket låter dig kryptera information för olika mottagare. Varje profil representerar en mottagare och deras publika nyckel.</p>
        <h3>Säkerhet</h3>
        <p>Ditt lösenord och dina nycklar hanteras säkert i applikationen:</p>
        <ul>
            <li>Den privata nyckeln är krypterad med ditt lösenord och lagras säkert på din dator.</li>
            <li>Lösenord lagras aldrig i klartext och rensas från minnet efter användning.</li>
            <li>Efter en period av inaktivitet låses den privata nyckeln, och du måste ange ditt lösenord igen för att använda den.</li>
            <li>En lösenordspolicy säkerställer att ditt lösenord är starkt och svårgissat.</li>
            <li>AES-256 GCM används för symmetrisk kryptering med autentisering, vilket skyddar mot manipulation.</li>
        </ul>
        <h3>Kryptografiska metoder</h3>
        <p>Applikationen använder följande metoder:</p>
        <ul>
            <li><b>RSA (4096 bitar)</b> för asymmetrisk kryptering av symmetriska nycklar.</li>
            <li><b>AES-256 GCM</b> för symmetrisk kryptering av filer och meddelanden.</li>
            <li><b>OAEP-padding</b> med SHA-256 för RSA-kryptering.</li>
            <li><b>PBKDF2HMAC</b> för nyckelhärledning från lösenord med salt och 100,000 iterationer.</li>
        </ul>
        <h3>Ny funktion: Dela upp stora filer</h3>
        <p>Nu kan du dela upp stora krypterade filer i mindre delar för enklare hantering och överföring.</p>
        <h3>Kryptering av filnamn</h3>
        <p>För att ytterligare skydda din integritet krypteras filnamn alltid när du krypterar filer.</p>
        <h3>Lösenordspolicy</h3>
        <p>För att säkerställa att ditt lösenord är starkt måste det uppfylla följande krav:</p>
        <ul>
            <li>Minst 8 tecken långt</li>
            <li>Innehålla minst en versal (A-Z)</li>
            <li>Innehålla minst en gemen (a-z)</li>
            <li>Innehålla minst en siffra (0-9)</li>
            <li>Innehålla minst ett specialtecken (!@#$%^&* etc.)</li>
        </ul>
        """)
        layout = QVBoxLayout()
        layout.addWidget(text_browser)
        self.setLayout(layout)
        apply_style(self)

class EncryptionDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kryptering")
        self.setFixedSize(600, 200)

        layout = QVBoxLayout()
        label = QLabel("Meddelandet har krypterats och kopierats till urklipp.")
        label.setWordWrap(True)
        self.checkbox = QCheckBox("Visa inte detta meddelande igen")
        self.checkbox.setFixedHeight(30)
        buttons_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        buttons_layout.addStretch()
        buttons_layout.addWidget(ok_button)

        layout.addWidget(label)
        layout.addWidget(self.checkbox)
        layout.addStretch()
        layout.addLayout(buttons_layout)
        self.setLayout(layout)

        apply_style(self)

class PasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lösenord")
        self.setFixedSize(400, 200)

        layout = QVBoxLayout()
        label = QLabel("Ange lösenord för den privata nyckeln:")
        label.setWordWrap(True)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setFixedHeight(40)

        buttons_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Avbryt")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addStretch()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        layout.addWidget(label)
        layout.addWidget(self.password_edit)
        layout.addStretch()
        layout.addLayout(buttons_layout)
        self.setLayout(layout)

        apply_style(self)

    def accept(self):
        self.password = self.password_edit.text()
        super().accept()
