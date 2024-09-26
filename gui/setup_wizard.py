# gui/setup_wizard.py
import sys  # Lägg till denna rad för att importera sys
import os
import json
import subprocess

from PyQt5.QtWidgets import (
    QWizard, QWizardPage, QLabel, QVBoxLayout, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from utils.resources import apply_style
from gui.dialogs import InactivityTimeoutDialog

class SetupWizard(QWizard):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Välkommen till CryptApp")
        self.setWizardStyle(QWizard.ModernStyle)
        self.setFixedSize(700, 900)  # Ställ in en fast storlek

        # Applicera stil
        apply_style(self)

        # Spara användarinställningar
        self.settings = {}

        # Lägg till sidor i guiden med specifika ID:n
        self.setPage(0, self.create_intro_page())
        self.setPage(1, self.create_key_generation_page())
        self.setPage(2, self.create_directory_page())
        self.setPage(3, self.create_conclusion_page())

        # Översätt navigeringsknapparna till svenska
        self.setButtonText(QWizard.BackButton, "< Tillbaka")
        self.setButtonText(QWizard.NextButton, "Nästa >")
        self.setButtonText(QWizard.CancelButton, "Avbryt")
        self.setButtonText(QWizard.FinishButton, "Slutför")

    def create_intro_page(self):
        page = QWizardPage()
        page.setTitle("Introduktion")

        label = QLabel(
            "Välkommen till CryptApp!\n\n"
            "Denna applikation låter dig kryptera och dekryptera filer och meddelanden säkert.\n\n"
            "I denna guide kommer du att:\n"
            "- Lära dig om hur applikationen fungerar\n"
            "- Generera ditt eget nyckelpar\n"
            "- Välja en standardkatalog för dina filer\n"
        )
        label.setWordWrap(True)
        label.setObjectName("titleLabel")  # För styling i styles.qss

        layout = QVBoxLayout()
        layout.addWidget(label)
        page.setLayout(layout)

        return page

    def create_key_generation_page(self):
        page = QWizardPage()
        page.setTitle("Generera nyckelpar")

        label = QLabel(
            "För att komma igång behöver du generera ett nyckelpar.\n\n"
            "Den privata nyckeln ska du hålla hemlig och aldrig dela med någon.\n"
            "Den publika nyckeln kan du dela med dina vänner så att de kan skicka krypterade meddelanden till dig."
        )
        label.setWordWrap(True)
        label.setObjectName("titleLabel")

        password_label = QLabel("Ange ett lösenord för att skydda din privata nyckel:")
        password_label.setWordWrap(True)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setFixedHeight(40)

        confirm_label = QLabel("Bekräfta lösenord:")
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit.setFixedHeight(40)

        # Lösenordskrav
        self.password_policy_label = QLabel(
            "Lösenordet måste vara minst 8 tecken långt och innehålla:\n"
            "- Minst en versal (A-Z)\n"
            "- Minst en gemen (a-z)\n"
            "- Minst en siffra (0-9)\n"
            "- Minst ett specialtecken (!@#$%^&* etc.)"
        )
        self.password_policy_label.setWordWrap(True)

        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addSpacing(10)
        layout.addWidget(password_label)
        layout.addWidget(self.password_edit)
        layout.addWidget(confirm_label)
        layout.addWidget(self.confirm_edit)
        layout.addWidget(self.password_policy_label)
        layout.addStretch()
        page.setLayout(layout)

        # Validering
        page.registerField("password*", self.password_edit)
        page.registerField("confirm*", self.confirm_edit)

        return page

    def create_directory_page(self):
        page = QWizardPage()
        page.setTitle("Välj standardkatalog")

        label = QLabel(
            "Välj en katalog där du vill spara alla dekrypterade och krypterade filer.\n\n"
            "Om du exempelvis väljer 'C:\\filer', kommer alla filer att sparas i 'C:\\filer\\[profilnamn]'."
        )
        label.setWordWrap(True)
        label.setObjectName("titleLabel")

        self.directory_edit = QLineEdit()
        self.directory_edit.setFixedHeight(40)
        browse_button = QPushButton("Bläddra")
        browse_button.clicked.connect(self.browse_directory)

        dir_layout = QHBoxLayout()
        dir_layout.addWidget(self.directory_edit)
        dir_layout.addWidget(browse_button)

        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addLayout(dir_layout)
        layout.addStretch()
        page.setLayout(layout)

        # Validering
        page.registerField("directory*", self.directory_edit)

        return page

    def create_conclusion_page(self):
        page = QWizardPage()
        page.setTitle("Slutför")

        label = QLabel("Guiden är nu klar!\n\nKlicka på 'Slutför' för att börja använda CryptApp.")
        label.setWordWrap(True)
        label.setObjectName("titleLabel")

        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addStretch()
        page.setLayout(layout)

        return page

    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Välj katalog")
        if directory:
            self.directory_edit.setText(directory)

    def validatePage(self):
        if self.currentId() == 1:
            password = self.password_edit.text()
            confirm = self.confirm_edit.text()
            if password != confirm:
                QMessageBox.warning(self, "Fel", "Lösenorden matchar inte.")
                return False
            if not self.validate_password_strength(password):
                QMessageBox.warning(self, "Fel", "Lösenordet uppfyller inte kraven.")
                return False
        return super().validatePage()

    def validate_password_strength(self, password):
        if len(password) < 8:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password)
        return has_upper and has_lower and has_digit and has_special

    def accept(self):
        password = self.password_edit.text()
        confirm = self.confirm_edit.text()
        if password != confirm:
            QMessageBox.warning(self, "Fel", "Lösenorden matchar inte.")
            return

        if not self.validate_password_strength(password):
            QMessageBox.warning(self, "Fel", "Lösenordet uppfyller inte kraven.")
            return

        # Använd KDF för att härleda en nyckel från lösenordet
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        encryption_algorithm = serialization.BestAvailableEncryption(key)

        # Generera nyckelpar
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Spara nycklar i "keys"-katalogen
        if not os.path.exists("keys"):
            os.makedirs("keys")

        priv_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm
        )
        with open(os.path.join("keys", "private_key.pem"), "wb") as f:
            f.write(salt + priv_key_pem)

        pub_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(os.path.join("keys", "public_key.pem"), "wb") as f:
            f.write(pub_key_pem)

        # Spara standardkatalogen
        directory = self.directory_edit.text()
        self.settings['default_directory'] = directory

        # Spara inställningar i config.json
        with open("config.json", "w") as f:
            json.dump(self.settings, f)

        # Informera användaren och fråga om de vill öppna katalogen
        public_key_path = os.path.abspath(os.path.join("keys", "public_key.pem"))
        reply = self.show_key_generated_dialog(public_key_path)
        if reply == QMessageBox.Yes:
            public_key_dir = os.path.dirname(public_key_path)
            if sys.platform == "win32":
                os.startfile(public_key_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", public_key_dir])
            else:
                subprocess.Popen(["xdg-open", public_key_dir])

        # Rensa lösenordet från minnet
        password = None
        key = None

        super().accept()

    def show_key_generated_dialog(self, public_key_path):
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Nyckel genererad")
        dialog.setText(
            f"Din publika nyckel har sparats i:\n{public_key_path}\n\nVill du öppna katalogen för att dela den med andra?"
        )
        dialog.setIcon(QMessageBox.Question)

        # Använd anpassade knappar
        yes_button = dialog.addButton("Ja", QMessageBox.YesRole)
        no_button = dialog.addButton("Nej", QMessageBox.NoRole)

        dialog.exec_()

        if dialog.clickedButton() == yes_button:
            return QMessageBox.Yes
        else:
            return QMessageBox.No
