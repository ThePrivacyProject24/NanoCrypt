# gui/main_window.py

import sys
import os
import json
import webbrowser
import subprocess
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QListWidget,
    QPushButton, QTextEdit, QFileDialog, QMessageBox, QLabel, QHBoxLayout,
    QAction, QComboBox, QStackedWidget, QLineEdit, QCheckBox,
    QProgressBar, QWizard, QWizardPage, QDialog, QTextBrowser,
    QInputDialog, QApplication
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject, QEvent
from PyQt5.QtGui import QIcon

from workers.crypto_worker import CryptoWorker
from gui.dialogs import AboutDialog, PasswordDialog, EncryptionDialog, InactivityTimeoutDialog
from gui.widgets import DropListWidget
from gui.setup_wizard import SetupWizard  # Importerar SetupWizard för att fixa "SetupWizard is not defined"
from utils.resources import get_resource_path, apply_style
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding  # Importerar padding för att fixa "padding is not defined"

MAX_FILE_SIZE = 100 * 1024 * 1024

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialisera attribut
        self.file_list = []
        self.public_keys = {}  # profiler: profilnamn -> publik nyckel
        self.load_profiles()
        self.private_key = None
        self.private_key_encrypted_pem = None  # Krypterad PEM-data för privat nyckel
        self.inactivity_timeout = 300  # Standardvärde 5 minuter
        self.inactivity_timer = QTimer()
        self.inactivity_timer.timeout.connect(self.lock_private_key)
        self.reset_inactivity_timer()
        self.default_directory = ""
        self.show_encryption_dialog = True  # För att hantera om dialogen ska visas
        self.chat_history = {}  # Lagra chat-historik per profil

        # Ladda inställningar
        self.load_settings()

        # Applicera stil
        # Notera: Stilen har redan applicerats i main.py, så detta kan tas bort eller behållas för ytterligare tillämpningar.

        # Starta guiden om det behövs
        if not os.path.exists(os.path.join("keys", "private_key.pem")):
            self.run_setup_wizard()
        else:
            self.load_private_key_from_file()

        # Ställ in huvudfönstret
        self.setWindowTitle("CryptApp")
        self.setGeometry(100, 100, 800, 800)  # Ändra höjden här (fjärde värdet)
        self.setAcceptDrops(False)

        # Skapa menyer
        self.create_menus()

        # Skapa central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Skapa layout
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        # Lägg till en kombinationsruta för att välja läge
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Fil", "Text", "Chat"])
        self.mode_combo.currentIndexChanged.connect(self.switch_mode)
        title_label = QLabel("Välj läge:")
        title_label.setObjectName("titleLabel")
        self.layout.addWidget(title_label)
        self.layout.addWidget(self.mode_combo)

        # Skapa en QStackedWidget för att hålla olika lägen
        self.stacked_widget = QStackedWidget()
        self.layout.addWidget(self.stacked_widget)

        # Fil-läge
        self.create_file_mode()

        # Text-läge
        self.create_text_mode()

        # Chat-läge
        self.create_chat_mode()

        # Lägg till widgets till stacked_widget
        self.stacked_widget.addWidget(self.file_widget)
        self.stacked_widget.addWidget(self.text_widget)
        self.stacked_widget.addWidget(self.chat_widget)

        # Lägg till krypterings- och dekrypteringsknappar
        self.encrypt_button = QPushButton("Kryptera")
        encrypt_icon = QIcon(get_resource_path(os.path.join("assets", "encrypt.png")))
        self.encrypt_button.setIcon(encrypt_icon)
        self.encrypt_button.clicked.connect(self.encrypt)

        self.decrypt_button = QPushButton("Dekryptera")
        decrypt_icon = QIcon(get_resource_path(os.path.join("assets", "decrypt.png")))
        self.decrypt_button.setIcon(decrypt_icon)
        self.decrypt_button.clicked.connect(self.decrypt)

        self.button_layout2 = QHBoxLayout()
        self.button_layout2.addWidget(self.encrypt_button)
        self.button_layout2.addWidget(self.decrypt_button)
        self.layout.addLayout(self.button_layout2)

        # Anslut interaktioner för att återställa inaktivitets-timern
        self.installEventFilter(self)

    def create_menus(self):
        # Skapa menyfält
        menubar = self.menuBar()

        # Skapa "Nyckel"-meny
        key_menu = menubar.addMenu("Nyckel")

        # Skapa actions
        import_public_key_action = QAction(QIcon(get_resource_path(os.path.join("assets", "encrypt.png"))), "Importera publik nyckel", self)
        import_public_key_action.triggered.connect(self.import_public_key)

        send_public_key_action = QAction(QIcon(get_resource_path(os.path.join("assets", "open_public_key_folder.png"))), "Skicka publik nyckel", self)
        send_public_key_action.triggered.connect(self.send_public_key)

        # Lägg till actions till menyn
        key_menu.addAction(import_public_key_action)
        key_menu.addAction(send_public_key_action)

        # Skapa "Inställningar"-meny
        settings_menu = menubar.addMenu("Inställningar")
        inactivity_timeout_action = QAction(QIcon(get_resource_path(os.path.join("assets", "timer.png"))), "Ange inaktivitets-tid", self)
        inactivity_timeout_action.triggered.connect(self.set_inactivity_timeout)
        settings_menu.addAction(inactivity_timeout_action)

        # Skapa "Om"-meny
        about_menu = menubar.addMenu("Om")
        about_action = QAction(QIcon(get_resource_path(os.path.join("assets", "about.png"))), "Om CryptApp", self)
        about_action.triggered.connect(self.show_about_dialog)
        about_menu.addAction(about_action)

    def send_public_key(self):
        public_key_path = os.path.abspath(os.path.join("keys", "public_key.pem"))
        if os.path.exists(public_key_path):
            public_key_dir = os.path.dirname(public_key_path)
            if sys.platform == "win32":
                os.startfile(public_key_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", public_key_dir])
            else:
                subprocess.Popen(["xdg-open", public_key_dir])
        else:
            QMessageBox.warning(self, "Fel", "Publik nyckel hittades inte.")

    def show_about_dialog(self):
        dialog = AboutDialog()
        dialog.exec_()

    def run_setup_wizard(self):
        wizard = SetupWizard(self)
        if wizard.exec_():
            # Ladda den privata nyckeln
            self.load_private_key_from_file()
            # Ladda standardkatalogen
            self.default_directory = wizard.settings.get('default_directory', '')
        else:
            QMessageBox.warning(self, "Avbrutet", "Guiden avbröts. Applikationen avslutas.")
            sys.exit()

    def load_private_key_from_file(self):
        try:
            with open(os.path.join("keys", "private_key.pem"), "rb") as f:
                file_data = f.read()
                salt = file_data[:16]
                self.private_key_encrypted_pem = file_data[16:]
                self.salt = salt
            # Be om lösenord för att dekryptera nyckeln
            self.unlock_private_key()
        except Exception as e:
            QMessageBox.warning(self, "Fel", f"Kunde inte ladda privat nyckel.\n{str(e)}")
            sys.exit()

    def unlock_private_key(self):
        while True:
            # Be om lösenord för att dekryptera nyckeln
            password_dialog = PasswordDialog()
            if password_dialog.exec_():
                password = password_dialog.password.encode()
            else:
                sys.exit()
            try:
                # Använd KDF för att härleda nyckeln
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(password)
                self.private_key = serialization.load_pem_private_key(
                    self.private_key_encrypted_pem,
                    password=key,
                    backend=default_backend()
                )
                self.reset_inactivity_timer()
                # Rensa lösenordet från minnet
                password = None
                key = None
                break
            except ValueError:
                # Använd anpassad meddelanderuta med svenska knappar
                message_box = QMessageBox(self)
                message_box.setIcon(QMessageBox.Warning)
                message_box.setWindowTitle("Fel")
                message_box.setText("Fel lösenord eller korrupt nyckel. Försök igen eller avbryt.")
                retry_button = message_box.addButton("Försök igen", QMessageBox.AcceptRole)
                abort_button = message_box.addButton("Avbryt", QMessageBox.RejectRole)
                apply_style(message_box)
                message_box.exec_()
                if message_box.clickedButton() == abort_button:
                    sys.exit()
            except Exception as e:
                QMessageBox.warning(self, "Fel", f"Kunde inte dekryptera privat nyckel.\n{str(e)}")
                sys.exit()

    def load_profiles(self):
        if os.path.exists("profiles.json"):
            with open("profiles.json", "r") as f:
                profiles = json.load(f)
            for name, key_data in profiles.items():
                public_key = serialization.load_pem_public_key(
                    key_data.encode(),
                    backend=default_backend()
                )
                self.public_keys[name] = public_key
        else:
            self.public_keys = {}

    def save_profiles(self):
        profiles = {}
        for name, key in self.public_keys.items():
            key_pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            profiles[name] = key_pem
        with open("profiles.json", "w") as f:
            json.dump(profiles, f)

    def load_settings(self):
        if os.path.exists("config.json"):
            with open("config.json", "r") as f:
                settings = json.load(f)
            self.default_directory = settings.get('default_directory', '')
            self.show_encryption_dialog = settings.get('show_encryption_dialog', True)
        else:
            self.show_encryption_dialog = True

    def save_settings(self):
        settings = {
            'default_directory': self.default_directory,
            'show_encryption_dialog': self.show_encryption_dialog
        }
        with open("config.json", "w") as f:
            json.dump(settings, f)

    def set_inactivity_timeout(self):
        dialog = InactivityTimeoutDialog(self.inactivity_timeout)
        if dialog.exec_():
            self.inactivity_timeout = dialog.timeout
            self.reset_inactivity_timer()
            QMessageBox.information(self, "Inställningar", f"Inaktivitetstid inställd till {self.inactivity_timeout} sekunder.")

    def reset_inactivity_timer(self):
        self.inactivity_timer.stop()
        self.inactivity_timer.start(self.inactivity_timeout * 1000)

    def lock_private_key(self):
        self.private_key = None
        QMessageBox.information(self, "Låst", "Den privata nyckeln har låsts på grund av inaktivitet.")
        # Be användaren att låsa upp nyckeln igen
        self.unlock_private_key()

    def eventFilter(self, source, event):
        if event.type() in (QEvent.MouseButtonPress, QEvent.KeyPress):
            self.reset_inactivity_timer()
        return super().eventFilter(source, event)

    def toggle_queue_visibility(self):
        if self.total_progress_bar.isVisible():
            self.total_progress_bar.hide()
            self.current_file_label.hide()
        else:
            self.total_progress_bar.show()
            self.current_file_label.show()

    def switch_mode(self, index):
        self.stacked_widget.setCurrentIndex(index)
        mode = self.mode_combo.currentText()
        if mode == "Text":
            self.encrypt_button.show()
            self.decrypt_button.show()
        elif mode == "Fil":
            self.encrypt_button.show()
            self.decrypt_button.show()
        elif mode == "Chat":
            # Dölj kryptera/dekrytera-knapparna i chat-läget
            self.encrypt_button.hide()
            self.decrypt_button.hide()

    def add_file(self):
        options = QFileDialog.Options()
        files, _ = QFileDialog.getOpenFileNames(self, "Välj filer", "", "Alla filer (*)", options=options)
        if files:
            for filepath in files:
                if os.path.getsize(filepath) > MAX_FILE_SIZE:
                    QMessageBox.warning(self, "Fel", f"Filen {filepath} överstiger maximal tillåten storlek.")
                else:
                    self.file_list.append(filepath)
                    self.drop_zone.addItem(filepath)

    def remove_file(self):
        selected_items = self.drop_zone.selectedItems()
        if not selected_items:
            return
        for item in selected_items:
            self.file_list.remove(item.text())
            self.drop_zone.takeItem(self.drop_zone.row(item))

    def clear_files(self):
        self.file_list.clear()
        self.drop_zone.clear()

    def clear_text(self):
        self.text_edit.clear()

    def import_public_key(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Importera publik nyckel", "", "PEM-filer (*.pem);;Alla filer (*)", options=options)
        if fileName:
            while True:
                profile_name, ok = QInputDialog.getText(self, "Profilnamn", "Ange ett namn för profilen:")
                if not ok or not profile_name:
                    QMessageBox.warning(self, "Fel", "Profilnamn krävs.")
                    return
                if profile_name in self.public_keys:
                    QMessageBox.warning(self, "Fel", "En profil med detta namn finns redan. Välj ett annat namn.")
                else:
                    break
            with open(fileName, "rb") as f:
                pub_key_pem = f.read()
                try:
                    public_key = serialization.load_pem_public_key(pub_key_pem, backend=default_backend())
                    self.public_keys[profile_name] = public_key
                    self.save_profiles()
                    # Uppdatera profilval
                    self.profile_combo.clear()
                    self.profile_combo.addItems(self.public_keys.keys())
                    self.profile_combo_text.clear()
                    self.profile_combo_text.addItems(self.public_keys.keys())
                    self.profile_combo_chat.clear()
                    self.profile_combo_chat.addItems(self.public_keys.keys())
                    QMessageBox.information(self, "Importera", "Publik nyckel har importerats.")
                except Exception as e:
                    QMessageBox.warning(self, "Fel", "Kunde inte importera publik nyckel.\n" + str(e))

    def encrypt(self):
        if self.mode_combo.currentText() == "Fil":
            self.encrypt_files()
        else:
            self.encrypt_text()

    def decrypt(self):
        if self.mode_combo.currentText() == "Fil":
            self.decrypt_files()
        else:
            self.decrypt_text()

    def encrypt_files(self):
        if not self.public_keys:
            QMessageBox.warning(self, "Fel", "Ingen publik nyckel tillgänglig.")
            return
        if not self.file_list:
            QMessageBox.warning(self, "Fel", "Inga filer att kryptera.")
            return

        profile_name = self.profile_combo.currentText()
        public_key = self.public_keys.get(profile_name)
        if not public_key:
            QMessageBox.warning(self, "Fel", "Vald profil har ingen giltig publik nyckel.")
            return

        # Spara i standardkatalogen under profilens namn
        output_path = os.path.join(self.default_directory, profile_name)
        if not os.path.exists(output_path):
            os.makedirs(output_path)

        # Kolla om delning av fil är vald
        split_file = self.split_file_checkbox.isChecked()
        split_size = None
        if split_file:
            size_text = self.split_size_combo.currentText()
            size_mapping = {
                "1 MB": 1 * 1024 * 1024,
                "5 MB": 5 * 1024 * 1024,
                "10 MB": 10 * 1024 * 1024,
                "100 MB": 100 * 1024 * 1024,
                "1 GB": 1 * 1024 * 1024 * 1024,
            }
            split_size = size_mapping.get(size_text, None)

        # Skapa arbetstråden
        self.worker_thread = QThread()
        self.worker = CryptoWorker(
            'encrypt', self.file_list, public_key, self.private_key,
            output_path=output_path,
            split_file=split_file,
            split_size=split_size
        )
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.encryption_finished)
        self.worker.error.connect(self.show_error)
        self.worker_thread.start()

        # Visa progress bar
        self.total_progress_bar.show()
        self.current_file_label.show()

    def decrypt_files(self):
        if not self.private_key:
            QMessageBox.warning(self, "Fel", "Ingen privat nyckel tillgänglig.")
            return
        if not self.file_list:
            QMessageBox.warning(self, "Fel", "Inga filer att dekryptera.")
            return

        extract_path = self.default_directory
        if not extract_path:
            extract_path = QFileDialog.getExistingDirectory(self, "Välj mapp för att spara dekrypterade filer")
            if not extract_path:
                QMessageBox.warning(self, "Avbrutet", "Dekryptering avbröts.")
                return

        # Skapa arbetstråden
        self.worker_thread = QThread()
        self.worker = CryptoWorker(
            'decrypt', self.file_list, None, self.private_key,
            extract_path=extract_path
        )
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.decryption_finished)
        self.worker.error.connect(self.show_error)
        self.worker_thread.start()

        # Visa progress bar
        self.total_progress_bar.show()
        self.current_file_label.show()

    def update_progress(self, current_file_index, total_files, current_file_name):
        percent = int((current_file_index / total_files) * 100)
        self.total_progress_bar.setValue(percent)
        self.current_file_label.setText(f"Bearbetar: {current_file_name}")

    def encryption_finished(self):
        self.total_progress_bar.hide()
        self.current_file_label.hide()
        self.total_progress_bar.setValue(0)
        self.current_file_label.setText("")
        QMessageBox.information(self, "Kryptering", "Kryptering slutförd.")

    def decryption_finished(self):
        self.total_progress_bar.hide()
        self.current_file_label.hide()
        self.total_progress_bar.setValue(0)
        self.current_file_label.setText("")
        QMessageBox.information(self, "Dekryptering", "Dekryptering slutförd.")
        # Lägg till "Visa filerna"-knapp
        open_folder = QMessageBox.question(self, "Dekryptering", "Vill du öppna mappen med filerna?", QMessageBox.Yes | QMessageBox.No)
        if open_folder == QMessageBox.Yes:
            webbrowser.open(self.default_directory)

    def show_error(self, message):
        QMessageBox.warning(self, "Fel", f"Ett fel uppstod: {message}")

    def encrypt_text(self):
        if not self.public_keys:
            QMessageBox.warning(self, "Fel", "Ingen publik nyckel tillgänglig.")
            return
        message = self.text_edit.toPlainText()
        if not message:
            QMessageBox.warning(self, "Fel", "Ingen text att kryptera.")
            return

        profile_name = self.profile_combo_text.currentText()
        public_key = self.public_keys.get(profile_name)
        if not public_key:
            QMessageBox.warning(self, "Fel", "Vald profil har ingen giltig publik nyckel.")
            return

        try:
            message_bytes = message.encode('utf-8')
            encrypted_message = public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_hex = encrypted_message.hex()
            self.text_edit.setPlainText(encrypted_hex)
            # Kopiera till urklipp
            clipboard = QApplication.clipboard()
            clipboard.setText(encrypted_hex)
            # Visa dialog om inställningen är satt
            if self.show_encryption_dialog:
                dialog = EncryptionDialog()
                dialog.setFixedSize(600, 200)
                if dialog.exec_() == QDialog.Accepted:
                    self.show_encryption_dialog = not dialog.checkbox.isChecked()
                    self.save_settings()
        except Exception as e:
            QMessageBox.warning(self, "Fel", f"Kryptering misslyckades.\n{str(e)}")

    def decrypt_text(self):
        if not self.private_key:
            QMessageBox.warning(self, "Fel", "Ingen privat nyckel tillgänglig.")
            return
        message = self.text_edit.toPlainText()
        if not message:
            QMessageBox.warning(self, "Fel", "Ingen text att dekryptera.")
            return
        try:
            encrypted_message = bytes.fromhex(message)
            decrypted_message = self.private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.text_edit.setPlainText(decrypted_message.decode('utf-8'))
            # Använd anpassad meddelanderuta för styling
            message_box = QMessageBox(self)
            message_box.setWindowTitle("Dekryptering")
            message_box.setText("Meddelandet har dekrypterats.")
            message_box.setIcon(QMessageBox.Information)
            apply_style(message_box)  # Stilar hanteras i styles.qss
            message_box.setFixedSize(600, 200)
            message_box.exec_()
        except Exception as e:
            QMessageBox.warning(self, "Fel", f"Kunde inte dekryptera meddelandet.\n{str(e)}")

    def create_file_mode(self):
        # Fil-läge
        self.file_widget = QWidget()
        self.file_layout = QVBoxLayout()
        self.file_widget.setLayout(self.file_layout)

        # Lägg till kryssruta och kombinationsruta för att dela upp filen
        self.split_file_checkbox = QCheckBox("Dela upp den krypterade filen i flera mindre bitar")
        self.split_file_checkbox.stateChanged.connect(self.toggle_split_size_combo)
        self.file_layout.addWidget(self.split_file_checkbox)

        self.split_size_combo = QComboBox()
        self.split_size_combo.addItems(["1 MB", "5 MB", "10 MB", "100 MB", "1 GB"])
        self.split_size_combo.setEnabled(False)
        self.file_layout.addWidget(self.split_size_combo)

        # Lägg till profilval
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(self.public_keys.keys())
        title_label = QLabel("Välj profil för kryptering:")
        title_label.setObjectName("titleLabel")
        self.file_layout.addWidget(title_label)
        self.file_layout.addWidget(self.profile_combo)

        # Lägg till fil-widgetar
        self.drop_zone = DropListWidget(self)
        self.file_layout.addWidget(QLabel("Dra och släpp filer här:"))
        self.file_layout.addWidget(self.drop_zone)

        self.file_button_layout = QHBoxLayout()
        self.add_file_button = QPushButton("Lägg till fil")
        self.add_file_button.clicked.connect(self.add_file)
        self.remove_file_button = QPushButton("Ta bort fil(er)")
        self.remove_file_button.clicked.connect(self.remove_file)
        self.clear_files_button = QPushButton("Rensa alla")
        self.clear_files_button.clicked.connect(self.clear_files)
        self.file_button_layout.addWidget(self.add_file_button)
        self.file_button_layout.addWidget(self.remove_file_button)
        self.file_button_layout.addWidget(self.clear_files_button)
        self.file_layout.addLayout(self.file_button_layout)

        # Progress bars
        self.progress_layout = QVBoxLayout()
        self.current_file_label = QLabel("Ingen aktiv fil")
        self.progress_layout.addWidget(self.current_file_label)
        self.total_progress_bar = QProgressBar()
        self.total_progress_bar.setFormat("Total framsteg: %p%")
        self.progress_layout.addWidget(self.total_progress_bar)
        self.file_layout.addLayout(self.progress_layout)

        # Visa/Dölj progress bar-knapp
        self.toggle_queue_button = QPushButton("Visa/Dölj progress bar")
        self.toggle_queue_button.clicked.connect(self.toggle_queue_visibility)
        self.file_layout.addWidget(self.toggle_queue_button)

        # Döljer progress bar initialt
        self.progress_layout.setAlignment(Qt.AlignTop)
        self.progress_layout.setContentsMargins(0, 0, 0, 0)
        self.total_progress_bar.hide()
        self.current_file_label.hide()

    def toggle_split_size_combo(self, state):
        self.split_size_combo.setEnabled(state == Qt.Checked)

    def create_text_mode(self):
        # Text-läge
        self.text_widget = QWidget()
        self.text_layout = QVBoxLayout()
        self.text_widget.setLayout(self.text_layout)

        # Lägg till profilval för textläge
        self.profile_combo_text = QComboBox()
        self.profile_combo_text.addItems(self.public_keys.keys())
        title_label = QLabel("Välj profil för kryptering:")
        title_label.setObjectName("titleLabel")
        self.text_layout.addWidget(title_label)
        self.text_layout.addWidget(self.profile_combo_text)

        # Lägg till text-widgetar
        self.text_layout.addWidget(QLabel("Skriv ett meddelande:"))
        self.text_edit = QTextEdit()
        self.text_edit.setAcceptDrops(False)
        self.text_layout.addWidget(self.text_edit)

        # Lägg till rensa-knapp för text
        self.clear_text_button = QPushButton("Rensa text")
        self.clear_text_button.clicked.connect(self.clear_text)
        self.text_layout.addWidget(self.clear_text_button)

    def create_chat_mode(self):
        # Chat-läge
        self.chat_widget = QWidget()
        self.chat_layout = QVBoxLayout()
        self.chat_widget.setLayout(self.chat_layout)

        # Lägg till profilval för chat-läge
        self.profile_combo_chat = QComboBox()
        self.profile_combo_chat.addItems(self.public_keys.keys())
        self.profile_combo_chat.currentIndexChanged.connect(self.change_chat_profile)
        title_label = QLabel("Välj profil för chat:")
        title_label.setObjectName("titleLabel")
        self.chat_layout.addWidget(title_label)
        self.chat_layout.addWidget(self.profile_combo_chat)

        # Chat display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_layout.addWidget(self.chat_display)

        # Chat input layout
        input_layout = QHBoxLayout()

        # Bifoga fil-knapp
        attach_icon = QIcon(get_resource_path(os.path.join("assets", "attach_files.png")))
        self.attach_button = QPushButton()
        self.attach_button.setIcon(attach_icon)
        self.attach_button.clicked.connect(self.attach_file)
        input_layout.addWidget(self.attach_button)

        # Chat input
        self.chat_input = QLineEdit()
        self.chat_input.returnPressed.connect(self.send_chat_message)
        input_layout.addWidget(self.chat_input)

        # Skicka-knapp
        send_icon = QIcon(get_resource_path(os.path.join("assets", "send_icon.png")))
        self.send_button = QPushButton()
        self.send_button.setIcon(send_icon)
        self.send_button.clicked.connect(self.send_chat_message)
        input_layout.addWidget(self.send_button)

        self.chat_layout.addLayout(input_layout)

    def attach_file(self):
        options = QFileDialog.Options()
        files, _ = QFileDialog.getOpenFileNames(self, "Välj filer att bifoga", "", "Alla filer (*)", options=options)
        if files:
            # Hantera bifogade filer (implementera enligt dina behov)
            QMessageBox.information(self, "Bifoga filer", f"{len(files)} filer har bifogats (funktionalitet att skicka filer kan implementeras).")

    def change_chat_profile(self):
        profile_name = self.profile_combo_chat.currentText()
        self.chat_display.clear()
        if profile_name in self.chat_history:
            for message in self.chat_history[profile_name]:
                self.chat_display.append(message)

    def send_chat_message(self):
        message = self.chat_input.text()
        if not message:
            return
        profile_name = self.profile_combo_chat.currentText()
        public_key = self.public_keys.get(profile_name)
        if not public_key:
            QMessageBox.warning(self, "Fel", "Vald profil har ingen giltig publik nyckel.")
            return
        try:
            message_bytes = message.encode('utf-8')
            encrypted_message = public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_hex = encrypted_message.hex()
            # Lägg till meddelandet i chat-historiken
            display_message = f"<b>Du:</b> {message}"
            if profile_name not in self.chat_history:
                self.chat_history[profile_name] = []
            self.chat_history[profile_name].append(display_message)
            self.chat_display.append(display_message)
            self.chat_input.clear()
        except Exception as e:
            QMessageBox.warning(self, "Fel", f"Kunde inte skicka meddelandet.\n{str(e)}")

