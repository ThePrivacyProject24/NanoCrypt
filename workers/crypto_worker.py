# workers/crypto_worker.py
from PyQt5.QtCore import QObject, pyqtSignal
import os
import zipfile
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

class CryptoWorker(QObject):
    progress = pyqtSignal(int, int, str)  # (current_file_index, total_files, current_file_name)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, operation, files, public_key, private_key, extract_path=None, output_path=None, split_file=False, split_size=None):
        super().__init__()
        self.operation = operation  # 'encrypt' or 'decrypt'
        self.files = files
        self.public_key = public_key
        self.private_key = private_key
        self.extract_path = extract_path
        self.output_path = output_path
        self.split_file = split_file
        self.split_size = split_size  # in bytes

    def run(self):
        try:
            if self.operation == 'encrypt':
                self.encrypt_files()
            elif self.operation == 'decrypt':
                self.decrypt_files()
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))
        finally:
            # Rensa känsliga data från minnet
            self.private_key = None
            self.public_key = None

    def encrypt_files(self):
        total_files = len(self.files)
        try:
            # Kontrollera filstorlekar
            for file in self.files:
                if os.path.getsize(file) > MAX_FILE_SIZE:
                    raise Exception(f"Filen {file} överstiger maximal tillåten storlek.")

            # Skapa en arkivfil med alla filer
            archive_name = "archive.zip"
            with zipfile.ZipFile(archive_name, 'w') as zipf:
                for file in self.files:
                    # Kontrollera filnamnets längd
                    filename = os.path.basename(file)
                    max_length = self.public_key.key_size // 8 - 2 * hashes.SHA256().digest_size - 2
                    if len(filename.encode('utf-8')) > max_length:
                        raise Exception(f"Filnamnet {filename} är för långt för kryptering.")
                    # Kryptera filnamnet
                    encrypted_filename = self.encrypt_filename(filename)
                    zipf.write(file, encrypted_filename)
                    self.progress.emit(1, total_files, filename)

            # Kryptera arkivfilen
            with open(archive_name, "rb") as f:
                data = f.read()
            os.remove(archive_name)
            encrypted_data = self.encrypt_data(data)

            # Spara i output_path under profilens namn
            if not os.path.exists(self.output_path):
                os.makedirs(self.output_path)
            # Generera unikt filnamn
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            encrypted_filepath = os.path.join(self.output_path, f"encrypted_{timestamp}.enc")

            # Dela upp filen om det är valt
            if self.split_file and self.split_size:
                self.split_and_save_file(encrypted_data, encrypted_filepath)
            else:
                with open(encrypted_filepath, "wb") as f:
                    f.write(encrypted_data)

            self.progress.emit(total_files, total_files, "Alla filer")
        except Exception as e:
            self.error.emit(f"Fel vid kryptering av filer: {str(e)}")

    def decrypt_files(self):
        total_files = len(self.files)
        try:
            # Om filen är uppdelad, kombinera den
            if len(self.files) > 1 or self.files[0].endswith('.part1'):
                encrypted_data = self.combine_split_files(self.files)
            else:
                with open(self.files[0], "rb") as f:
                    encrypted_data = f.read()

            decrypted_data = self.decrypt_data(encrypted_data)
            if decrypted_data is None:
                self.error.emit(f"Kunde inte dekryptera filen.")
                return

            archive_name = "decrypted_files.zip"
            with open(archive_name, "wb") as f:
                f.write(decrypted_data)

            if self.extract_path:
                with zipfile.ZipFile(archive_name, 'r') as zip_ref:
                    # Dekryptera filnamn
                    for member in zip_ref.infolist():
                        original_filename = self.decrypt_filename(member.filename)
                        member.filename = original_filename
                        zip_ref.extract(member, self.extract_path)
                os.remove(archive_name)

            self.progress.emit(total_files, total_files, "Alla filer")
        except Exception as e:
            self.error.emit(f"Fel vid dekryptering av filer: {str(e)}")

    def encrypt_data(self, data):
        # Generera symmetrisk nyckel
        sym_key = os.urandom(32)
        # Kryptera data med symmetrisk nyckel med AES-GCM
        aad = b"authenticated but unencrypted data"
        encryptor = AESGCM(sym_key)
        nonce = os.urandom(12)
        encrypted_data = encryptor.encrypt(nonce, data, aad)
        # Kryptera symmetrisk nyckel med publik nyckel
        encrypted_sym_key = self.public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Returnera nonce + krypterad symmetrisk nyckel + krypterad data
        return nonce + encrypted_sym_key + encrypted_data

    def decrypt_data(self, data):
        encrypted_sym_key_length = self.private_key.key_size // 8
        if len(data) < 12 + encrypted_sym_key_length:
            return None
        nonce = data[:12]
        encrypted_sym_key = data[12:12 + encrypted_sym_key_length]
        encrypted_data = data[12 + encrypted_sym_key_length:]
        try:
            sym_key = self.private_key.decrypt(
                encrypted_sym_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Dekryptera data med symmetrisk nyckel
            aad = b"authenticated but unencrypted data"
            decryptor = AESGCM(sym_key)
            decrypted_data = decryptor.decrypt(nonce, encrypted_data, aad)
            return decrypted_data
        except Exception:
            return None

    def encrypt_filename(self, filename):
        encrypted_bytes = self.public_key.encrypt(
            filename.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Använd URL-säker Base64-kodning för filnamn
        return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

    def decrypt_filename(self, encrypted_filename):
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_filename)
            decrypted_bytes = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return "dekrypterad_fil"

    def split_and_save_file(self, data, filepath):
        total_size = len(data)
        part_number = 1
        index = 0
        while index < total_size:
            part_data = data[index:index + self.split_size]
            part_filename = f"{filepath}.part{part_number}"
            with open(part_filename, "wb") as f:
                f.write(part_data)
            index += self.split_size
            part_number += 1

    def combine_split_files(self, files):
        data = b""
        base_filename = files[0].split('.part')[0]
        part_files = []
        part_number = 1
        while True:
            part_file = f"{base_filename}.part{part_number}"
            if os.path.exists(part_file):
                part_files.append(part_file)
                part_number += 1
            else:
                break
        if not part_files:
            raise Exception("Inga delar av den uppdelade filen hittades.")
        for file in part_files:
            with open(file, "rb") as f:
                data += f.read()
        return data
