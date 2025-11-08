# core/secure_folder.py
#import os
import time
#import shutil
#import threading
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.crypto_engine import CryptoEngine

class TempFileHandler(FileSystemEventHandler):
    def __init__(self, secure_folder_manager):
        self.manager = secure_folder_manager

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_file_change(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._handle_file_change(event.dest_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_file_change(event.src_path)

    def _handle_file_change(self, file_path: str):
        temp_path = Path(file_path)

        # Игнорируем временные файлы
        if temp_path.name.startswith('~') or '.tmp' in temp_path.name:
            return
        if not temp_path.is_file():
            return

        print(f"Change detected: {temp_path.name} (stem={temp_path.stem})")

        # Ищем все .enc файлы
        pattern = f"*{self.manager.encrypted_extension}"
        enc_files = list(self.manager.folder_path.rglob(pattern))
        if not enc_files:
            print(f"No .enc files found in {self.manager.folder_path}")
            return

        for enc_file in enc_files:
            if not enc_file.is_file():
                continue

            # Убираем .enc → получаем ожидаемое имя оригинала
            if enc_file.name.endswith(self.manager.encrypted_extension):
                base_enc_name = enc_file.name[:-len(self.manager.encrypted_extension)]
            else:
                continue

            # Сравниваем полное имя временного файла с base_enc_name
            if temp_path.name == base_enc_name:
                print(f"MATCH: {temp_path.name} ←→ {enc_file.name}")
                time.sleep(0.3)
                self.manager._reencrypt_file(enc_file, temp_path)
                return

        print("No matching .enc file found")





class SecureFolderManager:
    def __init__(self, folder_path: str, password: str, crypto_engine: CryptoEngine, algorithm: str = 'aes_gcm', log_callback=None, settings=None):
        self.folder_path = Path(folder_path).resolve()
        self.password = password
        self.crypto_engine = crypto_engine
        self.algorithm = algorithm
        self.log_callback = log_callback
        self.settings = settings
        self.encrypted_extension = ".enc"
        self.temp_dir = self.folder_path / ".temp_decrypted"
        self.observer = Observer()
        self.is_running = False

        self.folder_path.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)

        self._log(f"Secure folder initialized: {self.folder_path}")
        self._log(f"Algorithm: {self.algorithm}, Extension: {self.encrypted_extension}")

    def _log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def start_monitoring(self):
        if self.is_running:
            return
        self._cleanup_stale_files()

        event_handler = SecureFolderEventHandler(self)
        self.observer.schedule(event_handler, str(self.folder_path), recursive=True)
        self.observer.start()
        print(f"SecureFolder: started monitoring {self.folder_path}")

        # For Temp folder
        self.temp_handler = TempFileHandler(self)
        self.temp_observer = Observer()
        self.temp_observer.schedule(self.temp_handler, str(self.temp_dir), recursive=True)
        self.temp_observer.start()

        self._log("Secure Folder and Temp Folder are now monitoring")
        self.is_running = True

    def stop_monitoring(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            print("SecureFolder: stopped monitoring")

        if hasattr(self, 'temp_observer'):
            self.temp_observer.stop()
            self.temp_observer.join()

    def encrypt_file(self, file_path: Path):
        if not file_path.is_file() or file_path.suffix == self.encrypted_extension or ".temp_decrypted" in str(file_path):
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            encrypted_data = self.crypto_engine.encrypt_data(data, self.password, self.algorithm)
            encrypted_path = file_path.with_name(file_path.name + self.encrypted_extension)

            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            file_path.unlink()

            self._log(f"Encrypted: {file_path.name} -> {encrypted_path.name}")

            if self.settings:
                self.settings.increment_encrypted()

        except Exception as e:
            self._log(f"Encryption failed for {file_path.name}: {e}")


    def _reencrypt_file(self, enc_path: Path, temp_path: Path):
        try:
            with open(temp_path, 'rb') as f:
                data = f.read()

            encrypted_data = self.crypto_engine.encrypt_data(data, self.password, self.algorithm)

            temp_enc = enc_path.with_suffix(".enc.tmp")
            with open(temp_enc, 'wb') as f:
                f.write(encrypted_data)
            temp_enc.replace(enc_path)
            self._log(f"Re-encrypted: {enc_path.name}")

        except Exception as e:
            self._log(f"Re-encryption failed: {e}")


    def decrypt_file(self, encrypted_path: Path) -> Path:
        temp_output = None
        try:
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.crypto_engine.decrypt_data(encrypted_data, self.password, self.algorithm)

            if encrypted_path.name.endswith(self.encrypted_extension):
                original_name = encrypted_path.name[:-len(self.encrypted_extension)]
            else:
                original_name = encrypted_path.name

            temp_output = self.temp_dir / original_name
            temp_output.parent.mkdir(exist_ok=True, parents=True)

            with open(temp_output, 'wb') as f:
                f.write(decrypted_data)

            self._log(f"Decrypted: {encrypted_path.name} → {temp_output.name}")

            if self.settings:
                self.settings.increment_decrypted()

            return temp_output

        except Exception as e:
            self._log(f"Decryption failed for {encrypted_path.name}: {e}")
            return None


    def cleanup_temp_files(self):
        if self.temp_dir.exists():
            for file in self.temp_dir.iterdir():
                try:
                    if file.is_file():
                        file.unlink()
                        print(f"Cleaned: {file.name}")
                except Exception as e:
                    print(f"Cannot delete {file.name}: {e}")
            print("Temp folder cleaned")

    def _cleanup_stale_files(self):
        patterns = [
            f"*{self.encrypted_extension}.tmp",
            "*.tmp",
            f"*.tmp{self.encrypted_extension}",
            f"*{self.encrypted_extension}.*tmp*",
            "*~",
        ]

        cleaned_count = 0
        for pattern in patterns:
            for tmp_file in self.folder_path.rglob(pattern):
                if tmp_file.is_file():
                    try:
                        tmp_file.unlink()
                        self._log(f"Cleaned stale file: {tmp_file.name} (pattern: {pattern})")
                        cleaned_count += 1
                    except Exception as e:
                        self._log(f"Cannot delete {tmp_file.name}: {e}")

        if cleaned_count == 0:
            self._log("No stale files found")
        else:
            self._log(f"Cleaned {cleaned_count} stale file(s)")


class SecureFolderEventHandler(FileSystemEventHandler):
    """Обработчик изменений в папке"""

    def __init__(self, manager: SecureFolderManager):
        self.manager = manager

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        if not file_path.name.endswith(".enc"):
            time.sleep(0.1)
            self.manager.encrypt_file(file_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        if not file_path.name.endswith(".enc") and ".temp_decrypted" not in str(file_path):
            time.sleep(0.1)
            self.manager.encrypt_file(file_path)