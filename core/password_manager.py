# CryptoZ/core/password_manager.py

"""
Encrypted local password vault using Fernet encryption.
Integrates PBKDF2, optional key file, and secure memory handling.
"""

import json
import os
import base64
import hashlib
from typing import List, Dict, Optional
from datetime import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config.settings import AppSettings
from core.security_utils import SecurityUtils


class PasswordVault:
    """
    Local encrypted password manager.
    Stores data in a single file: passwords.cryptozvault
    Uses Fernet (AES-128) with PBKDF2 key derivation and optional key file.
    """

    def __init__(self, vault_path: str = None, settings: AppSettings = None):
        self.settings = settings or AppSettings()
        self.vault_path = vault_path or "passwords.cryptozvault"
        self.data: List[Dict[str, str]] = []
        self._fernet: Optional[Fernet] = None
        self.salt: bytes = b''
        self.iterations = self.settings.get("security.key_derivation_iterations", 310000)

    def _derive_key(self, master_password: str) -> bytes:
        """
        Derive encryption key from master password using PBKDF2.
        :param master_password: user's master password
        :return: derived Fernet-compatible key (32 bytes, base64-encoded)
        """
        if not self.salt:
            self.salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.iterations
        )
        key = kdf.derive(master_password.encode())
        return base64.urlsafe_b64encode(key)

    def _initialize_fernet(self, master_password: str) -> bool:
        """
        Initialize Fernet cipher using master password and optional key file.
        :param master_password: user's master password
        :return: True if successful
        """
        if not self.salt:
            return False

        main_key = self._derive_key(master_password)
        use_key_file = self.settings.get("security.use_key_file", True)
        key_material = b''

        if use_key_file:
            key_path = "secret.key"
            if not os.path.exists(key_path):
                print("[Vault] secret.key not found")
                return False
            with open(key_path, "rb") as kf:
                key_material = kf.read()

        # Combine keys and normalize to 32 bytes
        combined_key = main_key + key_material
        raw_key = (combined_key[:32]).ljust(32, b'\0')
        fernet_key = base64.urlsafe_b64encode(raw_key)
        self._fernet = Fernet(fernet_key)
        return True

    def create_new_vault(self, master_password: str) -> bool:
        """
        Create a new vault with fresh salt and optional key file.
        :param master_password: master password for new vault
        :return: True if created successfully
        """
        self.data = []
        self.salt = os.urandom(16)

        use_key_file = self.settings.get("security.use_key_file", True)
        key_material = b''

        if use_key_file:
            key_material = os.urandom(32)
            key_path = "secret.key"
            if os.path.exists(key_path):
                backup = key_path + ".bak"
                if os.path.exists(backup):
                    os.remove(backup)
                os.rename(key_path, backup)
            with open(key_path, "wb") as f:
                f.write(key_material)

        main_key = self._derive_key(master_password)
        combined_key = main_key + key_material
        raw_key = (combined_key[:32]).ljust(32, b'\0')
        fernet_key = base64.urlsafe_b64encode(raw_key)
        self._fernet = Fernet(fernet_key)

        self.save()
        return True

    def unlock(self, master_password: str) -> bool:
        """
        Unlock existing vault using master password.
        :param master_password: master password
        :return: True if unlock successful
        """
        if not os.path.exists(self.vault_path):
            return False

        try:
            with open(self.vault_path, 'r') as f:
                data = json.load(f)

            self.salt = base64.b64decode(data["salt"])
            encrypted_data = base64.b64decode(data["data"])

            if not self._initialize_fernet(master_password):
                return False

            decrypted_json = self._fernet.decrypt(encrypted_data).decode()
            self.data = json.loads(decrypted_json)

            # Securely wipe sensitive temporary data
            temp_bytes = bytearray(decrypted_json, 'utf-8')
            SecurityUtils.secure_wipe(temp_bytes)

            return True

        except Exception as e:
            print(f"[Vault] Unlock failed: {e}")
            return False

    def save(self):
        """
        Save encrypted data to file with backup.
        Raises exception if vault is not unlocked.
        """
        if not self._fernet:
            raise Exception("Vault not unlocked")

        try:
            encrypted_data = self._fernet.encrypt(json.dumps(self.data).encode())

            data_to_save = {
                "salt": base64.b64encode(self.salt).decode(),
                "data": base64.b64encode(encrypted_data).decode(),
                "iterations": self.iterations,
                "version": "1.0"
            }

            # Backup old file if exists
            if os.path.exists(self.vault_path):
                backup = self.vault_path + ".bak"
                if os.path.exists(backup):
                    os.remove(backup)
                os.rename(self.vault_path, backup)

            # Save new data
            with open(self.vault_path, 'w') as f:
                json.dump(data_to_save, f, indent=2)

        except Exception as e:
            print(f"[Vault] Save failed: {e}")
            # Attempt to restore backup?
            raise

    def add_entry(self, site: str, login: str, password: str, notes: str = "", category: str = "General", color: list = None):
        """
        Add a new password entry.
        :param site: website or service name
        :param login: username or email
        :param password: password (will be stored encrypted)
        :param notes: optional notes
        :param category: category tag
        :param color: background color for UI [r, g, b, a]
        """
        entry_color = color or [30, 30, 60, 255]

        self.data.append({
            "site": site,
            "login": login,
            "password": password,
            "notes": notes,
            "category": category,
            "color": entry_color,
            "created_at": datetime.now().isoformat()
        })

        self.save()

    def delete_entry(self, site: str, login: str):
        """
        Remove entry by site and login.
        :param site: website name
        :param login: login/username
        """
        self.data = [e for e in self.data if not (e["site"] == site and e["login"] == login)]
        self.save()

    def get_all_entries(self) -> List[Dict[str, any]]:
        """
        Get all valid entries.
        :return: list of entries (dicts)
        """
        return [e for e in self.data if isinstance(e, dict) and "site" in e]

    def search(self, query: str) -> List[Dict[str, any]]:
        """
        Search entries by site, login, or notes.
        :param query: search term
        :return: list of matching entries
        """
        if not query:
            return self.get_all_entries()

        query = query.lower()
        return [
            entry for entry in self.data
            if query in entry.get("site", "").lower()
            or query in entry.get("login", "").lower()
            or query in entry.get("notes", "").lower()
        ]

    def analyze_security(self) -> Dict[str, any]:
        """
        Analyze password security: duplicates, length, etc.
        :return: security report
        """
        report = {
            "total": len(self.data),
            "reused_passwords": 0,
            "weak_passwords": 0,
            "suggestions": []
        }

        passwords = [e["password"] for e in self.data if isinstance(e, dict)]
        pwd_counts = {}
        for pwd in passwords:
            pwd_counts[pwd] = pwd_counts.get(pwd, 0) + 1

        reused = sum(1 for count in pwd_counts.values() if count > 1)
        report["reused_passwords"] = reused
        if reused > 0:
            report["suggestions"].append(f"{reused} password(s) are reused — consider changing them")

        weak = sum(1 for pwd in passwords if len(pwd) < 8)
        report["weak_passwords"] = weak
        if weak > 0:
            report["suggestions"].append(f"{weak} password(s) are shorter than 8 characters")

        return report

    def wipe_sensitive_data(self):
        """
        Securely wipe sensitive in-memory data.
        Call this before closing vault or on timeout.
        """
        if self._fernet:
            del self._fernet
            self._fernet = None

        # Wipe salt
        if self.salt:
            mutable_salt = bytearray(self.salt)
            SecurityUtils.secure_wipe(mutable_salt)
            self.salt = b''
