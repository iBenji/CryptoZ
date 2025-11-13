# Changelog

All notable changes to **CryptoZ** are documented in this file.

---

## [v2.3.0] - 2025-11-14

### ✨ New Features
- Added **automatic clipboard cleanup** 15 seconds after copying a password.
- Implemented **secure memory wiping on app shutdown**.
- Enhanced **password safety in modal dialogs** (add/edit password windows).

### 🔒 Security Improvements
- **Secure string wiping**:
  - Introduced `SecurityUtils.secure_wipe_string()` and `secure_wipe_bytes()` to overwrite sensitive data in memory.
  - Prevents password leakage via memory dumps or debugging tools.
- **Guaranteed cleanup on exit**:
  - All passwords, encryption keys, and temporary data are securely erased.
- `PasswordVault.wipe_sensitive_data()` — securely clears all vault-related secrets from memory.

### 🐛 Bug Fixes
- Fixed memory leaks: passwords were not cleared from memory when closing modals or the app.

### 🧹 Improvements
- All security-critical actions (copy, lock, shutdown) are now logged.
- Modal windows (add/edit password) securely wipe passwords on **any closure** (Cancel, X, Escape).
- Improved error resilience and graceful shutdown handling.

### 📦 Dependencies
- Requires `pyperclip` for clipboard operations.

---

## [v2.2.0] - 2025-11-09

(Previous release: Usage Stats, Auto-clean/lock, Secure Folder)
