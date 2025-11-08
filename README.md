# CryptoZ — Advanced Encryption & Security Suite

![CryptoZ](https://img.shields.io/badge/Version-2.2.0-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![GUI](https://img.shields.io/badge/GUI-Dear%20PyGUI-purple)

> 🔐 **From file encryption to policy-driven security — CryptoZ is your all-in-one cryptographic toolkit.**

CryptoZ is a **modern, cross-platform encryption suite** built with `Dear PyGUI`, designed for **developers, security professionals, and privacy-conscious users**. It combines **military-grade cryptography**, **real-time folder protection**, **steganography**, **policy automation**, and **advanced analysis** in a single powerful interface.

---

## 🚀 Core Features

### 🔐 Multi-Algorithm Cryptography
- **Fernet (AES-128-GCM)** – Authenticated, secure-by-default
- **AES-256** – CBC, GCM, CTR modes
- **ChaCha20-Poly1305** – Fast, modern stream cipher
- **Triple DES** – Legacy compatibility
- **XOR** – Educational/demo use
- All with **PBKDF2-HMAC-SHA256** (310,000+ iterations)

---

### 📁 Secure Folder — Live Encryption Vault
> Turn any folder into a self-encrypting workspace.

- **Auto-encrypt**: Files added → instantly encrypted
- **Decrypt on-demand**: Opens in `.temp_decrypted`
- **Edit & Save Back**: Auto-re-encrypt on save (even in Word, Excel, Notepad++)
- **Auto-Clean**: Temp files erased on stop or exit
- **Auto-Lock**: Full cleanup when app closes
- **Real-time monitoring**: Powered by `watchdog`

> 💡 No more manual steps — just work securely.

---

### 📜 Policy Engine — Automated Security Rules
> Define once, encrypt forever.

- **Create policies**: "Encrypt all `.txt` in `Documents\Secrets`"
- **Flexible targets**: Single files, folders, path lists
- **Pattern matching**: `*.pdf`, `config_*.json`, `**/private/*`
- **Auto-apply**: Rules trigger on file save or startup
- **Enable/Disable/Toggle**: Visual management
- **Batch execution**: Apply policies to existing files

> Ideal for compliance, automation, and recurring tasks.

---

### 🔁 Batch Folder Encryption
> Encrypt entire directory trees — recursively.

- **Preserves folder structure**
- **Progress tracking** with real-time status
- **Background processing** — UI stays responsive
- **Error logging** — detailed per-file report
- **Comprehensive logs** — every operation recorded
- Supports **allowed extensions**, **size limits**, **auto-backups**

---

### 🖼️ Steganography Suite
> Hide data in plain sight.

#### 🕵️ Cryptor
- **Hide in images**: PNG, JPG (auto-converted to PNG), BMP
- **Hide in audio**: WAV files
- **LSB & Enhanced LSB**: Max capacity, minimal distortion
- **Encrypt before hiding**: Double protection
- **Capacity calculator**: See how much you can hide

#### 🔍 Analyzer
- **Detect hidden content** in files
- **Extract & decrypt** hidden data
- **File analysis**: entropy, noise, pattern detection

---

### 💬 Message & Code Encryption
#### 📝 Message Encryption
- Real-time text encryption
- Base64 output for sharing
- Copy-to-clipboard
- Secure memory handling

#### 💻 Code Protection
- **Obfuscation**: Rename variables
- **Region-based encryption**: Protect key sections
- **Auto-select**: Encrypt entire file
- **Supports**: Python, JS, C++, HTML, etc.

---

### 🔍 Security Scanner
> Find secrets before attackers do.

- **Scan folders** for passwords, API keys, credentials
- **Entropy analysis** to detect encrypted or obfuscated files
- **Risk scoring**: High/Medium/Low
- **JSON reports** with details
- **Dashboard view** in UI

---

### 📊 Usage Statistics
> Track your security journey.

- **Files encrypted/decrypted**
- **Active sessions**
- **Last session time**
- **Real-time UI updates**
- **Saved in `cryptoz_config.json`**

> See `About → 📊 Stats` for live dashboard.

---

### 🛠️ User Experience
- **Modern UI**: Categorized tabs — Files, Security, Tools, System
- **Auto-paths**: Input → Output generated automatically
- **Drag & Drop**: Drop files → encrypt
- **Password strength meter**: Real-time feedback
- **Background operations**: No UI freezing
- **Full logging**: Copy, clear, export

---

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- `pip`

### Method 1: From Source
```bash
git clone https://github.com/iBenji/CryptoZ.git
cd CryptoZ
pip install -r requirements.txt
python main.py

### Method 2: Standalone Executable
```bash
python build.py
# → Executable in /dist (Windows)
