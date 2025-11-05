# CryptoZ - Advanced Encryption Tool

![CryptoZ](https://img.shields.io/badge/Version-2.1.5-blue)
![Python](https://img.shields.io/badge/Python-3.1B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

A powerful, modern encryption utility built with Dear PyGui that provides multiple encryption algorithms for files, messages, and source code protection.

![file enc](https://github.com/user-attachments/assets/4687a182-1f0d-454b-bf26-6ba225aa47c1)

## 🚀 Features

### 🔐 Multi-Algorithm Support
- **Fernet (AES-128)** - Recommended secure algorithm
- **AES-CBC (256-bit)** - Standard block cipher mode
- **AES-GCM (256-bit)** - Authenticated encryption
- **AES-CTR (256-bit)** - Stream cipher mode
- **ChaCha20** - Modern stream cipher
- **Triple DES** - Legacy algorithm support
- **XOR** - Basic encryption for educational purposes

### 📁 File Operations
- Encrypt/decrypt any file type with automatic format detection
- Smart output naming (.encrypted → .decrypted)
- Secure key derivation using PBKDF2 with configurable iterations
- Batch operation support with progress tracking
- File size limits and validation

### 💬 Message Encryption
- Real-time text message encryption
- Support for all available algorithms
- Base64 encoded output for easy sharing
- Copy-to-clipboard functionality
- Secure memory handling

### 💻 Code Protection
- Source code obfuscation with variable renaming
- Base64 encoding with markers for code regions
- XOR encryption with key derivation
- Selective region encryption
- Support for multiple programming languages

### 🔍 Security Analysis
- File encryption detection through entropy analysis
- Algorithm signature recognition
- Password strength assessment with real-time feedback
- Secure password generation
- File integrity checking

### 🔑 Security Features
- Secure password generation
- Password strength assessment
- Key derivation with configurable iterations
- Secure memory handling

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step-by-Step Installation
## Method 1: From Source
1. **Clone or download the project**
   ```
   git clone https://github.com/iBenji/CryptoZ.git
   cd CryptoZ
   ```
2. **Install dependencies**
   ```
   pip install -r requirements.txt
   ```
3. **Run the application**
   ```
   python main.py
   ```
## Method 2: Standalone Executable (Recommended)
1. **Build the executable**
   ```
   python build.py
   ```
2. **Find the executable in the [dist] folder**
   ```
   The executable contains all dependencies and is ready to run
   ```
## 🛠️ Usage

### File Encryption Tab
1. Select Input File: Click "Browse" to choose a file to encrypt/decrypt
2. Output Path: Automatically generated with appropriate extension (.encrypted/.decrypted)
3. Choose Algorithm: Select from 7 encryption algorithms
4. Set Password: Enter a secure password (use the generator for strong passwords)
5. Execute: Click "Encrypt File" or "Decrypt File"

### Message Encryption Tab
1. Enter Text: Type or paste your message in the input area
2. Select Algorithm: Choose your preferred encryption method
3. Set Password: Create a secure password
4. Encrypt/Decrypt: Transform your message with a single click

### Code Encryption Tab
1. Paste Source Code: Enter your code in the input area
2. Choose Method: Select between obfuscation, Base64, or XOR encryption
3. Set Positions: Define the code region to encrypt (use "Auto Select" for entire code)
4. Encrypt/Decrypt: Protect or restore your code

### File Analyzer Tab
1. Select File: Choose any file for analysis
2. Analyze: Detect encryption algorithms and entropy levels
3. View Results: See detailed analysis including confidence scores

## 🏗️ Project Structure
   ```
CryptoZ/
├── main.py                 # Application entry point
├── create_icon.py          # Icon generation utility
├── build.py               # Build script for executables
├── requirements.txt       # Python dependencies
├── cryptoz_config.json   # Application settings
├── assets/
│   ├── icon.ico          # Windows icon
│   └── icon.png          # Cross-platform icon
├── core/
│   ├── crypto_engine.py  # Encryption algorithms
│   ├── security_utils.py # Password utilities
│   └── code_analyzer.py  # Code processing
├── gui/
│   └── main_window.py    # User interface
└── config/
    └── settings.py       # Configuration management
   ```
## 🔒 Security Features
### Key Derivation
- PBKDF2-HMAC-SHA256 with configurable iterations (default: 310,000)
- Cryptographically secure random salt generation
- Secure memory clearing of sensitive data

### Encryption Standards
- Fernet: AES-128 in CBC mode with PKCS7 padding, HMAC authentication
- AES: 256-bit keys with proper IV/nonce generation
- ChaCha20: 256-bit keys with 96-bit nonce
- Industry-standard cryptographic libraries (cryptography, pycryptodome)

### Safety Measures
- Input validation and sanitization
- Protection against path traversal attacks
- Secure file handling with error recovery
- Automatic cleanup of temporary files

### Configuration
The application settings can be customized in cryptoz_config.json:
   ```
{
  "security": {
    "default_algorithm": "fernet",
    "key_derivation_iterations": 310000,
    "password_length": 16
  },
  "ui": {
    "show_password_strength": true,
    "confirm_before_operations": true
  },
  "files": {
    "default_output_extension": ".encrypted",
    "max_file_size_mb": 100
  }
}
   ```
## 🐛 Troubleshooting
### Common Issues
**File not found errors**
- Ensure file paths are accessible
- Check read/write permissions
- Verify file exists

**Encryption/decryption failures**
- Confirm correct password
- Check algorithm compatibility
- Verify file integrity

**Application crashes**
- Ensure all dependencies are installed
- Check system resources
- Review log files in logs/ directory

### Logs and Debugging
- Application logs: logs/cryptoz.log
- Debug logs: logs/cryptoz_debug.log
- Configuration: cryptoz_config.json

## 🛡️ Security Notice
- This tool is designed for educational and professional use
- Always keep backups of important data
- Use strong, unique passwords
- Review the source code for transparency
- The developers are not responsible for data loss

## 🤝 Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly

5. Submit a pull request



