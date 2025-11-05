import os
import sys
import subprocess
import shutil
from pathlib import Path


def build_app():
    """Build CryptoZ as standalone executable"""
    print("🚀 Building CryptoZ application...")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("❌ PyInstaller not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Check if Pillow is installed
    try:
        from PIL import Image
    except ImportError:
        print("❌ Pillow not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    
    # Create icon if it doesn't exist
    if not os.path.exists("assets/icon.ico"):
        print("📝 Creating application icon...")
        subprocess.check_call([sys.executable, "create_icon.py"])
    
    # Create default config if it doesn't exist
    if not os.path.exists("cryptoz_config.json"):
        print("📝 Creating default config...")
        default_config = {
            "security": {
                "default_algorithm": "fernet",
                "key_derivation_iterations": 310000,
                "password_length": 16
            },
            "ui": {
                "show_password_strength": True,
                "confirm_before_operations": True
            },
            "files": {
                "default_output_extension": ".encrypted"
            }
        }
        import json
        with open("cryptoz_config.json", "w") as f:
            json.dump(default_config, f, indent=4)
    
    # Build with PyInstaller
    print("🔨 Building executable...")
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=CryptoZ",
        "--onefile",
        "--windowed",
        "--icon=assets/icon.ico",
        "--add-data=assets/icon.ico;assets",
        "--add-data=assets/icon.png;assets",
        "--add-data=cryptoz_config.json;.",
        "main.py"
    ]
    
    result = subprocess.call(cmd)
    
    if result == 0:
        print("✅ Build successful!")
        print(f"📁 Executable location: dist/CryptoZ.exe")
        print("🎉 Build completed successfully!")
    else:
        print("❌ Build failed!")
        sys.exit(1)


if __name__ == "__main__":
    build_app()