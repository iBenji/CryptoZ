# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

assets = [
    ('assets/icon.svg', 'assets'),
    ('assets/icon.ico', 'assets'),
    ('assets/icon.png', 'assets'),
    ('cryptoz_config.json', '.'),
    ('convert_icon.py', '.'),  # Include converter for first run
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=assets,
    hiddenimports=[
        'cryptography',
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Util',
        'Crypto.Protocol',
        'Crypto.Random',
        'dearpygui',
        'logging.handlers',
        'pathlib',
        'threading',
        'json',
        'base64',
        'hashlib',
        'secrets',
        'collections',
        'math',
        'typing',
        'functools',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Note: CairoSVG is optional, so we don't include it by default

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CryptoZ',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico',
)