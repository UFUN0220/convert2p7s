# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


block_cipher = None
project_dir = Path.cwd()
app_name = "P7S离线文件数字签名工具"


a = Analysis(
    ["p7s_signer.py"],
    pathex=[str(project_dir)],
    binaries=[],
    datas=[
        ("private_key.pem", "."),
        ("user.crt", "."),
    ],
    hiddenimports=[
        "cryptography",
        "cryptography.hazmat.bindings._rust",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "pytest",
        "unittest",
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=app_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=app_name,
)

app = BUNDLE(
    coll,
    name=f"{app_name}.app",
    icon=None,
    bundle_identifier="com.wabtec.p7s-signer",
    info_plist={
        "CFBundleName": app_name,
        "CFBundleDisplayName": app_name,
        "CFBundleShortVersionString": "1.2.2",
        "CFBundleVersion": "1.2.2",
        "NSHighResolutionCapable": True,
        "NSRequiresAquaSystemAppearance": False,
    },
)
