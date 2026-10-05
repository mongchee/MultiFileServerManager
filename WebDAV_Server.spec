# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all
from PyInstaller.building.api import Splash

datas = [
    ('app_icon.ico', '.'),
    ('splash.png', '.'),
]
binaries = []
hiddenimports = []

for mod in ['wsgidav', 'cheroot', 'pystray', 'pyftpdlib', 'cryptography', 'defusedxml']:
    tmp_ret = collect_all(mod)
    datas += tmp_ret[0]
    binaries += tmp_ret[1]
    hiddenimports += tmp_ret[2]

excludes = [
    'tkinter.test',
    'unittest',
    'test',
    'pdb',
    'pydoc',
    'doctest',
    'difflib',
    'curses',
    'xmlrpc',
    'distutils',
    'setuptools',
    'asyncio.test',
    'sqlite3',
    'lib2to3',
    'scipy',
    'numpy',
    'pandas',
    'matplotlib',
]

a = Analysis(
    ['webdav_server_gui.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure, optimize=2)

# ==============================================================================
# 1. 스플래시 화면 (클릭 즉시 0.05초 만에 화면 중앙에 로딩 화면 표시)
# ==============================================================================
splash = Splash(
    'splash.png',
    binaries=a.binaries,
    datas=a.datas,
    text_pos=(32, 205),
    text_size=9,
    text_color='#94a3b8',
    text_default='통합 파일 서버 환경 준비 중...',
    always_on_top=True,
)

# ==============================================================================
# 2. 최적화 단일 실행 파일 (Splash 탑재 휴대용 배포 버전) -> dist/WebDAV_Server.exe
# ==============================================================================
exe_single = EXE(
    pyz,
    a.scripts,
    splash,
    splash.binaries,
    a.binaries,
    a.datas,
    [],
    name='WebDAV_Server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app_icon.ico'],
)

# ==============================================================================
# 3. 초고속 온디렉터리 실행 파일 (압축 해제 0초, 0.1초 즉시 실행) -> dist/WebDAV_Server_Fast/
# ==============================================================================
exe_onedir = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='WebDAV_Server',
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
    icon=['app_icon.ico'],
)

coll = COLLECT(
    exe_onedir,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='WebDAV_Server_Fast',
)
