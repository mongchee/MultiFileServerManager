import io
import os
import sys
from typing import Dict, Optional, Tuple, Any, List
import json
import threading
import socket
import urllib.request
import urllib.parse
import base64
import html
import tempfile
import webbrowser
import subprocess
import time
import ssl
import datetime
import ipaddress
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import winreg
import pystray
from PIL import Image, ImageDraw
# pyftpdlib 라이브러리 (필수 기본 클래스만 선언 또는 지연 로딩)
from pyftpdlib.filesystems import AbstractedFS

# HTTP 서버
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

# 실행 파일(exe) 또는 스크립트 실행 경로 기준 설정 파일 위치 결정
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# PyInstaller Windows GUI 모드(console=False)에서 sys.stdout과 sys.stderr가 None으로 설정되거나
# encoding 속성이 없어 cheroot, wsgidav, http.server, logging 등 내부에서 오류가 발생하는 문제를
# 원천 방지하는 완벽한 표준 TextIO 호환 안전 스트림 클래스
class SafeStream(io.TextIOBase):
    encoding = "utf-8"
    errors = "replace"
    mode = "w"
    name = "<SafeStream>"
    @property
    def closed(self) -> bool:
        return False

    def __init__(self, log_path=None):
        super().__init__()
        self.log_path = log_path
        self._lock = threading.Lock()

    def write(self, s):
        if not s:
            return 0
        if self.log_path:
            try:
                with self._lock:
                    with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
                        f.write(str(s))
            except Exception:
                pass
        return len(str(s))

    def flush(self):
        pass

    def isatty(self):
        return False

    def writable(self):
        return True

    def readable(self):
        return False

    def seekable(self):
        return False

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def fileno(self):
        raise io.UnsupportedOperation("fileno is not supported")

    def reconfigure(self, **kwargs):
        pass

if sys.stdout is None or not hasattr(sys.stdout, "encoding") or sys.stdout.encoding is None:
    sys.stdout = SafeStream(os.path.join(BASE_DIR, "server.log"))
if sys.stderr is None or not hasattr(sys.stderr, "encoding") or sys.stderr.encoding is None:
    sys.stderr = SafeStream(os.path.join(BASE_DIR, "server_err.log"))
if getattr(sys, "__stdout__", None) is None:
    setattr(sys, "__stdout__", sys.stdout)
if getattr(sys, "__stderr__", None) is None:
    setattr(sys, "__stderr__", sys.stderr)

CONFIG_FILE = os.path.join(BASE_DIR, "webdav_config.json")
REG_KEY_NAME = "MultiFileServerManager"

# SSL/TLS 인증서 기본 저장 경로
SSL_DIR = os.path.join(BASE_DIR, "ssl")
DEFAULT_CERT_FILE = os.path.join(SSL_DIR, "server.crt")
DEFAULT_KEY_FILE = os.path.join(SSL_DIR, "server.key")


def generate_self_signed_cert(cert_path=DEFAULT_CERT_FILE, key_path=DEFAULT_KEY_FILE, san_ips=None):
    """2048-bit RSA 자체 서명 SSL 인증서 및 개인키 자동 생성 (유효기간 10년)"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    os.makedirs(os.path.dirname(os.path.abspath(cert_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MultiFileServerManager"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    alt_names = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
    ]
    if san_ips:
        for ip in san_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj not in [ipaddress.IPv4Address("127.0.0.1"), ipaddress.IPv4Address("0.0.0.0")]:
                    alt_names.append(x509.IPAddress(ip_obj))
            except Exception:
                pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10년 유효
        .add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)

    return cert_path, key_path


def get_cert_info(cert_path):
    """인증서 파일의 유효성 및 만료일 파싱"""
    if not cert_path or not os.path.exists(cert_path):
        return None
    try:
        from cryptography import x509
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        expiry_dt = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        is_valid = expiry_dt > now
        expiry_str = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        return {
            "expiry": expiry_str,
            "is_valid": is_valid,
            "exists": True
        }
    except Exception as e:
        return {"error": str(e), "exists": True}


def ensure_ssl_files(cert_path=None, key_path=None, san_ips=None):
    """인증서 파일이 없으면 자동 생성 후 경로 반환"""
    c_path = cert_path or DEFAULT_CERT_FILE
    k_path = key_path or DEFAULT_KEY_FILE

    if not (os.path.exists(c_path) and os.path.exists(k_path)):
        c_path, k_path = generate_self_signed_cert(c_path, k_path, san_ips=san_ips)
    return c_path, k_path

# ==============================================================================
# FTP 멀티 폴더 지원 파일시스템
# ==============================================================================
class MultiFolderFS(AbstractedFS):
    folder_mapping = {}

    def __init__(self, root, cmd_channel):
        super().__init__(root, cmd_channel)

    def validpath(self, path):
        norm_p = os.path.normcase(os.path.normpath(path))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_p == norm_root or norm_p.startswith(norm_root + os.sep):
            return True
        for real_base in self.folder_mapping.values():
            norm_base = os.path.normcase(os.path.normpath(real_base))
            if norm_p == norm_base or norm_p.startswith(norm_base + os.sep):
                return True
        return False
        
    def ftp2fs(self, ftppath):
        p = self.ftpnorm(ftppath)
        if not p or p == '/':
            return self.root

        parts = [x for x in p.split('/') if x]
        vname = parts[0]
        if vname in self.folder_mapping:
            real_base = self.folder_mapping[vname]
            rest = os.sep.join(parts[1:])
            return os.path.normpath(os.path.join(real_base, rest))
        
        return os.path.normpath(os.path.join(self.root, *parts))

    def fs2ftp(self, fspath):
        norm_fs = os.path.normcase(os.path.normpath(fspath))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_fs == norm_root:
            return '/'

        for vname, real_base in self.folder_mapping.items():
            norm_base = os.path.normcase(os.path.normpath(real_base))
            if norm_fs == norm_base:
                return f"/{vname}"
            if norm_fs.startswith(norm_base + os.sep):
                rel = os.path.relpath(fspath, real_base).replace('\\', '/')
                return f"/{vname}/{rel}"

        return '/'

    def chdir(self, path):
        norm_p = os.path.normcase(os.path.normpath(path))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_p == norm_root:
            self.cwd = '/'
            return
        os.chdir(path)
        self.cwd = self.fs2ftp(path)

    def listdir(self, path):
        norm_p = os.path.normcase(os.path.normpath(path))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_p == norm_root:
            return list(self.folder_mapping.keys())
        return os.listdir(path)

    def isdir(self, path):
        norm_p = os.path.normcase(os.path.normpath(path))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_p == norm_root:
            return True
        return os.path.isdir(path)

    def isfile(self, path):
        norm_p = os.path.normcase(os.path.normpath(path))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_p == norm_root:
            return False
        return os.path.isfile(path)

    def lexists(self, path):
        norm_p = os.path.normcase(os.path.normpath(path))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_p == norm_root:
            return True
        return os.path.lexists(path)

    def getstat(self, path):
        norm_p = os.path.normcase(os.path.normpath(path))
        norm_root = os.path.normcase(os.path.normpath(self.root))
        if norm_p == norm_root:
            return os.stat(tempfile.gettempdir())
        return os.stat(path)


# ==============================================================================
# WebDAV 멀티 폴더 지원 가상 루트 프로바이더 (MultiFolderDAVProvider)
# ==============================================================================
from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVError, HTTP_FORBIDDEN
from wsgidav.fs_dav_provider import FolderResource, FileResource


class MultiFolderDAVProvider(DAVProvider):
    """다중 폴더 등록 시 WebDAV 기본 루트(/)에서 모든 공유 폴더와 하위 파일/폴더를 완벽 제공하는 프로바이더"""

    def __init__(self, folder_mapping, readonly=False, fs_opts=None):
        super().__init__()
        self.readonly = readonly
        self.fs_opts = fs_opts or {}
        self.shadow_map = {}
        self.shares = {}
        self.name_map = {}
        for name, p in folder_mapping.items():
            clean = name.strip("/").strip()
            if not clean:
                continue
            self.shares[clean] = os.path.abspath(p)
            self.name_map[clean.lower()] = clean
            self.name_map[urllib.parse.unquote(clean).lower()] = clean

    def resolve_share(self, segment):
        seg = segment.strip("/")
        if seg in self.shares:
            return seg
        return self.name_map.get(seg.lower()) or self.name_map.get(urllib.parse.unquote(seg).lower())

    def _loc_to_file_path(self, path, environ=None):
        clean_path = path.strip("/")
        if not clean_path:
            return ""
        parts = clean_path.split("/", 1)
        share_key = self.resolve_share(parts[0])
        if not share_key:
            raise DAVError(HTTP_FORBIDDEN, f"Share not found: {parts[0]!r}")
        base_dir = self.shares[share_key]
        if len(parts) == 1:
            return base_dir
        unquoted_rel = urllib.parse.unquote(parts[1]).replace("/", os.sep)
        file_path = os.path.normpath(os.path.join(base_dir, unquoted_rel))
        try:
            is_inside = (os.path.commonpath([os.path.normcase(base_dir), os.path.normcase(file_path)]) == os.path.normcase(base_dir))
        except ValueError:
            is_inside = False
        if not is_inside:
            raise DAVError(HTTP_FORBIDDEN, f"Access outside share is not allowed: {file_path!r}")
        return file_path

    def get_resource_inst(self, path, environ):
        self._count_get_resource_inst += 1
        clean_path = path.strip("/")
        if not clean_path:
            class RootCol(DAVCollection):
                def __init__(self, p, env, prov):
                    super().__init__(p, env)
                    self.prov = prov

                def get_member_names(self):
                    return [k for k, p in self.prov.shares.items() if os.path.exists(p)]

                def get_member(self, name):
                    return self.prov.get_resource_inst("/" + name, self.environ)

                def get_member_list(self):
                    members = []
                    for name in self.get_member_names():
                        m = self.get_member(name)
                        if m is not None:
                            members.append(m)
                    return members

                def get_display_name(self):
                    return "WebDAV Shares"

            return RootCol("/", environ, self)

        parts = clean_path.split("/", 1)
        share_key = self.resolve_share(parts[0])
        if not share_key:
            return None

        base_dir = self.shares[share_key]
        if not os.path.exists(base_dir):
            return None

        if len(parts) == 1:
            res = FolderResource("/" + share_key, environ, base_dir)
            res.name = share_key
            return res

        file_path = self._loc_to_file_path(path, environ)
        if not os.path.exists(file_path):
            return None

        unquoted_sub = urllib.parse.unquote(parts[1]).replace(os.sep, "/")
        dav_path = "/" + share_key + "/" + unquoted_sub
        if os.path.isdir(file_path):
            return FolderResource(dav_path, environ, file_path)
        return FileResource(dav_path, environ, file_path)


# ==============================================================================
# 미디어 스트리밍 MIME 및 확장자 정의
# ==============================================================================
MEDIA_MIMETYPES = {
    # 동영상 (Video)
    ".mp4": "video/mp4",
    ".m4v": "video/mp4",
    ".mkv": "video/x-matroska",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    ".wmv": "video/x-ms-wmv",
    ".flv": "video/x-flv",
    ".ts": "video/mp2t",
    ".m2ts": "video/mp2t",
    ".3gp": "video/3gpp",
    ".ogv": "video/ogg",
    # 음원 (Audio)
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".flac": "audio/flac",
    ".aac": "audio/aac",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".opus": "audio/opus",
    ".wma": "audio/x-ms-wma",
    # 자막 및 텍스트 (Subtitles)
    ".vtt": "text/vtt; charset=utf-8",
    ".srt": "text/plain; charset=utf-8",
    ".smi": "text/plain; charset=utf-8",
    ".ass": "text/plain; charset=utf-8",
    ".ssa": "text/plain; charset=utf-8",
    # 이미지 (Image)
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}

VIDEO_EXTENSIONS = {'.mp4', '.m4v', '.mkv', '.webm', '.mov', '.avi', '.wmv', '.flv', '.ts', '.m2ts', '.3gp', '.ogv'}
AUDIO_EXTENSIONS = {'.mp3', '.m4a', '.flac', '.aac', '.wav', '.ogg', '.oga', '.opus', '.wma'}
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'}


# ==============================================================================
# HTTP 웹 파일 탐색 및 스트리밍 핸들러 (RFC 7233 Range 지원)
# ==============================================================================
class MultiFolderHTTPHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    folder_mapping: Dict[str, str] = {}  # { 'virtual_name': 'real_os_path', ... }
    auth_credentials: Optional[Tuple[str, str]] = None  # (username, password) or None
    serve_index_html: bool = True  # True이면 index.html 존재 시 웹페이지 서빙, False이면 파일 목록 표시
    server_title: str = "🌐 HTTP 파일 서버"

    def log_message(self, format, *args):
        # 표준 출력 로그 노이즈 최소화
        pass

    def check_auth(self):
        if not self.auth_credentials:
            return True
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
        try:
            auth_type, encoded = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False
            decoded = base64.b64decode(encoded).decode('utf-8')
            u, p = decoded.split(':', 1)
            return (u, p) == self.auth_credentials
        except Exception:
            return False

    def require_auth(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="HTTP File Server"')
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        html_msg = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>인증 필요</title></head>"
            "<body style='font-family:sans-serif; text-align:center; padding:50px;'>"
            "<h2>🔒 인증이 필요합니다.</h2><p>아이디와 비밀번호를 입력해주세요.</p></body></html>"
        )
        try:
            self.wfile.write(html_msg.encode('utf-8'))
        except Exception:
            pass

    def do_HEAD(self):
        self._handle_request(is_head=True)

    def do_GET(self):
        self._handle_request(is_head=False)

    def _handle_request(self, is_head: bool = False):
        if not self.check_auth():
            self.require_auth()
            return

        url_path = urllib.parse.unquote(self.path.split('?')[0])
        clean_path = url_path.strip('/')

        # 1. 단일 폴더이면서 virtual name이 없는 경우 (또는 1개 폴더 직결)
        if len(self.folder_mapping) == 1 and "" in self.folder_mapping:
            real_base = self.folder_mapping[""]
            self.serve_single_folder_path(real_base, clean_path, url_path, is_head=is_head)
            return

        # 2. 다중 폴더 가상 루트
        if not clean_path:
            self.render_virtual_root(is_head=is_head)
            return

        parts = clean_path.split('/')
        vname = parts[0]
        if vname in self.folder_mapping:
            real_base = self.folder_mapping[vname]
            rel_parts = parts[1:]
            real_target = os.path.normpath(os.path.join(real_base, *rel_parts))

            if os.path.isdir(real_target):
                if not url_path.endswith('/'):
                    self.send_response(301)
                    self.send_header('Location', url_path + '/')
                    self.end_headers()
                    return

                # index.html 파일이 있고 serve_index_html이 켜진 경우에만 직접 서빙
                if self.serve_index_html:
                    for index_file in ("index.html", "index.htm"):
                        index_path = os.path.join(real_target, index_file)
                        if os.path.isfile(index_path):
                            self.send_file(index_path, is_head=is_head)
                            return

                self.render_directory(vname, rel_parts, real_target, is_head=is_head)
                return
            elif os.path.isfile(real_target):
                self.send_file(real_target, is_head=is_head)
                return

        self.send_error(404, "File Not Found")

    def serve_single_folder_path(self, real_base, clean_path, url_path, is_head: bool = False):
        real_target = os.path.normpath(os.path.join(real_base, *clean_path.split('/'))) if clean_path else real_base
        if os.path.isdir(real_target):
            if not url_path.endswith('/'):
                self.send_response(301)
                self.send_header('Location', url_path + '/')
                self.end_headers()
                return

            if self.serve_index_html:
                for index_file in ("index.html", "index.htm"):
                    index_path = os.path.join(real_target, index_file)
                    if os.path.isfile(index_path):
                        self.send_file(index_path, is_head=is_head)
                        return

            rel_parts = clean_path.split('/') if clean_path else []
            self.render_directory("", rel_parts, real_target, is_head=is_head)
        elif os.path.isfile(real_target):
            self.send_file(real_target, is_head=is_head)
        else:
            self.send_error(404, "File Not Found")

    def render_virtual_root(self, is_head: bool = False):
        title = html.escape(self.server_title)
        body = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - 공유 폴더 목록</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 40px 20px; background: #0f172a; color: #f8fafc; }}
.container {{ max-width: 850px; margin: 0 auto; }}
.card {{ background: #1e293b; border-radius: 12px; padding: 24px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); border: 1px solid #334155; }}
h1 {{ margin: 0 0 8px 0; color: #38bdf8; font-size: 24px; display: flex; align-items: center; gap: 10px; }}
p.desc {{ margin: 0 0 20px 0; color: #94a3b8; font-size: 14px; }}
.folder-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 16px; margin-top: 16px; }}
.folder-card {{ background: #334155; border-radius: 10px; padding: 16px; text-decoration: none; color: #f8fafc; transition: all 0.2s; border: 1px solid #475569; display: flex; align-items: center; gap: 12px; }}
.folder-card:hover {{ transform: translateY(-3px); background: #475569; border-color: #38bdf8; }}
.folder-icon {{ font-size: 28px; }}
.folder-title {{ font-weight: 600; font-size: 16px; word-break: break-all; }}
</style>
</head>
<body>
<div class="container">
<div class="card">
    <h1>{title}</h1>
    <p class="desc">접근 가능한 공유 폴더 목록입니다. 클릭하여 탐색을 시작하세요.</p>
    <div class="folder-grid">
"""
        for vname in self.folder_mapping:
            escaped_name = html.escape(vname)
            quoted_url = "/" + urllib.parse.quote(vname) + "/"
            body += f"""        <a href="{quoted_url}" class="folder-card">
            <span class="folder-icon">📁</span>
            <span class="folder-title">{escaped_name}</span>
        </a>\n"""

        body += """    </div>
</div>
</div>
</body>
</html>"""
        encoded = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.end_headers()
        if not is_head:
            try:
                self.wfile.write(encoded)
            except Exception:
                pass

    def render_directory(self, vname, rel_parts, real_target, is_head: bool = False):
        try:
            entries = os.listdir(real_target)
        except OSError:
            self.send_error(403, "Permission Denied")
            return

        entries.sort(key=lambda a: (not os.path.isdir(os.path.join(real_target, a)), a.lower()))

        if vname:
            if not rel_parts:
                parent_url = "/"
            else:
                parent_url = "/" + urllib.parse.quote(vname) + "/" + "/".join(urllib.parse.quote(p) for p in rel_parts[:-1])
                if parent_url != "/" and not parent_url.endswith('/'):
                    parent_url += "/"
            curr_display = "/" + vname + ("/" + "/".join(rel_parts) if rel_parts else "")
            curr_url_base = "/" + urllib.parse.quote(vname) + ("/" + "/".join(urllib.parse.quote(p) for p in rel_parts) if rel_parts else "")
        else:
            if not rel_parts:
                parent_url = "/"
            else:
                parent_url = "/" + "/".join(urllib.parse.quote(p) for p in rel_parts[:-1])
                if parent_url != "/" and not parent_url.endswith('/'):
                    parent_url += "/"
            curr_display = "/" + "/".join(rel_parts) if rel_parts else "/"
            curr_url_base = "/" + "/".join(urllib.parse.quote(p) for p in rel_parts) if rel_parts else ""

        if not curr_url_base.endswith('/'):
            curr_url_base += "/"

        has_index = any(e.lower() in ("index.html", "index.htm") for e in entries)
        index_btn_html = ""
        if has_index and not self.serve_index_html:
            target_idx = next(e for e in entries if e.lower() in ("index.html", "index.htm"))
            index_btn_html = f'<a href="{curr_url_base}{urllib.parse.quote(target_idx)}" class="btn" style="margin-left: 6px; border-color: #38bdf8; color: #38bdf8;" target="_blank">🌐 index.html 웹페이지로 열기</a>'

        body = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(curr_display)}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 40px 20px; background: #0f172a; color: #f8fafc; }}
.container {{ max-width: 1000px; margin: 0 auto; }}
.card {{ background: #1e293b; border-radius: 12px; padding: 24px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); border: 1px solid #334155; }}
.header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }}
h2 {{ margin: 0; color: #38bdf8; font-size: 20px; word-break: break-all; }}
.btn {{ text-decoration: none; padding: 6px 12px; background: #334155; color: #f8fafc; border-radius: 6px; font-size: 13px; font-weight: 500; border: 1px solid #475569; transition: all 0.2s; display: inline-flex; align-items: center; gap: 4px; }}
.btn:hover {{ background: #475569; color: #38bdf8; border-color: #38bdf8; }}
.btn-play {{ background: #0284c7; color: #fff; border-color: #38bdf8; font-weight: 600; cursor: pointer; }}
.btn-play:hover {{ background: #0369a1; transform: scale(1.02); }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid #475569; color: #94a3b8; font-size: 14px; }}
td {{ padding: 10px; border-bottom: 1px solid #334155; vertical-align: middle; }}
tr:hover td {{ background: #243248; }}
a.item-link {{ text-decoration: none; color: #f8fafc; font-weight: 500; display: inline-flex; align-items: center; gap: 8px; word-break: break-all; }}
a.item-link:hover {{ color: #38bdf8; }}
.size {{ color: #94a3b8; font-size: 13px; text-align: right; white-space: nowrap; }}
.action {{ text-align: right; white-space: nowrap; }}
.empty {{ text-align: center; color: #64748b; padding: 30px; }}

/* 스트리밍 모달 */
.modal-overlay {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.85); z-index: 9999; justify-content: center; align-items: center; backdrop-filter: blur(4px); }}
.modal-box {{ background: #1e293b; border: 1px solid #475569; border-radius: 12px; max-width: 900px; width: 95%; max-height: 90vh; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }}
.modal-top {{ display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-bottom: 1px solid #334155; background: #0f172a; }}
.modal-top h3 {{ margin: 0; font-size: 16px; color: #38bdf8; word-break: break-all; }}
.modal-close-btn {{ background: transparent; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 0 4px; transition: color 0.2s; }}
.modal-close-btn:hover {{ color: #ef4444; }}
.modal-body {{ padding: 16px; display: flex; justify-content: center; align-items: center; background: #000; }}
.modal-foot {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 18px; border-top: 1px solid #334155; background: #0f172a; flex-wrap: wrap; gap: 8px; }}
.modal-info {{ color: #10b981; font-size: 12px; font-weight: 500; }}
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="header">
    <h2>📁 {html.escape(curr_display)}</h2>
    <div>
        <a href="{parent_url}" class="btn">⬅ 상위 폴더</a>
        <a href="/" class="btn" style="margin-left: 6px;">🏠 홈</a>
        {index_btn_html}
    </div>
</div>
<table>
<thead>
    <tr>
        <th>이름</th>
        <th style="text-align:right; width: 110px;">크기</th>
        <th style="text-align:right; width: 190px;">작업</th>
    </tr>
</thead>
<tbody>
"""
        if not entries:
            body += """<tr><td colspan="3" class="empty">폴더가 비어 있습니다.</td></tr>"""

        for entry in entries:
            entry_path = os.path.join(real_target, entry)
            is_dir = os.path.isdir(entry_path)
            ext = os.path.splitext(entry)[1].lower() if not is_dir else ""

            if is_dir:
                icon = "📁"
            elif ext in VIDEO_EXTENSIONS:
                icon = "🎬"
            elif ext in AUDIO_EXTENSIONS:
                icon = "🎵"
            elif ext in IMAGE_EXTENSIONS:
                icon = "🖼️"
            else:
                icon = "📄"

            entry_url = curr_url_base + urllib.parse.quote(entry) + ("/" if is_dir else "")
            escaped_entry = html.escape(entry)
            js_escaped_name = entry.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')

            size_str = "-"
            actions_html = ""
            if not is_dir:
                try:
                    size_bytes = os.path.getsize(entry_path)
                    size_str = self.format_file_size(size_bytes)
                except OSError:
                    size_str = "알 수 없음"

                if ext in VIDEO_EXTENSIONS:
                    actions_html = f"""<button class="btn btn-play" onclick="openPlayer('{entry_url}', '{js_escaped_name}', 'video')">▶ 재생</button> <a href="{entry_url}" class="btn" download>⬇ 다운로드</a>"""
                elif ext in AUDIO_EXTENSIONS:
                    actions_html = f"""<button class="btn btn-play" onclick="openPlayer('{entry_url}', '{js_escaped_name}', 'audio')">▶ 재생</button> <a href="{entry_url}" class="btn" download>⬇ 다운로드</a>"""
                else:
                    actions_html = f"""<a href="{entry_url}" class="btn" download>⬇ 다운로드</a>"""

            body += f"""    <tr>
        <td>
            <a href="{entry_url}" class="item-link">
                <span>{icon}</span>
                <span>{escaped_entry}</span>
            </a>
        </td>
        <td class="size">{size_str}</td>
        <td class="action">{actions_html}</td>
    </tr>\n"""

        body += """</tbody>
</table>
</div>
</div>

<!-- 동영상/오디오 초고속 인라인 스트리밍 모달 -->
<div id="mediaModal" class="modal-overlay" onclick="if(event.target===this)closePlayer()">
    <div class="modal-box">
        <div class="modal-top">
            <h3 id="modalTitle">미디어 스트리밍</h3>
            <button class="modal-close-btn" onclick="closePlayer()" title="닫기 (ESC)">✕</button>
        </div>
        <div class="modal-body" id="playerWrap"></div>
        <div class="modal-foot">
            <span class="modal-info">⚡ 고속 HTTP Range(206) 즉각 시크(Seek) 스트리밍 활성화됨</span>
            <div>
                <a id="modalDlBtn" href="#" class="btn" download>⬇ 파일 다운로드</a>
                <button class="btn" onclick="closePlayer()" style="margin-left: 6px;">닫기</button>
            </div>
        </div>
    </div>
</div>

<script>
function openPlayer(url, title, type) {
    var modal = document.getElementById('mediaModal');
    var modalTitle = document.getElementById('modalTitle');
    var wrap = document.getElementById('playerWrap');
    var dl = document.getElementById('modalDlBtn');

    modalTitle.textContent = (type === 'video' ? '🎬 ' : '🎵 ') + title;
    dl.href = url;

    if (type === 'video') {
        wrap.innerHTML = '<video id="activeMedia" controls autoplay preload="metadata" style="width:100%; max-height:72vh; outline:none;"><source src="' + url + '">브라우저가 HTML5 비디오 스트리밍을 지원하지 않습니다.</video>';
    } else {
        wrap.innerHTML = '<audio id="activeMedia" controls autoplay preload="metadata" style="width:90%; padding:20px 0;"><source src="' + url + '">브라우저가 HTML5 오디오 스트리밍을 지원하지 않습니다.</audio>';
    }
    modal.style.display = 'flex';
}

function closePlayer() {
    var modal = document.getElementById('mediaModal');
    var wrap = document.getElementById('playerWrap');
    var media = document.getElementById('activeMedia');
    if (media) {
        media.pause();
        media.removeAttribute('src');
        media.load();
    }
    wrap.innerHTML = '';
    modal.style.display = 'none';
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closePlayer();
});
</script>
</body>
</html>"""
        encoded = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.end_headers()
        if not is_head:
            try:
                self.wfile.write(encoded)
            except Exception:
                pass

    def format_file_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}" if unit != 'B' else f"{size_bytes} B"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    @staticmethod
    def parse_byte_range(range_header: str, file_size: int) -> Optional[Tuple[int, int]]:
        """HTTP Range 헤더(bytes=start-end) 파싱 헬퍼 (RFC 7233)"""
        if not range_header or not range_header.startswith("bytes="):
            return None
        range_spec = range_header[6:].strip()
        if "," in range_spec:
            range_spec = range_spec.split(",")[0].strip()
        parts = range_spec.split("-")
        if len(parts) != 2:
            return None
        start_str, end_str = parts[0].strip(), parts[1].strip()
        if not start_str and not end_str:
            return None
        try:
            if not start_str:  # suffix byte range: -500 (끝에서 500바이트)
                suffix_len = int(end_str)
                if suffix_len <= 0:
                    return None
                start = max(0, file_size - suffix_len)
                end = file_size - 1
            elif not end_str:  # prefix byte range: 500- (500부터 끝까지)
                start = int(start_str)
                end = file_size - 1
            else:  # full byte range: 500-999
                start = int(start_str)
                end = int(end_str)

            if start > end or start >= file_size or start < 0:
                return None
            end = min(end, file_size - 1)
            return (start, end)
        except ValueError:
            return None

    def get_custom_content_type(self, file_path: str) -> str:
        """미디어 스트리밍 최적화 Content-Type 결정"""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in MEDIA_MIMETYPES:
            return MEDIA_MIMETYPES[ext]
        ctype = self.guess_type(file_path)
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        return ctype

    def send_file(self, file_path: str, is_head: bool = False):
        """HTTP Range (206 Partial Content) 및 대용량 스트리밍 최적 파일 전송"""
        try:
            file_size = os.path.getsize(file_path)
            f = open(file_path, 'rb')
        except OSError:
            self.send_error(404, "File Not Found")
            return

        try:
            ctype = self.get_custom_content_type(file_path)
            fn = os.path.basename(file_path)
            encoded_fn = urllib.parse.quote(fn)

            range_header = self.headers.get("Range")
            byte_range = None
            if range_header:
                byte_range = self.parse_byte_range(range_header, file_size)
                if byte_range is None and range_header.startswith("bytes="):
                    # 범위를 벗어난 잘못된 Range 요청 (416 Range Not Satisfiable)
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

            if byte_range is not None:
                start, end = byte_range
                content_length = end - start + 1
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                self.send_header("Content-Length", str(content_length))
            else:
                start = 0
                end = file_size - 1
                content_length = file_size
                self.send_response(200)
                self.send_header("Content-Length", str(content_length))

            self.send_header("Content-Type", ctype)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Last-Modified", self.date_time_string(os.path.getmtime(file_path)))
            self.send_header("Content-Disposition", f"inline; filename*=UTF-8''{encoded_fn}")
            # CORS 헤더 (웹 플레이어, 외부 기기, 모바일 앱 연동 지원)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Range, Authorization, Content-Type")
            self.send_header("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()

            if is_head:
                return

            if start > 0:
                f.seek(start)

            # 초고속 스트리밍 버퍼 복사 (128KB 단위)
            chunk_size = 131072
            bytes_left = content_length
            while bytes_left > 0:
                to_read = min(chunk_size, bytes_left)
                data = f.read(to_read)
                if not data:
                    break
                try:
                    self.wfile.write(data)
                    bytes_left -= len(data)
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, socket.error):
                    # 플레이어가 시크(Seek)하거나 닫은 경우 소켓 즉시 종료하여 스레드 반환
                    break
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, socket.error):
            pass
        except Exception:
            pass
        finally:
            f.close()


class FTPWebHandler(MultiFolderHTTPHandler):
    """웹 브라우저(Chrome/Edge 등)에서 FTP 공유 폴더를 열 수 있도록 서빙하는 웹 핸들러"""
    folder_mapping: Dict[str, str] = {}
    auth_credentials: Optional[Tuple[str, str]] = None
    serve_index_html: bool = False  # FTP는 파일 탐색/전송이 목적이므로 index.html이 있어도 파일 목록을 기본 표시
    server_title: str = "📡 FTP 웹 브라우저 뷰어"


# ==============================================================================
# 메인 통합 파일 서버 GUI 클래스
# ==============================================================================
class MultiServerGUI:
    def __init__(self, root, start_in_tray=False):
        self.root = root
        self.root.title("통합 파일 서버 관리자 (WebDAV / HTTP / FTP)")
        self.root.geometry("640x870")
        self.root.minsize(580, 750)

        # 윈도우 및 작업표시줄 아이콘 적용
        icon_path = os.path.join(BASE_DIR, "app_icon.ico")
        mei_pass = getattr(sys, "_MEIPASS", None)
        if not os.path.exists(icon_path) and mei_pass:
            icon_path = os.path.join(mei_pass, "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 공통 캐시된 외부 IP
        self.cached_public_ip = None
        self.ip_fetching_thread = None

        # 각 서버 스레드 및 객체
        self.webdav_server = None
        self.webdav_thread = None
        self.webdav_running = False

        self.http_server = None
        self.http_thread = None
        self.http_running = False

        self.ftp_server = None
        self.ftp_thread = None
        self.ftp_web_server = None
        self.ftp_web_thread = None
        self.ftp_running = False

        self.tray_icon = None
        self.shown_tray_notice = False

        # SSL/TLS 사용자 지정 인증서 경로 변수
        self.custom_ssl_cert_var = tk.StringVar(value="")
        self.custom_ssl_key_var = tk.StringVar(value="")

        # 폴더 목록 리스트박스 위젯 참조
        self.webdav_listbox: tk.Listbox = None  # type: ignore
        self.http_listbox: tk.Listbox = None  # type: ignore
        self.ftp_listbox: tk.Listbox = None  # type: ignore

        self.create_widgets()
        self.load_config()

        # SSL 상태 조회 및 표시는 메인 창 렌더링 완료 후 지연 실행 (초기 기동 속도 최적화)
        self.root.after(50, self.update_ssl_status_display)

        if start_in_tray:
            self.root.withdraw()
            self.setup_tray_icon()
        else:
            # 트레이 아이콘은 창이 먼저 뜬 후 백그라운드로 등록하여 첫 창 표시 지연 제거
            self.root.after(100, self.setup_tray_icon)

        # 백그라운드에서 IP 사전 조회
        self.start_ip_refresh()

        # 자동 실행 체크
        self.root.after(800, self.check_auto_starts)

    def get_effective_ssl_files(self):
        """설정된 사용자 지정 인증서가 있으면 사용하고, 없으면 기본 자체 서명 인증서 반환(필요시 자동 생성)"""
        c = self.custom_ssl_cert_var.get().strip()
        k = self.custom_ssl_key_var.get().strip()
        lan_ip = self.get_lan_ip()
        san_ips = [lan_ip] if lan_ip != "127.0.0.1" else []
        if c and k and os.path.exists(c) and os.path.exists(k):
            return c, k
        return ensure_ssl_files(DEFAULT_CERT_FILE, DEFAULT_KEY_FILE, san_ips=san_ips)

    def check_auto_starts(self):
        """설정에 따라 각 서버 자동 구동"""
        if self.webdav_autostart_var.get() and self.webdav_folders:
            self.start_webdav()
        if self.http_autostart_var.get() and self.http_folders:
            self.start_http()
        if self.ftp_autostart_var.get() and self.ftp_folders:
            self.start_ftp()

    # --------------------------------------------------------------------------
    # IP 조회 유틸리티
    # --------------------------------------------------------------------------
    def get_lan_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def fetch_public_ip(self):
        if self.cached_public_ip:
            return self.cached_public_ip
        try:
            req = urllib.request.Request("https://api.ipify.org", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                ip = response.read().decode('utf-8').strip()
                self.cached_public_ip = ip
                return ip
        except Exception:
            return "확인 불가"

    def start_ip_refresh(self):
        def _fetch():
            ip = self.fetch_public_ip()
            try:
                self.root.after(0, self.update_all_public_urls, ip)
            except Exception:
                pass
        threading.Thread(target=_fetch, daemon=True).start()

    def update_all_public_urls(self, public_ip):
        # WebDAV
        if self.webdav_running:
            p = self.webdav_port_var.get().strip()
            proto = "https" if getattr(self, "webdav_use_ssl_var", None) and self.webdav_use_ssl_var.get() else "http"
            self.webdav_public_url_var.set(f"{proto}://{public_ip}:{p}/" if public_ip != "확인 불가" else "확인 불가")
        # HTTP
        if self.http_running:
            p = self.http_port_var.get().strip()
            proto = "https" if getattr(self, "http_use_ssl_var", None) and self.http_use_ssl_var.get() else "http"
            self.http_public_url_var.set(f"{proto}://{public_ip}:{p}/" if public_ip != "확인 불가" else "확인 불가")
        # FTP
        if self.ftp_running:
            p = self.ftp_port_var.get().strip()
            self.ftp_public_url_var.set(f"ftp://{public_ip}:{p}/" if public_ip != "확인 불가" else "확인 불가")
            try:
                wp = int(p) + 1
                self.ftp_web_public_url_var.set(f"http://{public_ip}:{wp}/" if public_ip != "확인 불가" else "확인 불가")
            except Exception:
                pass

    def copy_clipboard(self, text):
        if text and not text.startswith("IP 확인 중") and text != "-" and text != "확인 불가":
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("복사 완료", f"클립보드에 복사되었습니다:\n{text}")
        elif text == "확인 불가":
            messagebox.showwarning("경고", "IP를 확인할 수 없어 복사할 수 없습니다.")

    # --------------------------------------------------------------------------
    # UI 위젯 생성
    # --------------------------------------------------------------------------
    def create_widgets(self):
        # 탭 노트북 생성
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        # 탭 1: WebDAV
        self.tab_webdav = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_webdav, text=" 📁 WebDAV 서버 ")
        self.create_webdav_tab(self.tab_webdav)

        # 탭 2: HTTP
        self.tab_http = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_http, text=" 🌐 HTTP 파일 서버 ")
        self.create_http_tab(self.tab_http)

        # 탭 3: FTP
        self.tab_ftp = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_ftp, text=" 📡 FTP 서버 ")
        self.create_ftp_tab(self.tab_ftp)

        # 탭 4: 일반 설정
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text=" ⚙ 일반 설정 ")
        self.create_settings_tab(self.tab_settings)

        # 하단 공통 제어 및 전체 상태 표시 영역
        bottom_frame = ttk.LabelFrame(self.root, text="전체 서버 제어 및 통합 상태")
        bottom_frame.pack(fill="x", padx=10, pady=8)

        status_box = ttk.Frame(bottom_frame)
        status_box.pack(fill="x", padx=10, pady=5)

        self.summary_webdav_lbl = ttk.Label(status_box, text="WebDAV: 중지됨", foreground="gray", font=("", 9, "bold"))
        self.summary_webdav_lbl.pack(side="left", padx=10)

        self.summary_http_lbl = ttk.Label(status_box, text="HTTP: 중지됨", foreground="gray", font=("", 9, "bold"))
        self.summary_http_lbl.pack(side="left", padx=10)

        self.summary_ftp_lbl = ttk.Label(status_box, text="FTP: 중지됨", foreground="gray", font=("", 9, "bold"))
        self.summary_ftp_lbl.pack(side="left", padx=10)

        btn_all_frame = ttk.Frame(bottom_frame)
        btn_all_frame.pack(fill="x", padx=10, pady=(0, 8))

        self.start_all_btn = ttk.Button(btn_all_frame, text="🚀 모든 서버 일괄 시작", command=self.start_all_servers)
        self.start_all_btn.pack(side="left", fill="x", expand=True, padx=4)

        self.stop_all_btn = ttk.Button(btn_all_frame, text="⏹ 모든 서버 일괄 중지", command=self.stop_all_servers)
        self.stop_all_btn.pack(side="left", fill="x", expand=True, padx=4)

    # --------------------------------------------------------------------------
    # 폴더 관리 보조 헬퍼
    # --------------------------------------------------------------------------
    def create_folder_section(self, parent, folders_attr, listbox_attr, title="공유할 폴더 목록"):
        frame = ttk.LabelFrame(parent, text=title)
        frame.pack(fill="both", expand=True, padx=10, pady=5)

        # 리스트박스와 스크롤바 컨테이너
        list_container = ttk.Frame(frame)
        list_container.pack(fill="both", expand=True, padx=8, pady=4)

        v_scroll = ttk.Scrollbar(list_container, orient="vertical")
        h_scroll = ttk.Scrollbar(list_container, orient="horizontal")

        listbox = tk.Listbox(
            list_container,
            selectmode=tk.SINGLE,
            height=6,
            yscrollcommand=v_scroll.set,
            xscrollcommand=h_scroll.set,
            activestyle="none"
        )
        v_scroll.config(command=listbox.yview)
        h_scroll.config(command=listbox.xview)

        v_scroll.pack(side="right", fill="y")
        h_scroll.pack(side="bottom", fill="x")
        listbox.pack(side="left", fill="both", expand=True)

        setattr(self, listbox_attr, listbox)

        btn_box = ttk.Frame(frame)
        btn_box.pack(fill="x", padx=8, pady=(0, 6))

        add_btn = ttk.Button(btn_box, text="➕ 폴더 추가", command=lambda: self.add_folder_to_list(folders_attr, listbox))
        add_btn.pack(side="left", padx=(0, 4))

        up_btn = ttk.Button(btn_box, text="▲ 위로", width=6, command=lambda: self.move_folder_up(folders_attr, listbox))
        up_btn.pack(side="left", padx=(0, 2))

        down_btn = ttk.Button(btn_box, text="▼ 아래로", width=6, command=lambda: self.move_folder_down(folders_attr, listbox))
        down_btn.pack(side="left", padx=(0, 4))

        del_btn = ttk.Button(btn_box, text="🗑 선택 삭제", command=lambda: self.remove_folder_from_list(folders_attr, listbox))
        del_btn.pack(side="left", padx=(0, 4))

        open_btn = ttk.Button(btn_box, text="📂 탐색기로 열기", command=lambda: self.open_selected_folder(listbox))
        open_btn.pack(side="left")

        return frame, add_btn, del_btn

    def move_folder_up(self, folders_attr, listbox):
        folders_list = getattr(self, folders_attr)
        sel = listbox.curselection()
        if not sel:
            messagebox.showinfo("알림", "위로 이동할 폴더를 목록에서 선택해주세요.")
            return
        idx = sel[0]
        if idx > 0:
            folders_list[idx - 1], folders_list[idx] = folders_list[idx], folders_list[idx - 1]
            listbox.delete(0, tk.END)
            for f in folders_list:
                listbox.insert(tk.END, f)
            listbox.selection_set(idx - 1)
            listbox.activate(idx - 1)
            self.save_config()

    def move_folder_down(self, folders_attr, listbox):
        folders_list = getattr(self, folders_attr)
        sel = listbox.curselection()
        if not sel:
            messagebox.showinfo("알림", "아래로 이동할 폴더를 목록에서 선택해주세요.")
            return
        idx = sel[0]
        if idx < len(folders_list) - 1:
            folders_list[idx + 1], folders_list[idx] = folders_list[idx], folders_list[idx + 1]
            listbox.delete(0, tk.END)
            for f in folders_list:
                listbox.insert(tk.END, f)
            listbox.selection_set(idx + 1)
            listbox.activate(idx + 1)
            self.save_config()

    def add_folder_to_list(self, folders_attr, listbox):
        folders_list = getattr(self, folders_attr)
        path = filedialog.askdirectory(title="공유할 폴더 선택")
        if path:
            norm = os.path.normpath(path)
            if norm not in folders_list:
                folders_list.append(norm)
                listbox.insert(tk.END, norm)
                self.save_config()
            else:
                messagebox.showwarning("경고", "이미 추가된 폴더입니다.")

    def remove_folder_from_list(self, folders_attr, listbox):
        folders_list = getattr(self, folders_attr)
        sel = listbox.curselection()
        if sel:
            idx = sel[0]
            if 0 <= idx < len(folders_list):
                del folders_list[idx]
            listbox.delete(idx)
            self.save_config()
        else:
            messagebox.showinfo("알림", "삭제할 폴더를 목록에서 선택해주세요.")

    def open_selected_folder(self, listbox):
        sel = listbox.curselection()
        if sel:
            path = listbox.get(sel[0])
            if os.path.exists(path):
                subprocess.Popen(f'explorer "{path}"')
            else:
                messagebox.showerror("오류", "폴더가 존재하지 않습니다.")
        else:
            messagebox.showinfo("알림", "열 폴더를 목록에서 선택해주세요.")

    # --------------------------------------------------------------------------
    # 탭 1: WebDAV 구현
    # --------------------------------------------------------------------------
    def create_webdav_tab(self, parent):
        self.webdav_folders = []
        self.create_folder_section(parent, "webdav_folders", "webdav_listbox", "WebDAV 공유 폴더 목록")

        # 설정
        s_frame = ttk.LabelFrame(parent, text="WebDAV 서버 설정")
        s_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(s_frame, text="포트 번호:").grid(row=0, column=0, padx=8, pady=3, sticky="e")
        self.webdav_port_var = tk.StringVar(value="8080")
        self.webdav_port_entry = ttk.Entry(s_frame, textvariable=self.webdav_port_var, width=15)
        self.webdav_port_entry.grid(row=0, column=1, padx=8, pady=3, sticky="w")

        self.webdav_use_ssl_var = tk.BooleanVar(value=False)
        self.webdav_ssl_chk = ttk.Checkbutton(
            s_frame,
            text="🔒 HTTPS (SSL/TLS 보안 연결) 사용",
            variable=self.webdav_use_ssl_var,
            command=self.on_webdav_ssl_toggle
        )
        self.webdav_ssl_chk.grid(row=0, column=2, padx=12, pady=3, sticky="w")

        ttk.Label(s_frame, text="사용자 이름:").grid(row=1, column=0, padx=8, pady=3, sticky="e")
        self.webdav_user_var = tk.StringVar(value="admin")
        self.webdav_user_entry = ttk.Entry(s_frame, textvariable=self.webdav_user_var, width=18)
        self.webdav_user_entry.grid(row=1, column=1, padx=8, pady=3, sticky="w")

        ttk.Label(s_frame, text="비밀번호:").grid(row=2, column=0, padx=8, pady=3, sticky="e")
        self.webdav_pass_var = tk.StringVar(value="password123!")
        self.webdav_pass_entry = ttk.Entry(s_frame, textvariable=self.webdav_pass_var, show="*", width=18)
        self.webdav_pass_entry.grid(row=2, column=1, padx=8, pady=3, sticky="w")

        # 주소 표시
        url_frame = ttk.LabelFrame(parent, text="WebDAV 접속 주소")
        url_frame.pack(fill="x", padx=10, pady=5)

        self.webdav_local_url_var = tk.StringVar(value="-")
        self.webdav_lan_url_var = tk.StringVar(value="-")
        self.webdav_public_url_var = tk.StringVar(value="-")

        ttk.Label(url_frame, text="로컬:").grid(row=0, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(url_frame, textvariable=self.webdav_local_url_var, state="readonly", width=40).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(url_frame, text="복사", command=lambda: self.copy_clipboard(self.webdav_local_url_var.get())).grid(row=0, column=2, padx=5, pady=2)

        ttk.Label(url_frame, text="내부망:").grid(row=1, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(url_frame, textvariable=self.webdav_lan_url_var, state="readonly", width=40).grid(row=1, column=1, padx=5, pady=2)
        ttk.Button(url_frame, text="복사", command=lambda: self.copy_clipboard(self.webdav_lan_url_var.get())).grid(row=1, column=2, padx=5, pady=2)

        ttk.Label(url_frame, text="외부망:").grid(row=2, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(url_frame, textvariable=self.webdav_public_url_var, state="readonly", width=40).grid(row=2, column=1, padx=5, pady=2)
        ttk.Button(url_frame, text="복사", command=lambda: self.copy_clipboard(self.webdav_public_url_var.get())).grid(row=2, column=2, padx=5, pady=2)

        wd_tip_lbl = ttk.Label(
            parent,
            text="💡 다중 폴더 안내: 여러 폴더 등록 시 루트(/) 접속 시 모든 폴더가 한 화면에 표시되며, 각 폴더별(/[폴더명])로도 개별 접근 가능합니다. (단일 폴더는 루트로 직결)",
            foreground="#64748b",
            font=("", 8),
            wraplength=580,
            justify="left"
        )
        wd_tip_lbl.pack(padx=10, pady=(2, 4), anchor="w")

        # 상태 및 개별 시작/중지
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(fill="x", padx=10, pady=8)

        self.webdav_status_lbl = ttk.Label(ctrl_frame, text="상태: 중지됨", foreground="red", font=("", 10, "bold"))
        self.webdav_status_lbl.pack(side="top", pady=(0, 6))

        btn_box = ttk.Frame(ctrl_frame)
        btn_box.pack(fill="x")
        self.webdav_start_btn = ttk.Button(btn_box, text="WebDAV 시작", command=self.start_webdav)
        self.webdav_start_btn.pack(side="left", fill="x", expand=True, padx=4)

        self.webdav_stop_btn = ttk.Button(btn_box, text="WebDAV 중지", command=self.stop_webdav, state="disabled")
        self.webdav_stop_btn.pack(side="left", fill="x", expand=True, padx=4)

    def on_webdav_ssl_toggle(self):
        use_ssl = self.webdav_use_ssl_var.get()
        cur_port = self.webdav_port_var.get().strip()
        if use_ssl and cur_port == "8080":
            self.webdav_port_var.set("8443")
        elif not use_ssl and cur_port == "8443":
            self.webdav_port_var.set("8080")
        self.save_config()

    def build_webdav_provider_mapping(self, valid_folders=None):
        mapping = {}
        folders = valid_folders if valid_folders is not None else self.webdav_folders
        if not folders:
            return mapping

        # 1개 폴더만 등록된 경우: 해당 폴더를 루트(/) 및 /[폴더명]에 직접 매핑 (단일 폴더 편의성)
        if len(folders) == 1:
            mapping["/"] = folders[0]
            vname = os.path.basename(folders[0]).strip()
            if not vname:
                clean_drive = folders[0].replace(":\\", "").replace(":/", "").replace(":", "").replace("\\", "").replace("/", "")
                vname = f"{clean_drive}_drive" if clean_drive else "root_drive"
            mapping[f"/{vname.lower()}"] = folders[0]
            return mapping

        # 다중 폴더 등록 시: MultiFolderDAVProvider를 루트(/)에 등록하여
        # 루트 접속 시 모든 공유 폴더 목록과 그 내부의 모든 하위 파일/폴더를 완벽 제공
        virtual_shares = {}
        for path in folders:
            folder_name = os.path.basename(path).strip()
            if not folder_name:
                clean_drive = path.replace(":\\", "").replace(":/", "").replace(":", "").replace("\\", "").replace("/", "")
                folder_name = f"{clean_drive}_drive" if clean_drive else "root_drive"

            orig_name = folder_name
            counter = 1
            while folder_name in virtual_shares:
                folder_name = f"{orig_name}_{counter}"
                counter += 1

            virtual_shares[folder_name] = path

        mapping["/"] = MultiFolderDAVProvider(virtual_shares)
        return mapping

    def start_webdav(self):
        if self.webdav_running:
            return
        if not self.webdav_folders:
            messagebox.showerror("오류", "WebDAV에서 공유할 폴더를 하나 이상 추가해주세요.")
            return

        # 실제 존재하는 폴더와 누락/미연결 드라이브 분리 점검
        existing_folders = [f for f in self.webdav_folders if os.path.exists(f)]
        missing_folders = [f for f in self.webdav_folders if not os.path.exists(f)]

        if not existing_folders:
            messagebox.showerror("오류", "지정된 WebDAV 공유 폴더가 시스템에 존재하지 않거나 연결되지 않았습니다.\n경로를 확인해주세요.")
            return

        if missing_folders:
            missing_str = "\n".join(f"• {p}" for p in missing_folders)
            messagebox.showwarning("주의: 일부 폴더 제외", f"다음 폴더는 현재 연결되어 있지 않아 제외하고 서버를 시작합니다:\n{missing_str}")

        try:
            port = int(self.webdav_port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("오류", "WebDAV 포트 번호는 1~65535 사이의 정수여야 합니다.")
            return

        self.save_config()
        u = self.webdav_user_var.get().strip()
        p = self.webdav_pass_var.get().strip()
        provider_mapping = self.build_webdav_provider_mapping(valid_folders=existing_folders)

        config = {
            "host": "0.0.0.0",
            "port": port,
            "provider_mapping": provider_mapping,
            "verbose": 1,
            "hotfixes": {
                "emulate_win32_lastmod": False,
                "re_encode_path_info": True,
                "unquote_path_info": True,
            },
            "cors": {
                "allow_origin": "*",
                "allow_methods": [
                    "GET", "HEAD", "OPTIONS", "PROPFIND", "PUT", "DELETE",
                    "MKCOL", "COPY", "MOVE", "PROPPATCH", "LOCK", "UNLOCK"
                ],
                "allow_headers": [
                    "Range", "Authorization", "Content-Type", "Depth",
                    "If-Modified-Since", "If-None-Match", "Lock-Token", "Timeout"
                ],
                "expose_headers": [
                    "Content-Range", "Content-Length", "Accept-Ranges", "ETag", "Lock-Token"
                ],
                "allow_credentials": True,
            }
        }
        if u and p:
            config["simple_dc"] = {"user_mapping": {"*": {u: {"password": p}}}}
        else:
            config["simple_dc"] = {"user_mapping": {"*": True}}

        use_ssl = self.webdav_use_ssl_var.get()
        protocol = "https" if use_ssl else "http"

        self.webdav_running = True
        self.webdav_port_entry.config(state="disabled")
        self.webdav_ssl_chk.config(state="disabled")
        self.webdav_user_entry.config(state="disabled")
        self.webdav_pass_entry.config(state="disabled")
        self.webdav_start_btn.config(state="disabled")
        self.webdav_stop_btn.config(state="normal")
        status_text = f"상태: 실행 중 ({protocol.upper()} 포트: {port})"
        self.webdav_status_lbl.config(text=status_text, foreground="green")
        self.summary_webdav_lbl.config(text=f"WebDAV: 실행 중 ({protocol.upper()})", foreground="#10B981")

        # 주소 갱신
        lan_ip = self.get_lan_ip()
        self.webdav_local_url_var.set(f"{protocol}://127.0.0.1:{port}/")
        self.webdav_lan_url_var.set(f"{protocol}://{lan_ip}:{port}/")
        pub_ip = self.fetch_public_ip()
        self.webdav_public_url_var.set(f"{protocol}://{pub_ip}:{port}/" if pub_ip != "확인 불가" else "확인 불가")

        self.update_tray_icon()

        def _run():
            try:
                # WsgiDAV 및 Cheroot 지연 로딩 (초기 GUI 기동 속도 극대화)
                from wsgidav.wsgidav_app import WsgiDAVApp
                from cheroot import wsgi
                from cheroot.ssl.builtin import BuiltinSSLAdapter
                import wsgidav.fs_dav_provider as fs_dav_provider
                import wsgidav.request_server as request_server

                # WebDAV 동영상 스트리밍 및 고속 파일 전송을 위한 I/O 버퍼 확장 (기본 8KB -> 256KB)
                setattr(fs_dav_provider, "BUFFER_SIZE", 262144)
                setattr(request_server, "DEFAULT_BLOCK_SIZE", 262144)

                app = WsgiDAVApp(config)

                # 대소문자 혼용 클라이언트(Windows 탐색기, Cyberduck, RaiDrive 등) 및
                # URL 인코딩(%20 등) 공백/특수문자 호환성을 위해 대소문자 키와 URL 인코딩/디코딩 키 모두 매핑 보강
                for k, v in list(app.provider_map.items()):
                    app.provider_map[k.lower()] = v
                    quoted_k = urllib.parse.quote(k)
                    app.provider_map[quoted_k] = v
                    app.provider_map[quoted_k.lower()] = v
                    unquoted_k = urllib.parse.unquote(k)
                    app.provider_map[unquoted_k] = v
                    app.provider_map[unquoted_k.lower()] = v

                # 길이 역순으로 정렬하여 가장 구체적인 마운트 경로가 우선 매칭되도록 보장
                app.sorted_share_list = sorted(
                    list({s.lower() for s in app.provider_map.keys()}),
                    key=len,
                    reverse=True
                )

                # 다중 동시 스트리밍 및 파일 전송 시 병목 방지를 위한 스레드 풀 확장 (numthreads=32)
                self.webdav_server = wsgi.Server(
                    ("0.0.0.0", port),
                    app,
                    numthreads=32,
                    timeout=60,
                    accepted_queue_size=64
                )

                # Cheroot error_log 안전 보호
                def _safe_error_log(msg='', level=20, traceback=False):
                    try:
                        if sys.stderr:
                            sys.stderr.write(f"[Cheroot WebDAV] {msg}\n")
                            sys.stderr.flush()
                    except Exception:
                        pass
                self.webdav_server.error_log = _safe_error_log

                if use_ssl:
                    cert_file, key_file = self.get_effective_ssl_files()
                    self.webdav_server.ssl_adapter = BuiltinSSLAdapter(cert_file, key_file)
                self.webdav_server.start()
            except Exception as e:
                self.root.after(0, messagebox.showerror, "WebDAV 오류", f"서버 실행 실패:\n{e}")
                self.root.after(0, self.stop_webdav)

        self.webdav_thread = threading.Thread(target=_run, daemon=True)
        self.webdav_thread.start()

    def stop_webdav(self):
        if self.webdav_running:
            self.webdav_status_lbl.config(text="상태: 중지 중...", foreground="orange")
            if self.webdav_server:
                try:
                    self.webdav_server.stop()
                except Exception:
                    pass
                self.webdav_server = None
            if self.webdav_thread and self.webdav_thread.is_alive():
                self.webdav_thread.join(timeout=1.0)
            self.webdav_running = False

            self.webdav_port_entry.config(state="normal")
            self.webdav_ssl_chk.config(state="normal")
            self.webdav_user_entry.config(state="normal")
            self.webdav_pass_entry.config(state="normal")
            self.webdav_start_btn.config(state="normal")
            self.webdav_stop_btn.config(state="disabled")
            self.webdav_status_lbl.config(text="상태: 중지됨", foreground="red")
            self.summary_webdav_lbl.config(text="WebDAV: 중지됨", foreground="gray")
            self.webdav_local_url_var.set("-")
            self.webdav_lan_url_var.set("-")
            self.webdav_public_url_var.set("-")
            self.update_tray_icon()

    # --------------------------------------------------------------------------
    # 탭 2: HTTP 파일 서버 구현
    # --------------------------------------------------------------------------
    def create_http_tab(self, parent):
        self.http_folders = []
        self.create_folder_section(parent, "http_folders", "http_listbox", "HTTP 웹 공유 폴더 목록")

        # 설정
        s_frame = ttk.LabelFrame(parent, text="HTTP 서버 설정")
        s_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(s_frame, text="포트 번호:").grid(row=0, column=0, padx=8, pady=3, sticky="e")
        self.http_port_var = tk.StringVar(value="18000")
        self.http_port_entry = ttk.Entry(s_frame, textvariable=self.http_port_var, width=15)
        self.http_port_entry.grid(row=0, column=1, padx=8, pady=3, sticky="w")

        self.http_use_ssl_var = tk.BooleanVar(value=False)
        self.http_ssl_chk = ttk.Checkbutton(
            s_frame,
            text="🔒 HTTPS (SSL/TLS 보안 연결) 사용",
            variable=self.http_use_ssl_var,
            command=self.on_http_ssl_toggle
        )
        self.http_ssl_chk.grid(row=0, column=2, padx=12, pady=3, sticky="w")

        self.http_use_auth_var = tk.BooleanVar(value=False)
        self.http_auth_chk = ttk.Checkbutton(s_frame, text="접속 시 계정 인증 요구", variable=self.http_use_auth_var)
        self.http_auth_chk.grid(row=1, column=0, columnspan=2, padx=8, pady=3, sticky="w")

        ttk.Label(s_frame, text="사용자 이름:").grid(row=2, column=0, padx=8, pady=3, sticky="e")
        self.http_user_var = tk.StringVar(value="admin")
        self.http_user_entry = ttk.Entry(s_frame, textvariable=self.http_user_var, width=18)
        self.http_user_entry.grid(row=2, column=1, padx=8, pady=3, sticky="w")

        ttk.Label(s_frame, text="비밀번호:").grid(row=3, column=0, padx=8, pady=3, sticky="e")
        self.http_pass_var = tk.StringVar(value="password123!")
        self.http_pass_entry = ttk.Entry(s_frame, textvariable=self.http_pass_var, show="*", width=18)
        self.http_pass_entry.grid(row=3, column=1, padx=8, pady=3, sticky="w")

        # 주소 표시 및 브라우저 열기
        url_frame = ttk.LabelFrame(parent, text="HTTP 접속 주소 (웹 브라우저)")
        url_frame.pack(fill="x", padx=10, pady=5)

        self.http_local_url_var = tk.StringVar(value="-")
        self.http_lan_url_var = tk.StringVar(value="-")
        self.http_public_url_var = tk.StringVar(value="-")

        ttk.Label(url_frame, text="로컬:").grid(row=0, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(url_frame, textvariable=self.http_local_url_var, state="readonly", width=38).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(url_frame, text="복사", command=lambda: self.copy_clipboard(self.http_local_url_var.get())).grid(row=0, column=2, padx=2, pady=2)
        ttk.Button(url_frame, text="열기", command=lambda: self.open_in_browser(self.http_local_url_var.get())).grid(row=0, column=3, padx=2, pady=2)

        ttk.Label(url_frame, text="내부망:").grid(row=1, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(url_frame, textvariable=self.http_lan_url_var, state="readonly", width=38).grid(row=1, column=1, padx=5, pady=2)
        ttk.Button(url_frame, text="복사", command=lambda: self.copy_clipboard(self.http_lan_url_var.get())).grid(row=1, column=2, padx=2, pady=2)
        ttk.Button(url_frame, text="열기", command=lambda: self.open_in_browser(self.http_lan_url_var.get())).grid(row=1, column=3, padx=2, pady=2)

        ttk.Label(url_frame, text="외부망:").grid(row=2, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(url_frame, textvariable=self.http_public_url_var, state="readonly", width=38).grid(row=2, column=1, padx=5, pady=2)
        ttk.Button(url_frame, text="복사", command=lambda: self.copy_clipboard(self.http_public_url_var.get())).grid(row=2, column=2, padx=2, pady=2)
        ttk.Button(url_frame, text="열기", command=lambda: self.open_in_browser(self.http_public_url_var.get())).grid(row=2, column=3, padx=2, pady=2)

        # 제어
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(fill="x", padx=10, pady=8)

        self.http_status_lbl = ttk.Label(ctrl_frame, text="상태: 중지됨", foreground="red", font=("", 10, "bold"))
        self.http_status_lbl.pack(side="top", pady=(0, 6))

        btn_box = ttk.Frame(ctrl_frame)
        btn_box.pack(fill="x")
        self.http_start_btn = ttk.Button(btn_box, text="HTTP 시작", command=self.start_http)
        self.http_start_btn.pack(side="left", fill="x", expand=True, padx=4)

        self.http_stop_btn = ttk.Button(btn_box, text="HTTP 중지", command=self.stop_http, state="disabled")
        self.http_stop_btn.pack(side="left", fill="x", expand=True, padx=4)

    def on_http_ssl_toggle(self):
        use_ssl = self.http_use_ssl_var.get()
        cur_port = self.http_port_var.get().strip()
        if use_ssl and cur_port == "18000":
            self.http_port_var.set("18443")
        elif not use_ssl and cur_port == "18443":
            self.http_port_var.set("18000")
        self.save_config()

    def open_in_browser(self, url):
        if url and (url.startswith("http://") or url.startswith("https://")):
            sep = "&" if "?" in url else "?"
            cache_busting_url = f"{url}{sep}_t={int(time.time())}"
            webbrowser.open(cache_busting_url)
        else:
            messagebox.showwarning("경고", "서버가 구동 중이지 않거나 올바른 주소가 아닙니다.")

    def build_http_folder_mapping(self, valid_folders=None):
        mapping = {}
        folders = valid_folders if valid_folders is not None else self.http_folders
        if not folders:
            return mapping
        if len(folders) == 1:
            mapping[""] = folders[0]
            return mapping

        for path in folders:
            vname = os.path.basename(path)
            if not vname:
                clean_drive = path.replace(":\\", "").replace(":/", "").replace(":", "").replace("\\", "").replace("/", "")
                vname = f"{clean_drive}_drive" if clean_drive else "root_drive"
            orig = vname
            cnt = 1
            while vname in mapping:
                vname = f"{orig}_{cnt}"
                cnt += 1
            mapping[vname] = path
        return mapping

    def start_http(self):
        if self.http_running:
            return
        if not self.http_folders:
            messagebox.showerror("오류", "HTTP에서 공유할 폴더를 하나 이상 추가해주세요.")
            return

        # 실제 존재하는 폴더와 미연결 드라이브 분리 점검
        existing_folders = [f for f in self.http_folders if os.path.exists(f)]
        missing_folders = [f for f in self.http_folders if not os.path.exists(f)]

        if not existing_folders:
            messagebox.showerror("오류", "지정된 HTTP 공유 폴더가 시스템에 존재하지 않거나 연결되지 않았습니다.\n경로를 확인해주세요.")
            return

        if missing_folders:
            missing_str = "\n".join(f"• {p}" for p in missing_folders)
            messagebox.showwarning("주의: 일부 폴더 제외", f"다음 폴더는 현재 연결되어 있지 않아 제외하고 서버를 시작합니다:\n{missing_str}")

        try:
            port = int(self.http_port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("오류", "HTTP 포트 번호는 1~65535 사이의 정수여야 합니다.")
            return

        self.save_config()
        mapping = self.build_http_folder_mapping(valid_folders=existing_folders)
        MultiFolderHTTPHandler.folder_mapping = mapping

        if self.http_use_auth_var.get():
            u = self.http_user_var.get().strip()
            p = self.http_pass_var.get().strip()
            MultiFolderHTTPHandler.auth_credentials = (u, p) if (u and p) else None
        else:
            MultiFolderHTTPHandler.auth_credentials = None

        use_ssl = self.http_use_ssl_var.get()
        protocol = "https" if use_ssl else "http"

        self.http_running = True
        self.http_port_entry.config(state="disabled")
        self.http_ssl_chk.config(state="disabled")
        self.http_auth_chk.config(state="disabled")
        self.http_user_entry.config(state="disabled")
        self.http_pass_entry.config(state="disabled")
        self.http_start_btn.config(state="disabled")
        self.http_stop_btn.config(state="normal")
        status_text = f"상태: 실행 중 ({protocol.upper()} 포트: {port})"
        self.http_status_lbl.config(text=status_text, foreground="green")
        self.summary_http_lbl.config(text=f"HTTP: 실행 중 ({protocol.upper()})", foreground="#10B981")

        lan_ip = self.get_lan_ip()
        self.http_local_url_var.set(f"{protocol}://127.0.0.1:{port}/")
        self.http_lan_url_var.set(f"{protocol}://{lan_ip}:{port}/")
        pub_ip = self.fetch_public_ip()
        self.http_public_url_var.set(f"{protocol}://{pub_ip}:{port}/" if pub_ip != "확인 불가" else "확인 불가")

        self.update_tray_icon()

        def _run():
            try:
                self.http_server = ThreadingHTTPServer(("0.0.0.0", port), MultiFolderHTTPHandler)
                self.http_server.daemon_threads = True
                if use_ssl:
                    cert_file, key_file = self.get_effective_ssl_files()
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
                    self.http_server.socket = ctx.wrap_socket(self.http_server.socket, server_side=True)
                self.http_server.serve_forever()
            except Exception as e:
                self.root.after(0, messagebox.showerror, "HTTP 오류", f"서버 실행 실패:\n{e}")
                self.root.after(0, self.stop_http)

        self.http_thread = threading.Thread(target=_run, daemon=True)
        self.http_thread.start()

    def stop_http(self):
        if self.http_running:
            self.http_status_lbl.config(text="상태: 중지 중...", foreground="orange")
            if self.http_server:
                try:
                    self.http_server.shutdown()
                    self.http_server.server_close()
                except Exception:
                    pass
                self.http_server = None
            if self.http_thread and self.http_thread.is_alive():
                self.http_thread.join(timeout=1.0)
            self.http_running = False

            self.http_port_entry.config(state="normal")
            self.http_ssl_chk.config(state="normal")
            self.http_auth_chk.config(state="normal")
            self.http_user_entry.config(state="normal")
            self.http_pass_entry.config(state="normal")
            self.http_start_btn.config(state="normal")
            self.http_stop_btn.config(state="disabled")
            self.http_status_lbl.config(text="상태: 중지됨", foreground="red")
            self.summary_http_lbl.config(text="HTTP: 중지됨", foreground="gray")
            self.http_local_url_var.set("-")
            self.http_lan_url_var.set("-")
            self.http_public_url_var.set("-")
            self.update_tray_icon()

    # --------------------------------------------------------------------------
    # 탭 3: FTP 서버 구현
    # --------------------------------------------------------------------------
    def create_ftp_tab(self, parent):
        self.ftp_folders = []
        self.create_folder_section(parent, "ftp_folders", "ftp_listbox", "FTP 공유 폴더 목록")

        # 설정
        s_frame = ttk.LabelFrame(parent, text="FTP 서버 설정")
        s_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(s_frame, text="포트 번호:").grid(row=0, column=0, padx=8, pady=3, sticky="e")
        self.ftp_port_var = tk.StringVar(value="2121")
        self.ftp_port_entry = ttk.Entry(s_frame, textvariable=self.ftp_port_var, width=15)
        self.ftp_port_entry.grid(row=0, column=1, padx=8, pady=3, sticky="w")

        ttk.Label(s_frame, text="사용자 이름:").grid(row=1, column=0, padx=8, pady=3, sticky="e")
        self.ftp_user_var = tk.StringVar(value="admin")
        self.ftp_user_entry = ttk.Entry(s_frame, textvariable=self.ftp_user_var, width=18)
        self.ftp_user_entry.grid(row=1, column=1, padx=8, pady=3, sticky="w")

        ttk.Label(s_frame, text="비밀번호:").grid(row=2, column=0, padx=8, pady=3, sticky="e")
        self.ftp_pass_var = tk.StringVar(value="password123!")
        self.ftp_pass_entry = ttk.Entry(s_frame, textvariable=self.ftp_pass_var, show="*", width=18)
        self.ftp_pass_entry.grid(row=2, column=1, padx=8, pady=3, sticky="w")

        opts_subframe = ttk.Frame(s_frame)
        opts_subframe.grid(row=3, column=0, columnspan=2, padx=8, pady=3, sticky="w")

        self.ftp_anon_var = tk.BooleanVar(value=False)
        self.ftp_anon_chk = ttk.Checkbutton(opts_subframe, text="익명 접속(anonymous) 허용", variable=self.ftp_anon_var)
        self.ftp_anon_chk.pack(side="left", padx=(0, 10))

        self.ftp_allow_write_var = tk.BooleanVar(value=True)
        self.ftp_write_chk = ttk.Checkbutton(opts_subframe, text="쓰기/수정 권한 허용", variable=self.ftp_allow_write_var)
        self.ftp_write_chk.pack(side="left")

        # 웹 브라우저 접속 주소
        web_url_frame = ttk.LabelFrame(parent, text="🌐 웹 브라우저 접속 주소 (Chrome / Edge / 모바일)")
        web_url_frame.pack(fill="x", padx=10, pady=4)

        self.ftp_web_local_url_var = tk.StringVar(value="-")
        self.ftp_web_lan_url_var = tk.StringVar(value="-")
        self.ftp_web_public_url_var = tk.StringVar(value="-")

        ttk.Label(web_url_frame, text="로컬:").grid(row=0, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(web_url_frame, textvariable=self.ftp_web_local_url_var, state="readonly", width=38).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(web_url_frame, text="복사", command=lambda: self.copy_clipboard(self.ftp_web_local_url_var.get())).grid(row=0, column=2, padx=2, pady=2)
        ttk.Button(web_url_frame, text="열기", command=lambda: self.open_in_browser(self.ftp_web_local_url_var.get())).grid(row=0, column=3, padx=2, pady=2)

        ttk.Label(web_url_frame, text="내부망:").grid(row=1, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(web_url_frame, textvariable=self.ftp_web_lan_url_var, state="readonly", width=38).grid(row=1, column=1, padx=5, pady=2)
        ttk.Button(web_url_frame, text="복사", command=lambda: self.copy_clipboard(self.ftp_web_lan_url_var.get())).grid(row=1, column=2, padx=2, pady=2)
        ttk.Button(web_url_frame, text="열기", command=lambda: self.open_in_browser(self.ftp_web_lan_url_var.get())).grid(row=1, column=3, padx=2, pady=2)

        ttk.Label(web_url_frame, text="외부망:").grid(row=2, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(web_url_frame, textvariable=self.ftp_web_public_url_var, state="readonly", width=38).grid(row=2, column=1, padx=5, pady=2)
        ttk.Button(web_url_frame, text="복사", command=lambda: self.copy_clipboard(self.ftp_web_public_url_var.get())).grid(row=2, column=2, padx=2, pady=2)
        ttk.Button(web_url_frame, text="열기", command=lambda: self.open_in_browser(self.ftp_web_public_url_var.get())).grid(row=2, column=3, padx=2, pady=2)

        # FTP 전용 클라이언트 주소
        ftp_url_frame = ttk.LabelFrame(parent, text="📡 FTP 전용 접속 주소 (파일 탐색기 / 파일질라 / 알FTP)")
        ftp_url_frame.pack(fill="x", padx=10, pady=4)

        self.ftp_local_url_var = tk.StringVar(value="-")
        self.ftp_lan_url_var = tk.StringVar(value="-")
        self.ftp_public_url_var = tk.StringVar(value="-")

        ttk.Label(ftp_url_frame, text="로컬:").grid(row=0, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(ftp_url_frame, textvariable=self.ftp_local_url_var, state="readonly", width=38).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(ftp_url_frame, text="복사", command=lambda: self.copy_clipboard(self.ftp_local_url_var.get())).grid(row=0, column=2, padx=2, pady=2)
        ttk.Button(ftp_url_frame, text="탐색기로 열기", command=self.open_ftp_in_explorer).grid(row=0, column=3, padx=2, pady=2)

        ttk.Label(ftp_url_frame, text="내부망:").grid(row=1, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(ftp_url_frame, textvariable=self.ftp_lan_url_var, state="readonly", width=38).grid(row=1, column=1, padx=5, pady=2)
        ttk.Button(ftp_url_frame, text="복사", command=lambda: self.copy_clipboard(self.ftp_lan_url_var.get())).grid(row=1, column=2, padx=2, pady=2)

        ttk.Label(ftp_url_frame, text="외부망:").grid(row=2, column=0, padx=5, pady=2, sticky="e")
        ttk.Entry(ftp_url_frame, textvariable=self.ftp_public_url_var, state="readonly", width=38).grid(row=2, column=1, padx=5, pady=2)
        ttk.Button(ftp_url_frame, text="복사", command=lambda: self.copy_clipboard(self.ftp_public_url_var.get())).grid(row=2, column=2, padx=2, pady=2)

        tip_lbl = ttk.Label(parent, text="💡 최신 브라우저는 ftp://를 지원하지 않으므로 웹 브라우저 주소(HTTP) 또는 [탐색기로 열기]를 사용하세요.", foreground="#64748b", font=("", 8))
        tip_lbl.pack(padx=10, pady=(2, 4), anchor="w")

        # 제어
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(fill="x", padx=10, pady=8)

        self.ftp_status_lbl = ttk.Label(ctrl_frame, text="상태: 중지됨", foreground="red", font=("", 10, "bold"))
        self.ftp_status_lbl.pack(side="top", pady=(0, 6))

        btn_box = ttk.Frame(ctrl_frame)
        btn_box.pack(fill="x")
        self.ftp_start_btn = ttk.Button(btn_box, text="FTP 시작", command=self.start_ftp)
        self.ftp_start_btn.pack(side="left", fill="x", expand=True, padx=4)

        self.ftp_stop_btn = ttk.Button(btn_box, text="FTP 중지", command=self.stop_ftp, state="disabled")
        self.ftp_stop_btn.pack(side="left", fill="x", expand=True, padx=4)

    def open_ftp_in_explorer(self):
        """Windows 파일 탐색기에서 FTP 주소 바로 열기"""
        if not self.ftp_running:
            messagebox.showwarning("경고", "FTP 서버가 실행 중이지 않습니다.")
            return
        port = self.ftp_port_var.get().strip()
        u = self.ftp_user_var.get().strip()
        p = self.ftp_pass_var.get().strip()
        is_anon = self.ftp_anon_var.get()
        if not is_anon and u and p:
            ftp_url = f"ftp://{urllib.parse.quote(u)}:{urllib.parse.quote(p)}@127.0.0.1:{port}/"
        else:
            ftp_url = f"ftp://127.0.0.1:{port}/"
        try:
            subprocess.Popen(["explorer.exe", ftp_url])
        except Exception as e:
            messagebox.showerror("오류", f"탐색기 실행 실패:\n{e}")

    def build_http_folder_mapping_for_ftp(self, valid_folders=None):
        """FTP 공유 폴더를 웹 브라우저 뷰어(HTTP)에서 표시하기 위한 매핑 생성"""
        mapping = {}
        folders = valid_folders if valid_folders is not None else self.ftp_folders
        if not folders:
            return mapping
        if len(folders) == 1:
            mapping[""] = folders[0]
            return mapping
        for path in folders:
            vname = os.path.basename(path)
            if not vname:
                clean_drive = path.replace(":\\", "").replace(":/", "").replace(":", "").replace("\\", "").replace("/", "")
                vname = f"{clean_drive}_drive" if clean_drive else "root_drive"
            orig = vname
            cnt = 1
            while vname in mapping:
                vname = f"{orig}_{cnt}"
                cnt += 1
            mapping[vname] = path
        return mapping

    def build_ftp_folder_mapping(self, valid_folders=None):
        mapping = {}
        folders = valid_folders if valid_folders is not None else self.ftp_folders
        for path in folders:
            vname = os.path.basename(path)
            if not vname:
                clean_drive = path.replace(":\\", "").replace(":/", "").replace(":", "").replace("\\", "").replace("/", "")
                vname = f"{clean_drive}_drive" if clean_drive else "root_drive"
            orig = vname
            cnt = 1
            while vname in mapping:
                vname = f"{orig}_{cnt}"
                cnt += 1
            mapping[vname] = path
        return mapping

    def start_ftp(self):
        if self.ftp_running:
            return
        if not self.ftp_folders:
            messagebox.showerror("오류", "FTP에서 공유할 폴더를 하나 이상 추가해주세요.")
            return

        # 실제 존재하는 폴더와 미연결 드라이브 분리 점검
        existing_folders = [f for f in self.ftp_folders if os.path.exists(f)]
        missing_folders = [f for f in self.ftp_folders if not os.path.exists(f)]

        if not existing_folders:
            messagebox.showerror("오류", "지정된 FTP 공유 폴더가 시스템에 존재하지 않거나 연결되지 않았습니다.\n경로를 확인해주세요.")
            return

        if missing_folders:
            missing_str = "\n".join(f"• {p}" for p in missing_folders)
            messagebox.showwarning("주의: 일부 폴더 제외", f"다음 폴더는 현재 연결되어 있지 않아 제외하고 서버를 시작합니다:\n{missing_str}")

        try:
            port = int(self.ftp_port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("오류", "FTP 포트 번호는 1~65535 사이의 정수여야 합니다.")
            return

        self.save_config()
        u = self.ftp_user_var.get().strip()
        p = self.ftp_pass_var.get().strip()
        is_anon = self.ftp_anon_var.get()
        allow_write = self.ftp_allow_write_var.get()

        perm = "elradfmwM" if allow_write else "elr"

        # pyftpdlib 모듈 지연 로딩 (초기 GUI 기동 속도 최적화)
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer

        authorizer = DummyAuthorizer()
        
        # 단일 폴더일 때와 다중 폴더일 때 분기
        is_single = (len(existing_folders) == 1)
        if is_single:
            root_dir = existing_folders[0]
            fs_class = AbstractedFS
        else:
            root_dir = tempfile.gettempdir()
            MultiFolderFS.folder_mapping = self.build_ftp_folder_mapping(valid_folders=existing_folders)
            fs_class = MultiFolderFS

        if u and p:
            authorizer.add_user(u, p, root_dir, perm=perm)
        if is_anon:
            anon_perm = "elradfmwM" if allow_write else "elr"
            authorizer.add_anonymous(root_dir, perm=anon_perm)

        class CustomHandler(FTPHandler):
            abstracted_fs = fs_class
            passive_ports: Any = None

        pub_ip = self.fetch_public_ip()
        if pub_ip != "확인 불가":
            CustomHandler.masquerade_address = pub_ip
        CustomHandler.passive_ports = range(60000, 60020)
        CustomHandler.authorizer = authorizer
        CustomHandler.encoding = "utf-8"
        CustomHandler.tcp_no_delay = True  # 패킷 대기 없는 즉시 전송 (Nagle 해제)
        CustomHandler.timeout = 300

        # FTP용 웹 뷰어 핸들러 설정
        ftp_web_port = port + 1
        FTPWebHandler.folder_mapping = self.build_http_folder_mapping_for_ftp(valid_folders=existing_folders)
        if not is_anon and u and p:
            FTPWebHandler.auth_credentials = (u, p)
        else:
            FTPWebHandler.auth_credentials = None

        self.ftp_running = True
        self.ftp_port_entry.config(state="disabled")
        self.ftp_user_entry.config(state="disabled")
        self.ftp_pass_entry.config(state="disabled")
        self.ftp_anon_chk.config(state="disabled")
        self.ftp_write_chk.config(state="disabled")
        self.ftp_start_btn.config(state="disabled")
        self.ftp_stop_btn.config(state="normal")
        self.ftp_status_lbl.config(text=f"상태: 실행 중 (FTP: {port}, Web: {ftp_web_port})", foreground="green")
        self.summary_ftp_lbl.config(text="FTP: 실행 중", foreground="#10B981")

        lan_ip = self.get_lan_ip()
        self.ftp_local_url_var.set(f"ftp://127.0.0.1:{port}/")
        self.ftp_lan_url_var.set(f"ftp://{lan_ip}:{port}/")
        self.ftp_web_local_url_var.set(f"http://127.0.0.1:{ftp_web_port}/")
        self.ftp_web_lan_url_var.set(f"http://{lan_ip}:{ftp_web_port}/")

        if pub_ip != "확인 불가":
            self.ftp_public_url_var.set(f"ftp://{pub_ip}:{port}/")
            self.ftp_web_public_url_var.set(f"http://{pub_ip}:{ftp_web_port}/")
        else:
            self.ftp_public_url_var.set("확인 불가")
            self.ftp_web_public_url_var.set("확인 불가")

        self.update_tray_icon()

        # FTP 네이티브 서버 스레드
        def _run_ftp():
            try:
                self.ftp_server = FTPServer(("0.0.0.0", port), CustomHandler)
                self.ftp_server.max_cons = 256
                self.ftp_server.max_cons_per_ip = 20
                self.ftp_server.serve_forever()
            except Exception as e:
                self.root.after(0, messagebox.showerror, "FTP 오류", f"FTP 서버 실행 실패:\n{e}")
                self.root.after(0, self.stop_ftp)

        self.ftp_thread = threading.Thread(target=_run_ftp, daemon=True)
        self.ftp_thread.start()

        # 웹 브라우저용 HTTP 서버 스레드
        def _run_web():
            try:
                self.ftp_web_server = ThreadingHTTPServer(("0.0.0.0", ftp_web_port), FTPWebHandler)
                self.ftp_web_server.daemon_threads = True
                self.ftp_web_server.serve_forever()
            except Exception as e:
                print(f"FTP Web Server error: {e}")

        self.ftp_web_thread = threading.Thread(target=_run_web, daemon=True)
        self.ftp_web_thread.start()

    def stop_ftp(self):
        if self.ftp_running:
            self.ftp_status_lbl.config(text="상태: 중지 중...", foreground="orange")
            if self.ftp_server:
                try:
                    self.ftp_server.close_all()
                except Exception:
                    pass
                self.ftp_server = None
            if self.ftp_thread and self.ftp_thread.is_alive():
                self.ftp_thread.join(timeout=1.0)

            if self.ftp_web_server:
                try:
                    self.ftp_web_server.shutdown()
                    self.ftp_web_server.server_close()
                except Exception:
                    pass
                self.ftp_web_server = None
            if self.ftp_web_thread and self.ftp_web_thread.is_alive():
                self.ftp_web_thread.join(timeout=1.0)

            self.ftp_running = False

            self.ftp_port_entry.config(state="normal")
            self.ftp_user_entry.config(state="normal")
            self.ftp_pass_entry.config(state="normal")
            self.ftp_anon_chk.config(state="normal")
            self.ftp_write_chk.config(state="normal")
            self.ftp_start_btn.config(state="normal")
            self.ftp_stop_btn.config(state="disabled")
            self.ftp_status_lbl.config(text="상태: 중지됨", foreground="red")
            self.summary_ftp_lbl.config(text="FTP: 중지됨", foreground="gray")
            self.ftp_local_url_var.set("-")
            self.ftp_lan_url_var.set("-")
            self.ftp_public_url_var.set("-")
            self.ftp_web_local_url_var.set("-")
            self.ftp_web_lan_url_var.set("-")
            self.ftp_web_public_url_var.set("-")
            self.update_tray_icon()

    # --------------------------------------------------------------------------
    # 탭 4: 일반 설정 구현
    # --------------------------------------------------------------------------
    def create_settings_tab(self, parent):
        sys_frame = ttk.LabelFrame(parent, text="시스템 및 트레이 동작")
        sys_frame.pack(fill="x", padx=10, pady=10)

        self.start_with_windows_var = tk.BooleanVar(value=False)
        self.autostart_chk = ttk.Checkbutton(
            sys_frame,
            text="컴퓨터 시작 시 자동 실행 (Windows 시작프로그램)",
            variable=self.start_with_windows_var,
            command=self.toggle_windows_autostart
        )
        self.autostart_chk.pack(anchor="w", padx=12, pady=6)

        self.minimize_to_tray_var = tk.BooleanVar(value=True)
        self.tray_minimize_chk = ttk.Checkbutton(
            sys_frame,
            text="창 닫기(X) 시 트레이 영역으로 최소화 (백그라운드 유지)",
            variable=self.minimize_to_tray_var,
            command=self.save_config
        )
        self.tray_minimize_chk.pack(anchor="w", padx=12, pady=6)

        auto_frame = ttk.LabelFrame(parent, text="프로그램 시작 시 서버 자동 구동")
        auto_frame.pack(fill="x", padx=10, pady=10)

        self.webdav_autostart_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auto_frame, text="프로그램 시작 시 WebDAV 서버 자동 시작", variable=self.webdav_autostart_var, command=self.save_config).pack(anchor="w", padx=12, pady=5)

        self.http_autostart_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auto_frame, text="프로그램 시작 시 HTTP 파일 서버 자동 시작", variable=self.http_autostart_var, command=self.save_config).pack(anchor="w", padx=12, pady=5)

        self.ftp_autostart_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auto_frame, text="프로그램 시작 시 FTP 서버 자동 시작", variable=self.ftp_autostart_var, command=self.save_config).pack(anchor="w", padx=12, pady=5)

        # 3. SSL/TLS 보안 인증서 설정 (HTTPS)
        ssl_frame = ttk.LabelFrame(parent, text="🔒 SSL/TLS 보안 인증서 관리 (HTTPS)")
        ssl_frame.pack(fill="x", padx=10, pady=10)

        self.ssl_cert_status_lbl = ttk.Label(ssl_frame, text="인증서 상태: 확인 중...", font=("", 9, "bold"))
        self.ssl_cert_status_lbl.pack(anchor="w", padx=12, pady=(6, 4))

        c_frame = ttk.Frame(ssl_frame)
        c_frame.pack(fill="x", padx=8, pady=2)
        ttk.Label(c_frame, text="인증서 파일 (.crt/.pem):", width=22).grid(row=0, column=0, padx=4, pady=2, sticky="e")
        self.custom_cert_entry = ttk.Entry(c_frame, textvariable=self.custom_ssl_cert_var, width=32)
        self.custom_cert_entry.grid(row=0, column=1, padx=4, pady=2, sticky="we")
        ttk.Button(c_frame, text="찾아보기", command=self.browse_custom_cert).grid(row=0, column=2, padx=4, pady=2)

        ttk.Label(c_frame, text="개인키 파일 (.key):", width=22).grid(row=1, column=0, padx=4, pady=2, sticky="e")
        self.custom_key_entry = ttk.Entry(c_frame, textvariable=self.custom_ssl_key_var, width=32)
        self.custom_key_entry.grid(row=1, column=1, padx=4, pady=2, sticky="we")
        ttk.Button(c_frame, text="찾아보기", command=self.browse_custom_key).grid(row=1, column=2, padx=4, pady=2)
        c_frame.columnconfigure(1, weight=1)

        btn_ssl_box = ttk.Frame(ssl_frame)
        btn_ssl_box.pack(fill="x", padx=12, pady=6)
        ttk.Button(btn_ssl_box, text="🔄 자체 서명 인증서 새로 생성/재발급", command=self.regenerate_ssl_cert).pack(side="left", padx=(0, 6))
        ttk.Button(btn_ssl_box, text="기본 인증서로 초기화", command=self.reset_to_default_ssl).pack(side="left")

        help_lbl = ttk.Label(
            ssl_frame,
            text=(
                "💡 HTTPS 안내사항:\n"
                "• 사용자 지정 인증서 경로를 비워두면 2048-bit RSA 자체 서명(Self-Signed) 인증서가 자동 생성되어 적용됩니다.\n"
                "• 자체 서명 인증서 사용 시 웹 브라우저 최초 접속 시 '안전하지 않음' 경고가 표시될 수 있습니다.\n"
                "  웹 브라우저에서 [고급] → [계속 이동]을 클릭하면 암호화된 통신(HTTPS)으로 안전하게 이용할 수 있습니다.\n"
                "• 보유 중인 정식 도메인 인증서(Let's Encrypt 등)가 있다면 위의 파일 경로를 직접 지정할 수 있습니다."
            ),
            foreground="#4B5563",
            font=("", 8),
            justify="left"
        )
        help_lbl.pack(anchor="w", padx=12, pady=(4, 8))

    def update_ssl_status_display(self):
        if not hasattr(self, "ssl_cert_status_lbl"):
            return
        c = self.custom_ssl_cert_var.get().strip()
        k = self.custom_ssl_key_var.get().strip()
        if c and k and os.path.exists(c) and os.path.exists(k):
            info = get_cert_info(c)
            if info and "error" not in info:
                exp = info.get("expiry", "알 수 없음")
                self.ssl_cert_status_lbl.config(
                    text=f"인증서 상태: 사용자 지정 인증서 적용됨 (만료일: {exp})",
                    foreground="green"
                )
            else:
                self.ssl_cert_status_lbl.config(
                    text="인증서 상태: 사용자 지정 인증서 파일 읽기 오류",
                    foreground="red"
                )
        elif os.path.exists(DEFAULT_CERT_FILE):
            info = get_cert_info(DEFAULT_CERT_FILE)
            if info and "error" not in info:
                exp = info.get("expiry", "알 수 없음")
                self.ssl_cert_status_lbl.config(
                    text=f"인증서 상태: 기본 자체 서명 인증서 활성 (만료일: {exp})",
                    foreground="#2563EB"
                )
            else:
                self.ssl_cert_status_lbl.config(
                    text="인증서 상태: 기본 인증서 확인 필요",
                    foreground="orange"
                )
        else:
            self.ssl_cert_status_lbl.config(
                text="인증서 상태: 인증서 미생성 (HTTPS 활성화 시 자동 생성됨)",
                foreground="#4B5563"
            )

    def browse_custom_cert(self):
        f = filedialog.askopenfilename(
            title="SSL 인증서 파일 선택 (.crt, .pem)",
            filetypes=[("인증서 파일", "*.crt *.pem *.cer"), ("모든 파일", "*.*")]
        )
        if f:
            self.custom_ssl_cert_var.set(os.path.normpath(f))
            self.save_config()
            self.update_ssl_status_display()

    def browse_custom_key(self):
        f = filedialog.askopenfilename(
            title="SSL 개인키 파일 선택 (.key, .pem)",
            filetypes=[("개인키 파일", "*.key *.pem"), ("모든 파일", "*.*")]
        )
        if f:
            self.custom_ssl_key_var.set(os.path.normpath(f))
            self.save_config()
            self.update_ssl_status_display()

    def reset_to_default_ssl(self):
        self.custom_ssl_cert_var.set("")
        self.custom_ssl_key_var.set("")
        self.save_config()
        self.update_ssl_status_display()
        messagebox.showinfo("설정 완료", "기본 자체 서명 인증서 경로로 초기화되었습니다.")

    def regenerate_ssl_cert(self):
        if self.webdav_running or self.http_running:
            if not messagebox.askyesno(
                "재발급 확인",
                "현재 서버가 실행 중입니다. 인증서를 재발급하면 다음 서버 시작 시 적용됩니다. 계속하시겠습니까?"
            ):
                return
        try:
            lan_ip = self.get_lan_ip()
            san_ips = [lan_ip] if lan_ip != "127.0.0.1" else []
            generate_self_signed_cert(DEFAULT_CERT_FILE, DEFAULT_KEY_FILE, san_ips=san_ips)
            self.update_ssl_status_display()
            messagebox.showinfo("성공", f"새 자체 서명 인증서가 성공적으로 발급되었습니다.\n저장 위치: {DEFAULT_CERT_FILE}")
        except Exception as e:
            messagebox.showerror("오류", f"인증서 생성 실패:\n{e}")

    # --------------------------------------------------------------------------
    # 전체 서버 일괄 시작 / 중지
    # --------------------------------------------------------------------------
    def start_all_servers(self):
        if not self.webdav_running and self.webdav_folders:
            self.start_webdav()
        if not self.http_running and self.http_folders:
            self.start_http()
        if not self.ftp_running and self.ftp_folders:
            self.start_ftp()

    def stop_all_servers(self):
        if self.webdav_running:
            self.stop_webdav()
        if self.http_running:
            self.stop_http()
        if self.ftp_running:
            self.stop_ftp()

    # --------------------------------------------------------------------------
    # 설정 파일 읽기 / 쓰기
    # --------------------------------------------------------------------------
    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)

                # 기존 레거시 단일 WebDAV config 호환 처리
                legacy_folders = config.get("shared_folders", [])
                self.minimize_to_tray_var.set(config.get("minimize_to_tray", True))

                # 1. WebDAV
                cfg_wd = config.get("webdav", {})
                wd_folders = cfg_wd.get("shared_folders", legacy_folders)
                self.webdav_folders.clear()
                self.webdav_folders.extend(wd_folders)
                self.webdav_listbox.delete(0, tk.END)
                for fld in self.webdav_folders:
                    self.webdav_listbox.insert(tk.END, fld)
                self.webdav_port_var.set(cfg_wd.get("port", config.get("port", "8080")))
                self.webdav_user_var.set(cfg_wd.get("username", config.get("username", "admin")))
                self.webdav_pass_var.set(cfg_wd.get("password", config.get("password", "password123!")))
                self.webdav_autostart_var.set(cfg_wd.get("auto_start", config.get("auto_start_server", False)))
                self.webdav_use_ssl_var.set(cfg_wd.get("use_ssl", False))

                # 2. HTTP
                cfg_http = config.get("http", {})
                http_folders = cfg_http.get("shared_folders", wd_folders if "http" not in config else [])
                self.http_folders.clear()
                self.http_folders.extend(http_folders)
                self.http_listbox.delete(0, tk.END)
                for fld in self.http_folders:
                    self.http_listbox.insert(tk.END, fld)
                self.http_port_var.set(cfg_http.get("port", "18000"))
                self.http_use_auth_var.set(cfg_http.get("use_auth", False))
                self.http_user_var.set(cfg_http.get("username", "admin"))
                self.http_pass_var.set(cfg_http.get("password", "password123!"))
                self.http_autostart_var.set(cfg_http.get("auto_start", False))
                self.http_use_ssl_var.set(cfg_http.get("use_ssl", False))

                # 3. FTP
                cfg_ftp = config.get("ftp", {})
                ftp_folders = cfg_ftp.get("shared_folders", wd_folders if "ftp" not in config else [])
                self.ftp_folders.clear()
                self.ftp_folders.extend(ftp_folders)
                self.ftp_listbox.delete(0, tk.END)
                for fld in self.ftp_folders:
                    self.ftp_listbox.insert(tk.END, fld)
                self.ftp_port_var.set(cfg_ftp.get("port", "2121"))
                self.ftp_user_var.set(cfg_ftp.get("username", "admin"))
                self.ftp_pass_var.set(cfg_ftp.get("password", "password123!"))
                self.ftp_anon_var.set(cfg_ftp.get("anonymous", False))
                self.ftp_allow_write_var.set(cfg_ftp.get("allow_write", True))
                self.ftp_autostart_var.set(cfg_ftp.get("auto_start", False))

                # 4. SSL 설정
                cfg_ssl = config.get("ssl", {})
                self.custom_ssl_cert_var.set(cfg_ssl.get("cert_path", ""))
                self.custom_ssl_key_var.set(cfg_ssl.get("key_path", ""))

            except Exception as e:
                print(f"설정 로드 실패: {e}")

        self.start_with_windows_var.set(self.is_registered_in_startup())

    def save_config(self):
        config = {
            # 레거시 호환을 위해 최상위에도 남겨둠
            "shared_folders": self.webdav_folders,
            "port": self.webdav_port_var.get().strip(),
            "username": self.webdav_user_var.get().strip(),
            "password": self.webdav_pass_var.get().strip(),
            "auto_start_server": self.webdav_autostart_var.get(),
            "minimize_to_tray": self.minimize_to_tray_var.get(),

            "webdav": {
                "shared_folders": self.webdav_folders,
                "port": self.webdav_port_var.get().strip(),
                "username": self.webdav_user_var.get().strip(),
                "password": self.webdav_pass_var.get().strip(),
                "auto_start": self.webdav_autostart_var.get(),
                "use_ssl": self.webdav_use_ssl_var.get()
            },
            "http": {
                "shared_folders": self.http_folders,
                "port": self.http_port_var.get().strip(),
                "use_auth": self.http_use_auth_var.get(),
                "username": self.http_user_var.get().strip(),
                "password": self.http_pass_var.get().strip(),
                "auto_start": self.http_autostart_var.get(),
                "use_ssl": self.http_use_ssl_var.get()
            },
            "ftp": {
                "shared_folders": self.ftp_folders,
                "port": self.ftp_port_var.get().strip(),
                "username": self.ftp_user_var.get().strip(),
                "password": self.ftp_pass_var.get().strip(),
                "anonymous": self.ftp_anon_var.get(),
                "allow_write": self.ftp_allow_write_var.get(),
                "auto_start": self.ftp_autostart_var.get()
            },
            "ssl": {
                "cert_path": self.custom_ssl_cert_var.get().strip(),
                "key_path": self.custom_ssl_key_var.get().strip()
            }
        }
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"설정 저장 실패: {e}")

    # --------------------------------------------------------------------------
    # 윈도우 시작프로그램 레지스트리 관리
    # --------------------------------------------------------------------------
    def is_registered_in_startup(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            winreg.QueryValueEx(key, REG_KEY_NAME)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            # 이전 키 이름으로 등록되어 있는지 체크
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
                winreg.QueryValueEx(key, "WebDAVServerManager")
                winreg.CloseKey(key)
                return True
            except Exception:
                return False
        except Exception:
            return False

    def toggle_windows_autostart(self):
        enable = self.start_with_windows_var.get()
        if getattr(sys, 'frozen', False):
            cmd = f'"{sys.executable}" --tray'
        else:
            script_path = os.path.abspath(__file__)
            python_exe = sys.executable
            pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
            exe_to_use = pythonw_exe if os.path.exists(pythonw_exe) else python_exe
            cmd = f'"{exe_to_use}" "{script_path}" --tray'

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            if enable:
                winreg.SetValueEx(key, REG_KEY_NAME, 0, winreg.REG_SZ, cmd)
                messagebox.showinfo("시작프로그램 등록", "컴퓨터 시작 시 자동 실행되도록 등록되었습니다.")
            else:
                try:
                    winreg.DeleteValue(key, REG_KEY_NAME)
                except FileNotFoundError:
                    pass
                try:
                    winreg.DeleteValue(key, "WebDAVServerManager")
                except FileNotFoundError:
                    pass
                messagebox.showinfo("시작프로그램 해제", "컴퓨터 시작 시 자동 실행이 해제되었습니다.")
            winreg.CloseKey(key)
        except Exception as e:
            messagebox.showerror("오류", f"레지스트리 설정 변경 중 오류:\n{e}")
            self.start_with_windows_var.set(not enable)

    # --------------------------------------------------------------------------
    # 트레이 아이콘 관리
    # --------------------------------------------------------------------------
    def create_tray_image(self):
        width, height = 64, 64
        image = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        any_running = self.webdav_running or self.http_running or self.ftp_running
        bg_color = "#2563EB" if any_running else "#475569"
        outline_color = "#1D4ED8" if any_running else "#334155"

        draw.rounded_rectangle([4, 4, 60, 60], radius=12, fill=bg_color, outline=outline_color, width=2)
        draw.rectangle([16, 18, 48, 26], fill="white")
        draw.rectangle([16, 30, 48, 38], fill="white")
        draw.rectangle([16, 42, 48, 50], fill="white")

        # 각 슬롯별 상태 점 (WebDAV, HTTP, FTP)
        wd_color = "#10B981" if self.webdav_running else "#94A3B8"
        http_color = "#10B981" if self.http_running else "#94A3B8"
        ftp_color = "#10B981" if self.ftp_running else "#94A3B8"

        draw.ellipse([42, 20, 46, 24], fill=wd_color)
        draw.ellipse([42, 32, 46, 36], fill=http_color)
        draw.ellipse([42, 44, 46, 48], fill=ftp_color)
        return image

    def setup_tray_icon(self):
        def on_show_window(icon, item):
            self.show_window()

        def toggle_wd(icon, item):
            self.root.after(0, self.stop_webdav if self.webdav_running else self.start_webdav)

        def toggle_http(icon, item):
            self.root.after(0, self.stop_http if self.http_running else self.start_http)

        def toggle_ftp(icon, item):
            self.root.after(0, self.stop_ftp if self.ftp_running else self.start_ftp)

        def do_start_all(icon, item):
            self.root.after(0, self.start_all_servers)

        def do_stop_all(icon, item):
            self.root.after(0, self.stop_all_servers)

        def on_exit(icon, item):
            self.root.after(0, self.exit_app)

        menu = pystray.Menu(
            pystray.MenuItem("관리자 창 열기", on_show_window, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda item: f"WebDAV 서버: {'중지' if self.webdav_running else '시작'}", toggle_wd),
            pystray.MenuItem(lambda item: f"HTTP 서버: {'중지' if self.http_running else '시작'}", toggle_http),
            pystray.MenuItem(lambda item: f"FTP 서버: {'중지' if self.ftp_running else '시작'}", toggle_ftp),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("모든 서버 시작", do_start_all),
            pystray.MenuItem("모든 서버 중지", do_stop_all),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("프로그램 완전 종료", on_exit)
        )

        image = self.create_tray_image()
        self.tray_icon = pystray.Icon("MultiFileServerManager", image, "통합 파일 서버 관리자", menu=menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def update_tray_icon(self):
        if self.tray_icon:
            self.tray_icon.icon = self.create_tray_image()
            active_list = []
            if self.webdav_running: active_list.append("WebDAV")
            if self.http_running: active_list.append("HTTP")
            if self.ftp_running: active_list.append("FTP")
            status_text = ", ".join(active_list) if active_list else "모두 중지됨"
            self.tray_icon.title = f"통합 파일 서버 관리자 ({status_text})"

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def on_closing(self):
        if self.minimize_to_tray_var.get():
            self.root.withdraw()
            if not self.shown_tray_notice:
                self.shown_tray_notice = True
                if self.tray_icon:
                    try:
                        self.tray_icon.notify(
                            "통합 파일 서버가 시스템 트레이에서 백그라운드로 계속 실행 중입니다.",
                            "백그라운드 실행 알림"
                        )
                    except Exception:
                        pass
        else:
            self.exit_app()

    def exit_app(self):
        any_running = self.webdav_running or self.http_running or self.ftp_running
        if any_running:
            if not messagebox.askokcancel("프로그램 종료", "실행 중인 서버가 있습니다. 완전히 종료하시겠습니까?"):
                return
            self.stop_all_servers()

        if self.tray_icon:
            self.tray_icon.stop()

        self.root.destroy()
        sys.exit(0)


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("mongchee.multifileservermanager.app")
        except Exception:
            pass

    start_in_tray = "--tray" in sys.argv
    root = tk.Tk()

    # PyInstaller Splash Screen이 실행 중인 경우 닫고 메인 창으로 인계
    try:
        import pyi_splash  # type: ignore
        pyi_splash.close()
    except Exception:
        pass

    app = MultiServerGUI(root, start_in_tray=start_in_tray)
    root.mainloop()