# 🗂️ 통합 파일 서버 관리자 (Multi File Server Manager)
> **WebDAV / HTTP / FTP 통합 파일 서버 GUI 관리 도구 (Windows)**

Python Tkinter 기반으로 제작된 올인원 파일 공유 서버 관리 프로그램입니다.  
복잡한 설정 없이 직관적인 GUI 환경에서 **WebDAV**, **HTTP 웹 파일 서버**, **FTP**를 동시에 또는 개별적으로 손쉽게 구동하고 관리할 수 있습니다.

---

## ✨ 주요 기능

### 1. 📁 WebDAV 서버
- WsgiDAV + Cheroot 고성능 WSGI 엔진 기반
- 복수 공유 폴더 개별 및 통합 마운트 지원
- 사용자 계정 인증(아이디/비밀번호) 및 익명 접속 제어
- **HTTPS (SSL/TLS)** 암호화 통신 지원 (자체 서명 인증서 자동 발급 또는 사용자 인증서 지정)

### 2. 🌐 HTTP 웹 파일 서버
- 웹 브라우저(Chrome, Edge, Safari 등)에서 별도 프로그램 설치 없이 파일 탐색 및 다운로드
- 다중 공유 폴더 가상 마운트 및 깔끔한 웹 탐색 UI
- HTTP 기본 인증(Basic Auth) 지원
- **HTTPS (SSL/TLS)** 보안 연결 옵션 제공

### 3. 📡 FTP 서버
- `pyftpdlib` 기반의 안정적이고 빠른 고속 파일 전송
- 익명(Anonymous) 및 전용 계정 인증
- 읽기 전용 / 쓰기 허용 권한 분리
- 최신 브라우저를 위한 내장 **HTTP 웹 뷰어** 동시 연동

### 4. ⚙️ 편의 기능 & 일반 설정
- **시스템 트레이(Tray) 최소화**: 백그라운드 무중단 실행 및 알림 영역 아이콘 제어
- **Windows 시작 시 자동 실행**: 레지스트리 자동 등록 지원
- **프로그램 시작 시 서버 자동 구동**: PC 부팅 후 무인 서버 운영 가능
- **IP 자동 감지**: 로컬(`127.0.0.1`), 내부망(LAN), 공인 IP 자동 조회 및 클릭 한 번으로 주소 복사
- **SSL/TLS 인증서 관리**: 2048-bit RSA 인증서 자동 생성 및 상태 확인

---

## 🛠️ 요구 사항 및 설치 방법

### 1. Python 패키지 설치
```bash
pip install wsgidav cheroot pyftpdlib cryptography pystray Pillow
```

### 2. 실행
```bash
python webdav_server_gui.py
```

### 3. 단일 실행 파일(.exe) 빌드
PyInstaller를 통해 종속성 없는 독립 실행 파일로 빌드할 수 있습니다.
```bash
pyinstaller WebDAV_Server.spec
```
빌드 완료 후 `dist/WebDAV_Server.exe`가 생성됩니다.

---

## 🔒 HTTPS / SSL 보안 연결 안내
- 자체 서명(Self-Signed) 인증서를 사용할 경우, 웹 브라우저 첫 접속 시 "연결이 비공개로 설정되어 있지 않습니다" 경고가 나타날 수 있습니다.
- 브라우저 화면에서 **`[고급]`** -> **`[접속 주소로 이동(안전하지 않음)]`**을 클릭하면 정상 접속됩니다.
- 또는 자체 도메인이 있는 경우, **Nginx Proxy Manager(NPM)** 또는 역방향 프록시와 연동하여 Let's Encrypt 공인 인증서로 운영할 수 있습니다.

---

## 📄 라이선스
MIT License
