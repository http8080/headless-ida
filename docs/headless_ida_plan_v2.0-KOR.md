# Headless IDA 분석 시스템 기획서 v2.0

---

## 1. 프로젝트 개요

**목표**: IDA Pro GUI 없이, Claude가 bash_tool만으로 IDA Pro 분석 기능을 직접 사용할 수 있는 경량 시스템

**v1.7 → v2.0 핵심 변경**: idat -S 스크립트 방식 → **idalib (Hex-Rays 공식 헤드리스 라이브러리)** 전환

**요구사항**
- IDA Pro **9.1 이상** (9.x 시리즈) — `open_database(args=...)` 파라미터가 9.1에서 추가됨
- Python **3.12 또는 3.13** (IDA가 기대하는 major.minor 일치 필수)
  - ⚠️ Python 3.14: IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14"), 사용 금지
  - IDAPython은 Stable ABI (abi3)로 빌드되나, 실제로는 IDA 번들 Python 버전 일치 권장
- idapro Python 패키지 (IDA 설치에 포함된 whl)
- Hex-Rays 디컴파일러 라이선스 (선택 사항, 없으면 어셈블리 전용 모드)
- Windows 10/11 (주 타겟)

**핵심 원칙**
- GUI 불필요 (idalib로 헤드리스 실행)
- MCP 레이어 없음 (bash_tool 직접 호출)
- IDA가 지원하는 모든 바이너리/아키텍처 지원
- .i64 재사용으로 반복 분석 시간 단축
- Claude 스킬로 사용 가능
- **단일 스레드 모델** — execute_sync, register_timer 불필요

---

## 2. 아키텍처

```
v1.7 (idat -S, 제거됨):
Claude → bash_tool → ida_cli.py → HTTP JSON-RPC → idat.exe 내부 스크립트
  문제점:
  - register_timer 트릭으로 프로세스 유지 (fragile, Hex-Rays 비공식)
  - execute_sync로 메인 스레드 디스패치 (데드락 위험)
  - ThreadingHTTPServer + auto_wait 스레드 안전성 복잡
  - notify_when(NW_TERMIDA) + atexit 이중 방어 필요

v2.0 (idalib, 현재):
Claude → bash_tool → ida_cli.py → HTTP JSON-RPC → ida_server.py (import idapro)
  장점:
  - Python 프로세스가 호스트 → IDA 엔진을 라이브러리로 로드
  - 단일 스레드 HTTPServer → 모든 IDA API가 메인 스레드에서 직접 호출
  - 데드락 불가, execute_sync/register_timer 불필요
  - Hex-Rays 공식 권장 방식
  - idapro.close_database()로 깔끔한 종료
```

**제거된 컴포넌트**

| v1.7 | v2.0 | 이유 |
|------|------|------|
| start_ida.py | 제거 (ida_cli.py에 병합) | idalib는 idat.exe 불필요 |
| params.json | 제거 (커맨드라인 인자) | ida_server.py가 일반 Python 스크립트 |
| execute_sync | 제거 | 단일 스레드, 디스패치 불필요 |
| register_timer | 제거 | Python이 호스트, serve_forever()가 프로세스 유지 |
| ThreadingHTTPServer | HTTPServer (단일 스레드) | idalib 단일 스레드 제약 |
| notify_when(NW_TERMIDA) | 제거 | idapro.close_database() 사용 |

**파일 구조**

```
tools/
├── config.json          ← 전역 설정 (로드 우선순위 1)
├── common.py            ← 공유 모듈 (config, registry, lock, file_md5, auth_token)
├── arch_detect.py       ← 바이너리 헤더 파싱, 아키텍처 감지 (정보 표시용)
├── ida_server.py        ← idalib 기반 HTTP JSON-RPC 서버 (common.py import)
└── ida_cli.py           ← Claude용 유일한 진입점 (common.py import)

%USERPROFILE%\.ida-headless\
├── config.json                ← 전역 설정 (로드 우선순위 2)
├── ida_servers.json           ← 인스턴스 레지스트리 (런타임에 생성)
├── ida_servers.json.lock      ← 레지스트리 lock 파일 (런타임)
├── auth_token                 ← 인증 토큰 (멀티라인: instance_id:port:token)
├── idb\
│   ├── <바이너리>_<md5-8자>.i64
│   └── <바이너리>_<md5-8자>.i64.meta.json
└── logs\
    ├── <instance_id>.log
    └── <instance_id>.log.1 ~ .3
```

---

## 3. 지원 범위

### 3-1. 파일 포맷

| 분류 | 포맷 |
|------|------|
| Windows | PE32, PE64, .NET, DOS MZ, NE, LE/LX |
| Linux/Unix | ELF32, ELF64 |
| macOS/iOS | Mach-O 32/64, FAT 바이너리, dylib, dyld_shared_cache |
| Android | ELF (ARM/ARM64/x86), DEX, APK 네이티브 .so |
| 펌웨어 | Raw 바이너리, Intel HEX, Motorola SREC |
| VM | .pyc, Java .class, .dex |
| 기타 | COFF, OMF, AR 아카이브 |

### 3-2. Hex-Rays 디컴파일러 지원 아키텍처

⚠️ **IDA 9.0+**: 통합 바이너리. `idat64.exe` 제거됨 → `idat.exe` 하나로 32/64비트 모두 처리.
데이터베이스도 `.i64` 단일 포맷 (`.idb`는 레거시, 자동 변환).

| 아키텍처 | 32-bit 플러그인 | 64-bit 플러그인 |
|---------|---------------|----------------|
| x86 | hexrays | hexx64 |
| ARM (Thumb 포함) | hexarm | hexarm64 |
| MIPS | hexmips | hexmips64 |
| PowerPC | hexppc | hexppc64 |
| RISC-V | hexrv | hexrv64 |

⚠️ IDA 9.x 통합 바이너리에서도 디컴파일러 플러그인은 **32/64비트 별도 유지**.
`ida_ida.inf_is_64bit()`로 대상 바이너리의 비트수를 확인 후 적절한 플러그인 로드 필수.

플러그인 로드 정석 (IDA 9.x):
```python
import ida_ida, ida_loader, ida_hexrays

# proc_name → (32bit_plugin, 64bit_plugin)
# proc_name은 ida_ida.inf_get_procname()으로 획득
# ⚠️ ida_idp.get_ph().id는 IDA 9.3에서 AttributeError 발생 — 사용 금지
_DECOMPILER_MAP = {
    "metapc": ("hexrays", "hexx64"),
    "ARM":    ("hexarm",  "hexarm64"),
    "mips":   ("hexmips", "hexmips64"),
    "PPC":    ("hexppc",  "hexppc64"),
    "RISCV":  ("hexrv",   "hexrv64"),
}

proc_name = ida_ida.inf_get_procname()
is_64 = ida_ida.inf_is_64bit()
entry = _DECOMPILER_MAP.get(proc_name)
plugin_name = entry[1 if is_64 else 0] if entry else None
if plugin_name:
    plg = ida_loader.load_plugin(plugin_name)
    if plg and ida_hexrays.init_hexrays_plugin():
        pass  # decompiler ready
```

### 3-3. 디컴파일 불가 케이스

| 케이스 | 처리 방법 |
|--------|----------|
| DEX / APK Java 코드 | JADX MCP에 위임 |
| .NET PE | 어셈블리 전용, 디컴파일 불가 |
| Raw 펌웨어 (아키텍처 불명) | --arch 수동 지정 필요, 어셈블리 전용 |

---

## 4. Python 환경

### 4-1. 전제 조건

⚠️ **Python 버전 호환성**

IDAPython은 SWIG `-py3-limited-api` (Stable ABI / abi3)로 빌드되어 이론상 Python 3.x 범위에서
버전 독립적이어야 하지만, 실제로는 IDA 번들 Python 버전과 일치시키는 것이 안전함.

```
권장 Python 버전 (IDA 9.3 기준):
  Python 3.12 또는 3.13 (idapyswitch 표시 버전과 일치 필수)

비호환:
  Python 3.14 — IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14")
                Hex-Rays 공식 미지원, 사용 금지

확인 방법:
  idapyswitch.exe 실행 → 기대하는 Python 버전 표시
  해당 버전의 Python이 시스템에 설치되어 있어야 함
  ※ idapyswitch는 런타임 Python DLL 경로만 변경, .pyd recompile 없음

참고:
  IDA 9.0sp1에서 Python 3.13 지원 추가
  idapro-*.whl은 "py3-none-any" (순수 Python)이지만
  IDA 설치의 python/lib-dynload/*.pyd는 네이티브 → 버전 종속
```

### 4-2. idapro 패키지 설치

```bash
# 1. whl 설치 (IDA 설치 디렉토리에 포함)
pip install "<IDA_DIR>/idalib/python/idapro-*.whl"

# 2. IDA 설치 경로 등록 (두 가지 방법 중 택일)
# 방법 A: py-activate-idalib.py 실행
python "<IDA_DIR>/idalib/python/py-activate-idalib.py"

# 방법 B: IDADIR 환경 변수 설정
set IDADIR=C:\Program Files\IDA Professional 9.3
```

### 4-3. 의존 패키지

```
pip install requests psutil idapro-*.whl

idapro   → idalib 헤드리스 라이브러리 Python 바인딩
requests → HTTP 호출 (ida_cli.py)
psutil   → 크로스플랫폼 프로세스 생존 확인 / 강제 종료
```

### 4-4. --check 검증 항목

```
[ ] IDA 설치 디렉토리 존재
[ ] IDA 버전 >= 9.1 (args 파라미터 필요)
[ ] idapro 패키지 설치됨 (pip show idapro)
[ ] idapro import 성공 (python -c "import idapro")
[ ] IDA Python 버전 == 시스템 Python 버전 (major.minor 일치)
[ ] Python 버전 != 3.14 (Known Issue 경고)
[ ] requests 설치됨
[ ] psutil 설치됨
[ ] 필수 디렉토리 존재 (idb, logs)
[ ] idb 디렉토리 쓰기 권한 확인 (tempfile.NamedTemporaryFile로 검증)
[ ] tools/ 디렉토리 경로에 공백 없음

구현:
  python -c "import idapro; v=idapro.get_library_version(); print(f'{v[0]}.{v[1]}.{v[2]}')"
  → idapro import + 버전 확인을 한 번에 수행
  → import 실패 시 에러 메시지로 원인 파악
  → 버전이 9.0이면: "IDA 9.1+ 필요 (open_database args 미지원)" 경고
  → Python 3.14 감지 시: "Python 3.14는 IDA 9.3 Known Issue, 3.12/3.13 사용 권장" 경고
```

---

## 5. 컴포넌트 설계

### 진입점 구조

**Claude는 ida_cli.py만 사용합니다.**

```
ida_cli.py               ← Claude(bash_tool)의 유일한 진입점
  ├── start 명령어      → 내부적으로 subprocess로 ida_server.py 실행
  ├── stop/status/wait   → HTTP RPC 또는 레지스트리 폴링
  └── 분석 명령어       → HTTP RPC 호출

ida_server.py            ← idalib 기반 HTTP 서버 (일반 Python 스크립트)
arch_detect.py           ← ida_cli.py start 내부에서 호출
```

---

### 5-0. config.json

```json
{
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3"
  },
  "paths": {
    "idb_dir":    "%USERPROFILE%/.ida-headless/idb",
    "log_dir":    "%USERPROFILE%/.ida-headless/logs",
    "registry":   "%USERPROFILE%/.ida-headless/ida_servers.json"
  },
  "analysis": {
    "auto_save":             true,
    "wait_timeout":          300,
    "wait_poll_interval":    2,
    "heartbeat_interval":    60,
    "stale_threshold":       300,
    "open_db_timeout":       600,
    "max_instances":         3,
    "request_timeout":       35,
    "request_timeout_batch": 300
  },
  "server": {
    "host":                  "127.0.0.1"
  },
  "output": {
    "max_inline_lines":      200,
    "default_count":         100,
    "max_count":             500,
    "encoding":              "utf-8"
  },
  "security": {
    "exec_enabled": false,
    "auth_token_file": "%USERPROFILE%/.ida-headless/auth_token"
  },
  "log": {
    "max_size_mb": 50,
    "backup_count": 3
  }
}
```

v1.7 대비 제거된 설정:
```
ida.idat                         → idat.exe 불필요 (idalib 사용)
paths.params_dir                 → params.json 불필요 (커맨드라인 인자)
server.timer_interval            → register_timer 불필요
server.execute_sync_timeout      → execute_sync 불필요
server.execute_sync_timeout_batch → execute_sync 불필요
```

v1.7 대비 변경된 설정:
```
analysis.auto_wait_timeout → analysis.open_db_timeout (이름 변경, 동일 역할)
```

로드 우선순위:
```
1. 현재 디렉토리의 config.json
2. %USERPROFILE%\.ida-headless\config.json
3. 기본값으로 폴백 + 경고 출력
```

환경 변수 치환:
```python
%USERPROFILE%  → os.environ["USERPROFILE"]
%TEMP%         → os.environ["TEMP"]
%APPDATA%      → os.environ["APPDATA"]
# 백슬래시 → 슬래시 변환, 최종 os.path.normpath() 적용
```

---

### 5-1. arch_detect.py

역할: 바이너리 헤더 파싱 → 아키텍처 + 파일 포맷 감지 (정보 제공용)

⚠️ **IDA 9.x**: `idat.exe`가 32/64비트를 자동 감지하므로 바이너리 선택 불필요.
arch_detect는 사용자 정보 표시용으로만 사용.
**실제 플러그인 로드는 ida_server.py가 `ida_ida.inf_get_procname()` 기반으로 결정** (arch_detect 결과에 의존하지 않음).
⚠️ `ida_idp.get_ph().id`는 IDA 9.3에서 `AttributeError` 발생 — `ida_ida.inf_get_procname()` 사용 필수.

감지 규칙 (정보 표시용):
```
ELF e_machine + EI_CLASS (오프셋 4: 1=32bit, 2=64bit):
  0x03              → x86     (32bit)
  0x3E              → x86     (64bit)
  0x28              → arm     (32bit)
  0xB7              → arm     (64bit)
  0x08 + EI_CLASS=1 → mips    (32bit)
  0x08 + EI_CLASS=2 → mips    (64bit)
  0x14              → ppc     (32bit)
  0x15              → ppc     (64bit)
  0xF3              → riscv   (EI_CLASS로 32/64 구분)

PE Machine:
  0x014C → x86     (32bit)
  0x8664 → x86     (64bit)
  0x01C0 → arm     (32bit)   (IMAGE_FILE_MACHINE_ARM)
  0x01C4 → arm     (32bit)   (IMAGE_FILE_MACHINE_ARMNT, Thumb-2)
  0xAA64 → arm     (64bit)

Mach-O cputype (매직: 0xFEEDFACE/0xFEEDFACF, FAT: 0xCAFEBABE):
  0x00000007 (CPU_TYPE_X86)       → x86  (32bit)
  0x01000007 (CPU_TYPE_X86_64)    → x86  (64bit)
  0x0000000C (CPU_TYPE_ARM)       → arm  (32bit)
  0x0100000C (CPU_TYPE_ARM64)     → arm  (64bit)
  0x00000012 (CPU_TYPE_POWERPC)   → ppc  (32bit)
  0x01000012 (CPU_TYPE_POWERPC64) → ppc  (64bit)

  FAT 바이너리 매직 (4가지):
    0xCAFEBABE (FAT_MAGIC)    — 빅엔디안 FAT
    0xBEBAFECA (FAT_CIGAM)    — 리틀엔디안 호스트에서 읽은 FAT
    0xCAFEBABF (FAT_MAGIC_64) — 64비트 FAT
    0xBFBAFECA (FAT_CIGAM_64) — 리틀엔디안 호스트에서 읽은 64비트 FAT
  → 슬라이스 목록 출력 → --arch 수동 선택 요구
  주의: 0xCAFEBABE는 Java .class 매직과 동일. 후속 바이트로 구분.

감지 실패 → --arch 수동 지정으로 폴백
```

출력:
```json
{
  "arch": "arm",
  "bits": 64,
  "file_format": "ELF"
}
```

---

### 5-2. ida_server.py

환경: 시스템 Python + idapro 패키지

```python
SERVER_VERSION = "2.0"
```

#### 핵심 변경 (v1.7 → v2.0)

| v1.7 (idat -S 내부 스크립트) | v2.0 (독립 Python 스크립트) |
|-----|-----|
| idat.exe 프로세스 내부에서 실행 | **일반 Python 프로세스로 실행** |
| idc.ARGV로 파라미터 수신 | **argparse로 인자 수신** |
| auto_wait() 메인 스레드 + HTTP 백그라운드 | **open_database() 블로킹 → HTTP 시작** |
| execute_sync로 IDA API 디스패치 | **메인 스레드에서 직접 호출** |
| register_timer로 프로세스 유지 | **serve_forever()가 프로세스 유지** |
| ThreadingHTTPServer (멀티 스레드) | **HTTPServer (단일 스레드)** |
| notify_when + atexit 이중 방어 | **idapro.close_database() + atexit** |

#### 라이프사이클

```
입력: ida_server.py <바이너리> --id <instance_id> --idb <idb_path>
                     --log <log_path> --config <config_path> [--fresh]
  ↓
1. argparse 인자 파싱
  ↓
2. config.json 로드 + 환경 변수 치환
  ↓
3. 로그 파일 초기화 (RotatingFileHandler)
  ↓
4. 레지스트리 업데이트: state=analyzing, pid=os.getpid(),
   pid_create_time=psutil.Process(os.getpid()).create_time()    [lock]
  ↓
5. open_db_timeout 워치독 스레드 시작
  ↓
6. import idapro  ← 반드시 첫 번째 IDA 관련 import
  ↓
7. .i64 존재 여부에 따른 분기:

   [신규 분석: .i64 없음 또는 --fresh]
   result = idapro.open_database(binary_path, True, args=f"-o{idb_prefix}")
   # -o<prefix>: DB 출력 경로를 idb_dir 내로 지정
   # ⚠️ -o는 -c (새 DB 생성)를 imply → 신규 분석 전용
   # ⚠️ args 파라미터는 IDA 9.1에서 추가됨 (9.0에서는 미지원)
   # True: auto analysis 실행 + 완료 대기 (blocking)
   _save_idb_metadata(idb_path, binary_path)

   [.i64 재사용]
   # 바이너리 변경 감지
   stored_md5 = _load_idb_metadata(idb_path).get("binary_md5")
   current_md5 = _file_md5(binary_path)
   if stored_md5 and stored_md5 != current_md5:
       log.warning(f"Binary changed: stored={stored_md5} current={current_md5}")
       # ida_cli.py가 이미 --force 확인 완료 상태로 여기 도달
   result = idapro.open_database(idb_path, True)
   # idb_path(.i64)를 직접 열기 → -o 미사용 (기존 DB이므로)
   # 분석 큐 최소 처리 (수 초)
  ↓
8. open_database 결과 확인
   result != 0 → state=error, log, sys.exit(1)
   result == 0 → 워치독 취소 (_open_db_done.set())
  ↓
9. 디컴파일러 플러그인 로드 (_DECOMPILER_MAP 기반)
  ↓
10. 캐싱 가능 값 수집 (메인 스레드):
    _ida_version_cached = ida_kernwin.get_kernel_version()  # idaapi는 umbrella, 정식 모듈 사용
    _binary_name, _arch_info 등
  ↓
11. save_db() — 초기 분석 결과 저장
  ↓
12. Auth 토큰 생성 + 파일 저장
  ↓
13. HTTP 서버 생성 (port 0 → OS 자동 할당)
  ↓
14. Heartbeat 스레드 시작 (레지스트리 timestamp 갱신만, IDA API 미호출)
  ↓
15. 레지스트리 업데이트: state=ready, port=N    [lock]
  ↓
16. server.serve_forever()  ← 메인 스레드에서 블로킹 (요청 순차 처리)
  ↓
17. (serve_forever 종료 후) 정리:
    idapro.close_database(save=True)
    레지스트리에서 인스턴스 제거
    auth_token 파일에서 해당 라인 제거
    로그 종료
```

⚠️ **핵심 단순화**: open_database()가 반환된 후에야 HTTP 서버가 시작됨.
analyzing 상태에서는 **HTTP 통신 없음** — ida_cli.py는 레지스트리 파일 폴링으로 상태 확인.

#### idalib 단일 스레드 제약

```
idapro/__init__.py 문서:
  "All library functions must be called from the same thread that
   initialized the library. The library is single-threaded, and
   performing database operations from a different thread may result
   in undefined behavior."

→ HTTPServer (단일 스레드) 사용
→ 요청 핸들러가 메인 스레드에서 실행 → IDA API 직접 호출 안전
→ 한 번에 하나의 요청만 처리 (Claude는 순차 호출이므로 문제 없음)
→ Heartbeat 스레드는 레지스트리 파일만 갱신 (IDA API 미호출, 안전)
```

#### open_database 타임아웃

```python
_open_db_timeout = config["analysis"]["open_db_timeout"]  # 기본 600초
_open_db_done = threading.Event()

def _open_db_watchdog():
    """open_database가 지정 시간 내에 완료되지 않으면 강제 종료"""
    if _open_db_done.wait(timeout=_open_db_timeout):
        return  # 정상 완료
    log.error(f"open_database timeout ({_open_db_timeout}s). Forcing exit.")
    _update_state("error")
    os._exit(1)

watchdog = threading.Thread(target=_open_db_watchdog, daemon=True)
watchdog.start()

# open_database 호출
result = idapro.open_database(binary_path, True, args=args_str)
_open_db_done.set()  # 워치독 취소
```

#### HTTP 서버

```python
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler

AUTH_TOKEN = secrets.token_urlsafe(32)

# port 0 → OS가 빈 포트 자동 할당
server = HTTPServer((host, 0), RpcHandler)
port = server.server_address[1]

# 토큰 파일에 저장 (lock 보호)
if not acquire_lock():
    log.error("Could not acquire lock for auth_token write")
    sys.exit(1)
try:
    with open(token_path, 'a') as f:
        f.write(f"{instance_id}:{port}:{AUTH_TOKEN}\n")
finally:
    release_lock()

class RpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Host 헤더 검증 (DNS rebinding 방어)
        host_header = self.headers.get("Host", "")
        allowed = [f"127.0.0.1:{port}", f"localhost:{port}"]
        if host_header not in allowed:
            self._send_json({"error": {"code": "FORBIDDEN_HOST",
                             "message": "Invalid Host header"}, "id": None})
            return

        # 2. 인증 토큰 검증
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {AUTH_TOKEN}":
            self._send_json({"error": {"code": "AUTH_FAILED",
                             "message": "Invalid or missing auth token"}, "id": None})
            return

        # 3. JSON-RPC 파싱 + 디스패치
        #    ⚠️ JSON 파싱도 try/except 내에 포함 — malformed 요청 시 JSON 에러 반환
        req_id = None
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len))
            method = body.get("method")
            params = body.get("params", {})
            req_id = body.get("id", 1)

            # 4. 디스패치 — 메인 스레드에서 직접 실행 (execute_sync 불필요!)
            result = _dispatch(method, params)
            self._send_json({"result": result, "id": req_id})
        except RpcError as e:
            self._send_json({"error": {"code": e.code, "message": e.message,
                             "suggestion": e.suggestion}, "id": req_id})
        except (json.JSONDecodeError, ValueError) as e:
            self._send_json({"error": {"code": "INVALID_PARAMS",
                             "message": f"Malformed request: {e}"}, "id": req_id})
        except Exception as e:
            self._send_json({"error": {"code": "INTERNAL",
                             "message": str(e)}, "id": req_id})

    def _send_json(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass  # 기본 stderr 로깅 비활성화

# 메인 스레드에서 실행 (serve_forever가 프로세스 유지)
server.serve_forever()
```

**v1.7과의 핵심 차이**: `_dispatch(method, params)`가 HTTP 핸들러 내에서 **직접 호출**.
execute_sync, threading.Event, result_box/exc_box 패턴이 전부 불필요.

#### 요청 처리 (_dispatch)

```python
class RpcError(Exception):
    def __init__(self, code, message, suggestion=None):
        self.code, self.message, self.suggestion = code, message, suggestion

def _dispatch(method, params):
    """메인 스레드에서 직접 실행. execute_sync 불필요.
       에러 시 RpcError 발생 → 핸들러가 {"error": ...} 형식으로 응답."""
    if method == "ping":
        return {"ok": True, "state": "ready"}
    if method == "status":
        return _handle_status()
    if method == "stop":
        return _handle_stop()
    if method == "get_functions":
        return _handle_get_functions(params)
    if method == "decompile":
        return _handle_decompile(params)
    # ... 나머지 API ...
    if method == "methods":
        return _handle_methods()
    raise RpcError("UNKNOWN_METHOD", f"Unknown method: {method}")
```

#### stop 처리

```python
def _handle_stop():
    """정상 종료. serve_forever()를 별도 스레드에서 중단."""
    global _keep_running
    _keep_running = False
    save_db()
    # serve_forever()는 메인 스레드에서 블로킹 중
    # shutdown()을 별도 스레드에서 호출해야 데드락 방지
    threading.Thread(target=server.shutdown).start()
    return {"ok": True}
    # ⚠️ 순서: _handle_stop() 반환 → _send_json() 응답 전송 → serve_forever() 루프에서
    #    shutdown 스레드가 _quitting 플래그 설정 → 현재 요청 처리 완료 후 루프 종료
    #    Python socketserver 공식: shutdown()은 serve_forever() 루프가 다음 poll에서 종료하도록 설정
    #    → 현재 요청의 응답 전송은 완료됨 (race condition 안전)
```

serve_forever() 종료 후 메인 스레드에서 정리:
```python
_db_closed = False

server.serve_forever()
# ↓ shutdown()에 의해 여기로 도달
idapro.close_database(save=True)
_db_closed = True
_remove_from_registry(instance_id)
_remove_auth_token(instance_id)
log.info("Server stopped normally")
```

#### 비정상 종료 처리

```python
import atexit

def _cleanup():
    """비정상 종료 시 최소한의 정리. double-close 방어."""
    global _db_closed
    try:
        if not _db_closed:
            idapro.close_database(save=True)
            _db_closed = True
    except:
        pass
    try:
        _remove_from_registry(instance_id)
    except:
        pass
    try:
        _remove_auth_token(instance_id)
    except:
        pass

atexit.register(_cleanup)
```

v1.7 대비 단순화:
- `notify_when(NW_TERMIDA)` 제거 — idalib에서는 불필요
- `_emergency_cleanup` 제거 — `_cleanup` 하나로 통합
- atexit는 **이중 방어** 용도. 정상 종료 시 serve_forever() 후 명시적 close_database() 호출이 우선

⚠️ **atexit 동작 범위**:
| 시나리오 | atexit 실행 | close_database 안전성 |
|----------|------------|---------------------|
| `sys.exit()` / 정상 종료 | 실행됨 | 안전 (main thread) |
| `os._exit()` (워치독) | **미실행** | N/A |
| SIGKILL / TerminateProcess | **미실행** | N/A |

⚠️ **Python 3.12+**: atexit handler 내에서 새 thread 시작 시 `RuntimeError` 발생 가능.
`close_database()`가 내부적으로 thread를 생성하지 않는지 테스트 필요.

워치독 타임아웃 시: `_update_state("error")` 직접 호출 후 `os._exit(1)`.
`os._exit()`는 C extension blocking (open_database 내부) 중 프로세스를 종료할 수 있는 **유일하게 확실한 방법**.

#### 플러그인 로드

```python
import ida_ida, ida_loader, ida_hexrays

_decompiler_available = False

# proc_name → (32bit_plugin, 64bit_plugin)
# ⚠️ ida_idp.get_ph().id는 IDA 9.3에서 AttributeError 발생 — 사용 금지
_DECOMPILER_MAP = {
    "metapc": ("hexrays", "hexx64"),
    "ARM":    ("hexarm",  "hexarm64"),
    "mips":   ("hexmips", "hexmips64"),
    "PPC":    ("hexppc",  "hexppc64"),
    "RISCV":  ("hexrv",   "hexrv64"),
}

proc_name = ida_ida.inf_get_procname()
is_64 = ida_ida.inf_is_64bit()
entry = _DECOMPILER_MAP.get(proc_name)
actual_plugin = entry[1 if is_64 else 0] if entry else None

if actual_plugin:
    plg = ida_loader.load_plugin(actual_plugin)  # PyCapsule | None
    if plg and ida_hexrays.init_hexrays_plugin():
        log.info(f"Decompiler loaded: {actual_plugin} (proc={proc_name}, 64bit={is_64})")
        _decompiler_available = True
    else:
        log.error(f"Decompiler load failed: {actual_plugin}")
        _decompiler_available = False
else:
    log.warning(f"No decompiler for processor '{proc_name}', 64bit={is_64}")
    _decompiler_available = False
    # 어셈블리 전용 모드로 계속
```

#### save_db

```python
import ida_loader

def save_db():
    """ida_loader.save_database() flags 기본값(-1) 타입 불일치 버그 회피.
    flags=0 명시 전달로 워크어라운드."""
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    ret = ida_loader.save_database(idb, 0)
    if ret:
        log.info(f"Database saved: {idb}")
    else:
        log.error(f"Database save failed: {idb}")
    return ret
```

⚠️ `ida_loader.save_database()`는 IDA 9.3에서 flags 기본값(-1) C++/Python 타입 불일치 버그 존재.
`ida_loader.save_database(path, 0)` — flags를 명시적으로 0 전달하여 회피.
⚠️ `idaapi`는 모든 `ida_*` 모듈을 re-export하는 umbrella 모듈. Hex-Rays 권장: originating module 직접 사용 (`ida_loader`, `ida_kernwin` 등).

#### 자동 save_db 트리거

```
open_database 완료 직후
set_name 호출 후
set_comment 호출 후
stop 명령 시 (+ close_database(save=True))
```

#### heartbeat

```python
_keep_running = True

def _heartbeat_loop():
    """레지스트리 timestamp만 갱신. IDA API 미호출 (스레드 안전)."""
    while _keep_running:
        time.sleep(config["analysis"]["heartbeat_interval"])  # 60초
        if not _keep_running:
            break
        _update_heartbeat()

def _update_heartbeat():
    if not acquire_lock():
        return
    try:
        r = _load_registry()
        if instance_id in r:
            r[instance_id]["last_heartbeat"] = time.time()
            _save_registry(r)
    finally:
        release_lock()

heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
heartbeat_thread.start()
```

#### 상태 정의

```
initializing  → ida_cli.py start가 등록, ida_server.py 아직 미실행
analyzing     → open_database 진행 중 (HTTP 서버 미시작)
ready         → 분석 완료, HTTP 서버 실행 중, 모든 API 사용 가능
error         → 분석 실패
```

⚠️ **v1.7과의 차이**: analyzing 상태에서 HTTP 통신 불가.
ida_cli.py는 레지스트리 파일 폴링으로 상태 확인.

#### 로그 시스템

```python
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler(
    log_path,
    maxBytes=config["log"]["max_size_mb"] * 1024 * 1024,
    backupCount=config["log"]["backup_count"],
    encoding='utf-8'
)
handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s',
                                        datefmt='%Y-%m-%d %H:%M:%S'))
log = logging.getLogger(f"ida-headless-{instance_id}")
log.addHandler(handler)
log.setLevel(logging.INFO)
```

#### idb 메타데이터

```python
def _file_md5(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def _save_idb_metadata(idb_path, binary_path):
    meta = {
        "binary_path": binary_path,
        "binary_md5": _file_md5(binary_path),
        "created": time.time()
    }
    with open(idb_path + ".meta.json", 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)

def _load_idb_metadata(idb_path):
    meta_path = idb_path + ".meta.json"
    if os.path.exists(meta_path):
        with open(meta_path, encoding='utf-8') as f:
            return json.load(f)
    return {}
```

#### exec 보안

```
exec_enabled = false (기본값)
비활성화 → EXEC_DISABLED
활성화  → 인증 토큰 + Host 검증 + 127.0.0.1 바인딩 전용, 실행 내용 로깅

⚠️ 보안 주의:
- 단일 스레드이므로 exec 무한 루프/장시간 실행 시 서버 전체 블로킹
- idc.qexit() 실행 시 서버 프로세스 종료됨 → _exec_namespace에서 qexit 제거 검토
- 서버 측 타임아웃 없음 → 클라이언트(ida_cli.py) request_timeout_batch로 간접 보호
```

```python
def _exec_code(code, base_namespace):
    ns = dict(base_namespace)
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        exec(code, ns)
    return stdout_buf.getvalue(), stderr_buf.getvalue()

_exec_namespace = {
    "idc": __import__("idc"),
    "idaapi": __import__("idaapi"),
    "idautils": __import__("idautils"),
    "ida_bytes": __import__("ida_bytes"),
    "ida_funcs": __import__("ida_funcs"),
    "ida_hexrays": __import__("ida_hexrays"),
    "ida_nalt": __import__("ida_nalt"),
    "ida_typeinf": __import__("ida_typeinf"),
    "ida_segment": __import__("ida_segment"),
    "ida_search": __import__("ida_search"),
    "ida_xref": __import__("ida_xref"),
    "ida_name": __import__("ida_name"),
    "ida_ida": __import__("ida_ida"),
    "ida_idp": __import__("ida_idp"),
    "ida_loader": __import__("ida_loader"),
}
```

---

### 5-3. HTTP 통신 프로토콜

#### 요청 형식: 단일 엔드포인트

```
POST /
Content-Type: application/json

{
  "method": "<메서드명>",
  "params": { ... },    ← 파라미터 없으면 생략
  "id": 1
}
```

#### 응답 형식 (공통)

```json
성공: {"result": { ... }, "id": 1}
실패: {"error": {"code": "...", "message": "...", "suggestion": "..."}, "id": 1}
```

#### ping

```json
요청: {"method": "ping", "id": 1}
응답: {"result": {"ok": true, "state": "ready"}, "id": 1}
```

#### status

```json
요청: {"method": "status", "id": 1}
응답:
{
  "result": {
    "state":                "ready",
    "binary":               "libsecurity.so",
    "arch":                 "arm",
    "bits":                 64,
    "idb_path":             "C:/.../.ida-headless/idb/libsecurity_ab12cd34.i64",
    "decompiler_available": true,
    "imagebase":            "0x100000",
    "func_count":           3842,
    "ida_version":          "9.3",
    "server_version":       "2.0",
    "uptime":               147.3,
    "binary_md5":           "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
  },
  "id": 1
}
```

v1.7과의 차이: analyzing/ready 이원화 불필요 — HTTP는 ready 상태에서만 가동.
모든 필드를 execute_sync 없이 메인 스레드에서 직접 수집.

#### stop

```json
요청: {"method": "stop", "id": 1}
응답: {"result": {"ok": true}, "id": 1}
```

#### 목록 API (get_functions / get_strings / get_imports / get_exports / get_segments)

요청 파라미터:

```
offset  int     기본값: 0
count   int     기본값: 100, 최대: 500
filter  string  기본값: null  → 이름에 대한 부분 문자열 매칭
output  string  기본값: null  → 파일 저장 경로
```

응답:

```json
{
  "result": {
    "total": 3842, "offset": 0, "count": 100,
    "data": [ ... ],
    "saved_to": null
  },
  "id": 1
}
```

API별 data 필드:

| API | 필드 |
|-----|------|
| get_functions | addr, name, size |
| get_strings | addr, value, length, encoding |
| get_imports | addr, name, module, ordinal |
| get_exports | addr, name, ordinal |
| get_segments | start_addr, end_addr, name, class, size, perm |

`perm` 값: `"rwx"`, `"r-x"` 등. `ida_segment.SEGPERM_READ`(4), `SEGPERM_WRITE`(2), `SEGPERM_EXEC`(1).

#### addr 입력 형식 (분석 API 공통)

```
16진수 주소:  "0x1234"  또는  "1234"   (0x 접두사 선택)
심볼 이름:    "check_root"            → idc.get_name_ea_simple(name), BADADDR면 INVALID_ADDRESS
```

#### decompile

```json
요청: {"method": "decompile", "params": {"addr": "check_root", "output": null}, "id": 1}
응답:
{
  "result": {
    "addr": "0x1234", "name": "check_root",
    "code": "int __fastcall check_root()\n{\n  ...\n}",
    "saved_to": null
  },
  "id": 1
}
```

플러그인 로드 실패 시: DECOMPILER_NOT_LOADED

#### disasm

```json
요청: {"method": "disasm", "params": {"addr": "0x1234", "count": 20, "output": null}, "id": 1}
count 기본값: 20. 최대: 500.
응답:
{
  "result": {
    "addr": "0x1234", "count": 20,
    "lines": [
      {"addr": "0x1234", "bytes": "2D E9 F0 4F", "insn": "PUSH {R4-R11,LR}"},
      {"addr": "0x1238", "bytes": "00 40 A0 E1", "insn": "MOV R4, R0"}
    ],
    "saved_to": null
  },
  "id": 1
}
```

#### get_xrefs_to / get_xrefs_from

```json
요청: {"method": "get_xrefs_to", "params": {"addr": "0x1234"}, "id": 1}
응답:
{
  "result": {
    "addr": "0x1234", "total": 5,
    "refs": [
      {"from_addr": "0x5678", "from_name": "sub_5678", "type": "call"},
      {"from_addr": "0x9ABC", "from_name": "init_func", "type": "jump"}
    ],
    "saved_to": null
  },
  "id": 1
}
```

type 매핑:

```python
import ida_xref

def _xref_type_str(xtype):
    if xtype in (ida_xref.fl_CF, ida_xref.fl_CN):
        return "call"
    if xtype in (ida_xref.fl_JF, ida_xref.fl_JN):
        return "jump"
    if xtype in (ida_xref.dr_R, ida_xref.dr_W, ida_xref.dr_O,
                 ida_xref.dr_I, ida_xref.dr_T, ida_xref.dr_S):
        return "data"
    return "unknown"
```

get_xrefs_from 응답: `from_addr/from_name` 대신 `to_addr/to_name`.

#### find_func

```json
요청: {"method": "find_func", "params": {"name": "check"}, "id": 1}
응답:
{
  "result": {
    "query": "check", "total": 2,
    "matches": [
      {"addr": "0x1234", "name": "check_root"},
      {"addr": "0x5678", "name": "check_root_bypass"}
    ]
  },
  "id": 1
}
```

기본: 부분 문자열 매칭. `max_results`: 기본 100, 최대 500.
`regex: true` → `re.search(pattern, func_name)`.

#### decompile_batch

```json
요청: {"method": "decompile_batch", "params": {"addrs": ["0x1234", "0x5678", "check_root"]}, "id": 1}
응답:
{
  "result": {
    "total": 3, "success": 2, "failed": 1,
    "functions": [
      {"addr": "0x1234", "name": "sub_1234", "code": "int __fastcall sub_1234()\n{\n  ...\n}"},
      {"addr": "0x5678", "name": "sub_5678", "code": "void __fastcall sub_5678(int a1)\n{\n  ...\n}"},
      {"addr": "0x9ABC", "name": "check_root", "error": "DECOMPILE_FAILED"}
    ],
    "saved_to": null
  },
  "id": 1
}
```

`addrs` 최대 20개. 개별 실패 시에도 나머지 계속 처리.

#### set_name

```json
요청: {"method": "set_name", "params": {"addr": "0x1234", "name": "check_root_real"}, "id": 1}
응답: {"result": {"ok": true, "addr": "0x1234", "name": "check_root_real"}, "id": 1}
```

성공 후 자동 save_db.

#### set_comment

```json
요청: {"method": "set_comment", "params": {"addr": "0x1234", "comment": "root detection core", "repeatable": false, "type": "line"}, "id": 1}
응답: {"result": {"ok": true, "addr": "0x1234"}, "id": 1}
```

파라미터:

- `repeatable`: 기본값 false. true면 반복 주석 (`idc.set_cmt(ea, cmt, 1)`)
- `type`: 기본값 `"line"`. `"func"`이면 함수 주석 (`idc.set_func_cmt(ea, cmt, repeatable)`)

성공 후 자동 save_db.

#### get_func_info

```json
요청: {"method": "get_func_info", "params": {"addr": "check_root"}, "id": 1}
응답:
{
  "result": {
    "addr": "0x1234", "name": "check_root",
    "start_ea": "0x1234", "end_ea": "0x1300",
    "size": 204,
    "is_thunk": false,
    "flags": "0x0",
    "decompiler_available": true,
    "calling_convention": "__fastcall",
    "return_type": "int",
    "args": [{"name": "a1", "type": "int"}]
  },
  "id": 1
}
```

디컴파일러 불가 시 `args: null, calling_convention: null`.

#### get_imagebase

```json
요청: {"method": "get_imagebase", "id": 1}
응답: {"result": {"imagebase": "0x100000"}, "id": 1}
```

#### get_bytes

```json
요청: {"method": "get_bytes", "params": {"addr": "0x1234", "size": 16}, "id": 1}
응답:
{
  "result": {
    "addr": "0x1234", "size": 16,
    "hex": "2D E9 F0 4F 00 40 A0 E1 01 50 A0 E1 04 D0 4D E2",
    "raw_b64": "LenwTwBAoOEBUKDhBNBN4g=="
  },
  "id": 1
}
```

size 최대 4096. 초과 시 INVALID_PARAMS.

#### find_bytes

```json
요청: {"method": "find_bytes", "params": {"pattern": "48 8B ? ? 00", "start": "0x1000", "max_results": 10}, "id": 1}
응답:
{
  "result": {
    "pattern": "48 8B ? ? 00", "total": 3,
    "matches": ["0x1234", "0x5678", "0x9ABC"]
  },
  "id": 1
}
```

`start`: 검색 시작 주소 (기본값: 첫 세그먼트 시작). `max_results` 기본 50, 최대 200.

⚠️ IDA 9.0+: `ida_bytes.find_bytes()` 고수준 API 사용 권장.
`parse_binpat_str` + `bin_search` 조합은 **deprecated** (IDA 9.0 포팅 가이드).
`idc.find_binary`, `ida_search.find_binary`도 IDA 9.0에서 **제거됨**.

```python
# IDA 9.0+ 권장 API (deprecated parse_binpat_str/bin_search 대체)
ea = ida_bytes.find_bytes(pattern, start_ea, range_end=end_ea)
# BADADDR 반환 시 매치 없음. 단일 ea_t 반환 (tuple 아님).
```

#### get_comments

```json
요청: {"method": "get_comments", "params": {"addr": "0x1234"}, "id": 1}
응답:
{
  "result": {
    "addr": "0x1234",
    "comment": "root detection core",
    "repeatable_comment": "called from init_security",
    "func_comment": "Checks for root/jailbreak indicators"
  },
  "id": 1
}
```

#### exec

```json
요청: {"method": "exec", "params": {"code": "print(idc.get_func_name(0x1234))"}, "id": 1}
응답: {"result": {"stdout": "check_root\n", "stderr": "", "saved_to": null}, "id": 1}
```

exec_enabled=false면 EXEC_DISABLED.

#### save_db

```json
요청: {"method": "save_db", "id": 1}
응답: {"result": {"ok": true, "idb_path": "..."}, "id": 1}
```

#### methods

```json
요청: {"method": "methods", "id": 1}
응답:
{
  "result": {
    "methods": [
      {"name": "ping", "description": "서버 생존 확인"},
      {"name": "status", "description": "인스턴스 상태 조회"},
      {"name": "stop", "description": "인스턴스 정상 종료"},
      {"name": "get_functions", "description": "함수 목록 조회"},
      {"name": "get_strings", "description": "문자열 목록 조회"},
      {"name": "get_imports", "description": "임포트 목록 조회"},
      {"name": "get_exports", "description": "익스포트 목록 조회"},
      {"name": "get_segments", "description": "세그먼트 목록 조회"},
      {"name": "decompile", "description": "함수 디컴파일"},
      {"name": "decompile_batch", "description": "여러 함수 일괄 디컴파일"},
      {"name": "disasm", "description": "어셈블리 디스어셈블"},
      {"name": "get_xrefs_to", "description": "주소로의 크로스 레퍼런스"},
      {"name": "get_xrefs_from", "description": "주소에서의 크로스 레퍼런스"},
      {"name": "find_func", "description": "함수 이름 검색"},
      {"name": "get_func_info", "description": "함수 상세 정보"},
      {"name": "get_imagebase", "description": "바이너리 베이스 주소"},
      {"name": "get_bytes", "description": "원시 바이트 읽기"},
      {"name": "find_bytes", "description": "바이트 패턴 검색"},
      {"name": "get_comments", "description": "주석 조회"},
      {"name": "set_name", "description": "심볼 이름 변경"},
      {"name": "set_comment", "description": "주석 설정"},
      {"name": "save_db", "description": "데이터베이스 저장"},
      {"name": "exec", "description": "Python 코드 실행 (보안 설정 필요)"},
      {"name": "methods", "description": "사용 가능한 API 목록"}
    ]
  },
  "id": 1
}
```

#### --out 파일 저장 규칙

```
인코딩: 항상 UTF-8
JSON:   json.dump(..., ensure_ascii=False, indent=2)
텍스트: UTF-8 일반 텍스트
저장 실패: SAVE_FAILED 에러, 결과는 응답 본문에 포함
```

#### 에러 코드

| 코드 | 상황 | suggestion |
|------|------|-----------|
| NOT_READY | 분석 진행 중 (HTTP 미가동 시에는 연결 자체 실패) | ida_cli.py wait \<id\> |
| DECOMPILER_NOT_LOADED | 플러그인 로드 실패 | 라이선스 확인 후 재시작 |
| INVALID_ADDRESS | 잘못된 주소 또는 심볼 이름 | 0x 접두사 사용 또는 find_func 시도 |
| DECOMPILE_FAILED | 디컴파일 실패 | disasm 대신 사용 |
| UNKNOWN_METHOD | 알 수 없는 API | methods로 목록 확인 |
| SAVE_FAILED | 파일 저장 실패 | 경로/권한 확인 |
| EXEC_DISABLED | exec API 비활성화 | config.json exec_enabled 확인 |
| INVALID_PARAMS | 파라미터 오류 (addrs 초과, size 초과 등) | 파라미터 제한 확인 |
| INTERNAL | 서버 내부 예외 (예상치 못한 에러) | 로그 확인, 재시도 |
| AUTH_FAILED | 인증 토큰 없음 또는 불일치 | 올바른 인증 토큰 사용 |
| FORBIDDEN_HOST | Host 헤더 검증 실패 | 127.0.0.1 또는 localhost로 접근 |

v1.7 대비 제거된 에러 코드:
- `TIMEOUT` (execute_sync 타임아웃) → execute_sync 자체 제거
- `PARAMS_NOT_FOUND` (params.json 미발견) → params.json 제거

---

### 5-4. ida_cli.py

**Claude의 유일한 진입점.** v1.7의 start_ida.py 역할을 흡수.

#### 전체 명령어 목록

**글로벌 옵션**: `--json` — 모든 명령어의 출력을 JSON 형식으로 변환

```
[설정]
ida_cli.py --init                                        ← 초기 설정 (디렉토리/config 생성)
ida_cli.py --check                                       ← 환경 검증 (idapro, Python 버전 등)

[인스턴스 관리]
ida_cli.py start   <바이너리> [--arch <arch>] [--fresh] [--force] [--idb-dir <경로>]
ida_cli.py stop    <id>
ida_cli.py status  [<id>]
ida_cli.py wait    <id> [--timeout 300]
ida_cli.py list
ida_cli.py logs    <id> [--tail N] [--follow]
ida_cli.py cleanup [--dry-run]

[목록 조회]
ida_cli.py [-i <id> | -b <hint>] functions [--offset N] [--count N] [--filter STR] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] strings   [--offset N] [--count N] [--filter STR] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] imports   [--offset N] [--count N] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] exports   [--offset N] [--count N] [--out FILE]
ida_cli.py [-i <id> | -b <hint>] segments  [--out FILE]

[분석]
ida_cli.py [-i <id> | -b <hint>] decompile       <addr>                    [--out FILE]
ida_cli.py [-i <id> | -b <hint>] decompile_batch <addr1> <addr2> ...       [--out FILE]
ida_cli.py [-i <id> | -b <hint>] disasm          <addr> [--count N]        [--out FILE]
ida_cli.py [-i <id> | -b <hint>] xrefs           <addr> [--direction to|from|both]   [--out FILE]
ida_cli.py [-i <id> | -b <hint>] find_func       <name> [--regex] [--max N]
ida_cli.py [-i <id> | -b <hint>] func_info       <addr>
ida_cli.py [-i <id> | -b <hint>] imagebase
ida_cli.py [-i <id> | -b <hint>] bytes           <addr> <size>
ida_cli.py [-i <id> | -b <hint>] find_pattern     <hex_pattern> [--max N]
ida_cli.py [-i <id> | -b <hint>] comments        <addr>
ida_cli.py [-i <id> | -b <hint>] methods

[수정]
ida_cli.py [-i <id> | -b <hint>] rename  <addr> <name>
ida_cli.py [-i <id> | -b <hint>] comment <addr> "<text>" [--repeatable] [--type line|func]
ida_cli.py [-i <id> | -b <hint>] save

[고급]
ida_cli.py [-i <id> | -b <hint>] exec "<python_code>" [--out FILE]
```

#### start 명령어 (v1.7의 start_ida.py 역할 흡수)

`--arch`: 정보 표시용 arch_detect 오버라이드 + FAT Mach-O 슬라이스 선택용.
idalib는 아키텍처를 자동 감지하므로, 대부분의 경우 불필요.
FAT 바이너리에서 특정 슬라이스 분석 시 필요할 수 있으나,
idalib의 `-T` 플래그가 미지원이므로 (Known Issue), 사전에 `lipo`로 추출 권장.

`--idb-dir`: IDB(.i64) 저장 디렉토리 오버라이드. 지정하지 않으면 config의 `paths.idb_dir` 사용.
프로젝트별로 IDB를 분리 저장할 때 유용. 예:
```bash
python tools/ida_cli.py start ./samples/target.so --idb-dir ./samples/
# → ./samples/target_ab12cd34.i64 에 저장
```

```python
def cmd_start(binary, arch, fresh, force, idb_dir=None):
    binary_path = os.path.abspath(binary)

    # 1. 바이너리 존재 확인
    if not os.path.isfile(binary_path):
        print(f"[ERROR] Binary not found: {binary_path}")
        return

    # 2. config 로드
    config, config_path = load_config()  # config_path: 실제 로드된 파일 경로

    # 3. arch_detect (정보 표시용, lock 불필요)
    arch_info = arch_detect(binary_path, arch)

    # 4. instance_id 생성 + idb 경로 결정 (lock 불필요)
    instance_id = make_instance_id(binary_path)
    idb_path = get_idb_path(config, binary_path, instance_id, force, idb_dir=idb_dir)

    # 5. .i64 재사용 시 MD5 검증 (lock 불필요)
    if os.path.exists(idb_path) and not fresh:
        meta = _load_idb_metadata(idb_path)
        stored_md5 = meta.get("binary_md5")
        if stored_md5:
            current_md5 = _file_md5(binary_path)
            if stored_md5 != current_md5:
                print(f"[WARNING] Binary changed since .i64 was created.")
                if not force:
                    print("  Use --fresh to rebuild, or --force to proceed.")
                    return

    # 6. 레지스트리 검증 + 등록 [단일 lock 내에서 원자적 수행]
    #    ⚠️ cleanup_stale, max_instances, 중복 체크, register를
    #       하나의 lock 범위에서 처리 → TOCTOU race 방지
    log_path = os.path.join(config["paths"]["log_dir"], f"{instance_id}.log")
    if not acquire_lock():
        print("[ERROR] Could not acquire registry lock")
        return
    try:
        registry = load_registry()
        cleanup_stale(registry, config["analysis"]["stale_threshold"])

        # max_instances 확인
        if len(registry) >= config["analysis"]["max_instances"]:
            print(f"[ERROR] Max instances reached ({config['analysis']['max_instances']})")
            return

        # 중복 바이너리 확인
        for info in registry.values():
            if info.get("path") == binary_path and info["state"] in ("analyzing", "ready"):
                if not force:
                    print(f"[WARNING] {binary} already running (id: {info['id']}). Use --force.")
                    return

        # initializing 등록 (lock 내에서 원자적)
        registry[instance_id] = {
            "id": instance_id, "pid": None, "port": None,
            "binary": os.path.basename(binary_path),
            "path": binary_path,
            "arch": arch_info.get("arch"), "bits": arch_info.get("bits"),
            "format": arch_info.get("file_format"),
            "idb_path": idb_path, "log_path": log_path,
            "state": "initializing",
            "started": time.time(),
            "last_heartbeat": None
        }
        save_registry(registry)
    finally:
        release_lock()

    # 7. ida_server.py subprocess 실행
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_script = os.path.join(script_dir, "ida_server.py")

    cmd = [sys.executable, server_script,
           binary_path,
           "--id", instance_id,
           "--idb", idb_path,
           "--log", log_path,
           "--config", config_path]
    if fresh:
        cmd.append("--fresh")

    proc = subprocess.Popen(
        cmd,
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 8. 상태 변경 대기 (최대 10초)
    ...

    # 9. 결과 출력
    print(f"[+] Instance started: id={instance_id}")
```

#### instance_id 생성

```python
def make_instance_id(binary_path):
    raw = f"{binary_path}{time.time()}{os.getpid()}"
    h = int(hashlib.md5(raw.encode()).hexdigest(), 16)
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    result = ""
    for _ in range(4):
        result = chars[h % 36] + result
        h //= 36
    return result  # "a1b2"
```

#### idb 파일명 규칙

```python
def get_idb_path(config, binary_path, instance_id, force=False, idb_dir=None):
    if not idb_dir:
        idb_dir = config["paths"]["idb_dir"]  # 기본: %USERPROFILE%/.ida-headless/idb
    os.makedirs(idb_dir, exist_ok=True)
    binary_name = os.path.basename(binary_path)
    name = re.sub(r'[^\w\-.]', '_', binary_name)
    md5 = hashlib.md5(binary_path.encode()).hexdigest()[:8]
    base = f"{name}_{md5}"
    suffix = ".i64"
    if force:
        return os.path.join(idb_dir, f"{base}_{instance_id}{suffix}")
    return os.path.join(idb_dir, f"{base}{suffix}")
```

`--idb-dir` 사용 예:
```
# 기본 (config 경로)
python tools/ida_cli.py start target.so
→ C:\Users\http80\.ida-headless\idb\target_ab12cd34.i64

# 프로젝트 로컬 저장
python tools/ida_cli.py start target.so --idb-dir C:\project\samples
→ C:\project\samples\target_ab12cd34.i64
```

#### 스테일 인스턴스 자동 정리

```python
import psutil

def cleanup_stale(registry, stale_threshold):
    """⚠️ 호출자가 반드시 acquire_lock() 후 호출해야 함.
       registry는 lock 내에서 로드한 객체를 전달."""
    now = time.time()
    changed = False
    for id, info in list(registry.items()):
        if info["state"] == "initializing":
            if now - info["started"] > 30:
                del registry[id]
                changed = True
                continue

        # error 상태: PID 종료 확인 후 즉시 정리
        if info["state"] == "error":
            if not _is_process_alive(info):
                del registry[id]
                changed = True
            continue

        hb = info.get("last_heartbeat")
        # heartbeat=null (analyzing 중 워치독 종료 등): PID로 생존 확인
        if not hb:
            if info.get("pid") and not _is_process_alive(info):
                del registry[id]
                changed = True
            continue

        if now - hb > stale_threshold:
            if not _is_process_alive(info):
                del registry[id]
                changed = True

    if changed:
        save_registry(registry)
    return registry

def _is_process_alive(info):
    """PID + create_time으로 프로세스 생존 확인.
    ⚠️ Windows에서 psutil.Process.create_time() 정밀도는 ~1초
    (내부적으로 100ns FILETIME이나 psutil이 float 변환 시 정밀도 손실).
    따라서 > 1.0 임계값이 적절함."""
    pid = info.get("pid")
    if not pid:
        return False
    try:
        proc = psutil.Process(pid)
        stored_ct = info.get("pid_create_time")
        if stored_ct and abs(proc.create_time() - stored_ct) > 1.0:
            return False  # PID 재사용됨
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
```

#### wait 구현

```python
def cmd_wait(id, timeout):
    deadline = time.time() + timeout
    state = "unknown"
    while time.time() < deadline:
        info = get_instance_info(id)
        if not info:
            print(f"[-] Instance {id} not found")
            return

        state = info.get("state", "unknown")
        port = info.get("port")

        # analyzing 또는 initializing: HTTP 미가동 → 레지스트리 폴링만
        if state in ("initializing", "analyzing"):
            remaining = int(deadline - time.time())
            print(f"[*] {state}... ({remaining}s remaining)")
            time.sleep(config["analysis"]["wait_poll_interval"])
            continue

        # ready: HTTP로 최종 확인
        if state == "ready" and port:
            try:
                resp = post_rpc(port, "ping", instance_id=id)
                if resp.get("result", {}).get("state") == "ready":
                    print("[+] ready")
                    return
            except Exception:
                pass

        if state == "error":
            print(f"[-] Analysis failed. Check logs: ida_cli.py logs {id}")
            return

        remaining = int(deadline - time.time())
        print(f"[*] {state}... ({remaining}s remaining)")
        time.sleep(config["analysis"]["wait_poll_interval"])

    print(f"[-] Timeout ({timeout}s). Current state: {state}")
```

v1.7과의 차이: analyzing 상태에서 HTTP 폴링 제거 → **레지스트리 파일 직접 읽기만**.

#### list 구현

```python
def cmd_list():
    if not acquire_lock():
        print("[ERROR] Could not acquire registry lock")
        return
    try:
        registry = load_registry()
        cleanup_stale(registry, config["analysis"]["stale_threshold"])
    finally:
        release_lock()
    if not registry:
        print("[*] No active instances")
        return
    for id, info in registry.items():
        state = info.get("state", "unknown")
        binary = info.get("binary", "?")
        port = info.get("port", "-")
        print(f"  {id}  {state:<12}  {binary}  port={port}")
```

#### xrefs --direction both 동작

```
--direction to   → post_rpc("get_xrefs_to", ...)
--direction from → post_rpc("get_xrefs_from", ...)
--direction both → get_xrefs_to + get_xrefs_from 순차 호출, 결과 병합
  → {"refs_to": [...], "refs_from": [...], "total_to": N, "total_from": M}
```

#### stop 흐름

```python
def cmd_stop(id):
    info = get_instance_info(id)
    port = info.get("port")
    pid = info.get("pid")

    # ready 상태: HTTP stop 요청
    if port:
        try:
            post_rpc(port, "stop", instance_id=id, timeout=10)
            for _ in range(10):
                time.sleep(0.5)
                if id not in load_registry():
                    print(f"[+] Instance {id} stopped normally")
                    return
        except Exception:
            pass

    # 정상 종료 실패 또는 analyzing 상태: 강제 종료
    if pid:
        try:
            proc = psutil.Process(pid)
            stored_ct = info.get("pid_create_time")
            if stored_ct and abs(proc.create_time() - stored_ct) > 1.0:
                print(f"[+] Instance {id} process already gone (PID reused)")
            else:
                proc.kill()
                print(f"[+] Instance {id} force killed (pid={pid})")
        except psutil.NoSuchProcess:
            print(f"[+] Instance {id} process already gone")

    # 수동 정리 [lock 보호]
    if acquire_lock():
        try:
            r = load_registry()
            r.pop(id, None)
            save_registry(r)
        finally:
            release_lock()
    _remove_auth_token(id)
```

#### RPC 호출 공통 함수

```python
_BATCH_METHODS = {"decompile_batch", "exec"}  # 장시간 소요 가능 API

def post_rpc(port, method, instance_id, params=None, req_id=1, timeout=None):
    if timeout is None:
        if method in _BATCH_METHODS:
            timeout = config["analysis"]["request_timeout_batch"]  # 300초
        else:
            timeout = config["analysis"]["request_timeout"]  # 35초
    url = f"http://127.0.0.1:{port}/"
    body = {"method": method, "id": req_id}
    if params:
        body["params"] = params

    headers = {"Content-Type": "application/json"}
    token = _load_auth_token(instance_id)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(3):
        try:
            resp = requests.post(url, json=body, headers=headers, timeout=timeout)
            try:
                return resp.json()
            except ValueError:
                return {"error": {"code": "INVALID_RESPONSE",
                         "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}}
        except requests.ConnectionError:
            if attempt < 2:
                time.sleep(1)
                continue
            raise
```

#### 인스턴스 선택 우선순위

```
1. -i <id>   → 명시적 ID
2. -b <hint> → 바이너리 이름으로 검색
3. 생략      → 1개면 자동 선택, 2개 이상이면 목록 출력 후 안내
```

#### logs --follow

```python
def cmd_logs_follow(log_path):
    try:
        with open(log_path, encoding='utf-8') as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    print(line, end='', flush=True)
                else:
                    if not os.path.exists(log_path):
                        print("\n[*] Log file removed (instance stopped)")
                        return
                    time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    except FileNotFoundError:
        print(f"[-] Log file not found: {log_path}")
```

#### cleanup 명령어

```python
def cmd_cleanup(dry_run=False):
    registry = load_registry()
    active_ids = set(registry.keys())

    # 1. 고아 로그 삭제 (7일 이상)
    cutoff = time.time() - 7 * 86400
    for f in glob.glob(os.path.join(log_dir, "*.log*")):
        iid = os.path.basename(f).split(".")[0]
        if iid not in active_ids and os.path.getmtime(f) < cutoff:
            if dry_run:
                print(f"  [dry-run] Would delete: {f}")
            else:
                os.remove(f)
                print(f"  Deleted old log: {f}")

    # 2. auth_token 파일에서 비활성 인스턴스 라인 제거
    _cleanup_auth_token(active_ids, dry_run)

    # 3. 미사용 .i64는 목록만 출력 (자동 삭제 안 함)
    for f in glob.glob(os.path.join(idb_dir, "*")):
        if f.endswith(".meta.json"):
            continue
        in_use = any(info.get("idb_path") == f for info in registry.values())
        if not in_use:
            print(f"  [info] Unused .i64 (not deleted): {f}")
```

---

### 5-5. ida_servers.json

초기 등록 (ida_cli.py start, state=initializing):

```json
{
  "a1b2": {
    "id": "a1b2", "pid": null, "port": null,
    "binary": "libsecurity.so",
    "path": "C:/samples/libsecurity.so",
    "arch": "arm", "bits": 64, "format": "ELF",
    "idb_path": "C:/Users/user/.ida-headless/idb/libsecurity_ab12cd34.i64",
    "log_path": "C:/Users/user/.ida-headless/logs/a1b2.log",
    "state": "initializing",
    "started": 1741234567.0,
    "last_heartbeat": null
  }
}
```

analyzing 상태 업데이트 (ida_server.py, open_database 진행 중):

```json
{
  "a1b2": {
    "pid": 12345, "port": null,
    "pid_create_time": 1741234568.5,
    "state": "analyzing",
    "last_heartbeat": null
  }
}
```

⚠️ **port는 analyzing에서 null** — HTTP 서버가 아직 미시작. ready 전환 시 port 할당.

ready 상태 업데이트 (open_database 완료 + HTTP 서버 시작 후):

```json
{
  "a1b2": {
    "port": 49201,
    "state": "ready",
    "last_heartbeat": 1741234630.0
  }
}
```

`pid_create_time`: Windows PID 재사용 감지용.

---

### 5-6. Windows 경로 처리

```python
# subprocess: shell=False + 리스트 스타일
[sys.executable, server_script,
 binary_path,
 "--id", instance_id,
 "--idb", idb_path,
 "--log", log_path,
 "--config", config_path]

# 인코딩
open(..., encoding='utf-8')
json.dump(..., ensure_ascii=False, indent=2)

# 비ASCII 경로 경고
"[WARNING] Non-ASCII characters in path. Use ASCII-only path if analysis fails."

# idb 파일명 정리
name = re.sub(r'[^\w\-.]', '_', binary_name)
```

---

### 5-7. 레지스트리 동시 쓰기 처리

```python
LOCK_PATH = registry_path + ".lock"

def acquire_lock(timeout=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fd = os.open(LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(LOCK_PATH) > 5:
                    os.remove(LOCK_PATH)
                    continue
            except:
                pass
            time.sleep(0.05)
    return False

def release_lock():
    try:
        os.remove(LOCK_PATH)
    except:
        pass
```

---

### 5-8. 중복 바이너리 로드 처리

```
동일 바이너리 경로 + state=analyzing 또는 ready 확인
  ↓
  --force 없음 →
    "[WARNING] libsecurity.so is already running (id: a1b2). Use --force."
    종료

  --force →
    idb_path = libsecurity_ab12cd34_c3d4.i64  (instance_id 접미사 추가)
    진행
```

---

### 5-9. common.py (공유 모듈)

ida_server.py와 ida_cli.py에서 동일하게 사용하는 코드를 추출한 모듈.
약 220줄의 중복 코드를 ~130줄의 단일 모듈로 통합.

#### 추출 배경

| 항목 | ida_server.py | ida_cli.py | 중복 |
| ---- | ------------- | ---------- | ---- |
| Config 로드 (_expand_env, _expand_config, load_config) | O | O | 동일 |
| Registry 관리 (acquire_lock, release_lock, load_registry, save_registry) | O | O | 동일 |
| file_md5 | O | O | 동일 |
| remove_auth_token | O | O | 동일 |
| init_registry_paths | O | O | 동일 |

양쪽에서 100% 동일한 코드를 유지해야 하는 부담 → 한쪽만 수정 시 불일치 발생 위험.

#### 구조

```python
# common.py — ida_server.py / ida_cli.py 공유 모듈

# Constants
STALE_LOCK_TIMEOUT = 5          # seconds before stale lock is forcibly removed
LOCK_POLL_INTERVAL = 0.05       # seconds between lock acquisition retries
DEFAULT_LOCK_TIMEOUT = 1.0      # seconds to wait for lock before giving up
FILE_READ_CHUNK = 8192          # bytes per chunk for file MD5

# Config
def _expand_env(path): ...      # %USERPROFILE% 등 환경 변수 치환
def _expand_config(obj): ...    # dict/list 재귀 치환
def load_config(config_path): ...  # config.json 로드 + 환경 변수 확장

# Registry (lock + load + save)
def init_registry_paths(config): ...  # config에서 registry 경로 초기화
def acquire_lock(timeout=1.0): ...    # 파일 잠금 획득 (stale lock 자동 정리)
def release_lock(): ...               # 파일 잠금 해제
def load_registry(): ...              # JSON → dict
def save_registry(registry): ...      # dict → JSON

# File utilities
def file_md5(path): ...               # 파일 MD5 해시 (hex)

# Auth token
def remove_auth_token(token_path, instance_id): ...  # 인스턴스 토큰 제거
```

#### 사용 패턴

```python
# ida_server.py
from common import (load_config, init_registry_paths, acquire_lock,
                     release_lock, load_registry, save_registry,
                     file_md5, remove_auth_token)

# ida_cli.py (load_config를 래핑하여 기본 경로 + tuple 반환)
from common import (load_config as _load_config_core, init_registry_paths,
                     acquire_lock, release_lock, load_registry, save_registry,
                     file_md5, remove_auth_token)
```

ida_cli.py는 `_load_config_core()`를 래핑하여 config 파일 탐색 로직(현재 디렉토리 → `~/.ida-headless/`) +
`(config, config_path)` tuple 반환을 추가. ida_server.py는 `--config` 인자로 경로를 직접 받으므로 래핑 불필요.

#### 설계 원칙

- **서버/CLI 고유 로직은 각 모듈에 유지**: `_update_registry`, `_update_state` (서버 전용), `cleanup_stale`, `_build_dispatch` (CLI 전용)
- **상태 없음**: `init_registry_paths()`로 경로 초기화 후 사용. 모듈 레벨 전역 상태 최소화.
- **Lock은 호출자 책임**: `acquire_lock()` / `release_lock()`을 직접 호출하는 패턴 유지 (context manager 미사용, 기존 코드 호환)

---

## 6. 설치 및 설정

### 6-1. 설치 단계

```
1. IDA 버전 확인
   IDA Pro 9.1 이상 필요 (open_database args 파라미터)

2. Python 버전 호환성 확인
   실행: idapyswitch.exe → 기대하는 Python 버전 표시 (예: 3.12)
   필요 시 해당 Python 버전 설치 (major.minor 일치 필수)

3. idapro 패키지 설치
   pip install "<IDA_DIR>/idalib/python/idapro-*.whl"

4. idalib 활성화 (두 가지 방법 중 택일)
   방법 A: python "<IDA_DIR>/idalib/python/py-activate-idalib.py"
   방법 B: 환경 변수 IDADIR=<IDA 설치 경로> 설정

5. tools/ 디렉토리 배치
   예: C:\tools\ida-headless\
   주의: 경로에 공백이 있으면 안 됨

6. 의존 패키지 설치
   pip install requests psutil

7. config 초기화
   python ida_cli.py --init
   → %USERPROFILE%\.ida-headless\config.json 기본 템플릿 생성
   → 디렉토리 자동 생성: idb/, logs/

8. 설정 검증
   python ida_cli.py --check
```

### 6-2. 자동 생성 디렉토리

```
%USERPROFILE%\.ida-headless\
%USERPROFILE%\.ida-headless\idb\
%USERPROFILE%\.ida-headless\logs\
```

v1.7 대비 제거: `params/` 디렉토리 (params.json 불필요).

### 6-3. 검증 체크리스트

```
[ ] IDA Pro 버전 >= 9.1
[ ] idapro 패키지 설치됨 (pip show idapro)
[ ] python -c "import idapro" 성공
[ ] Python 버전 일치 (IDA .pyd 호환)
[ ] pip install requests psutil 완료
[ ] tools/ 디렉토리 경로에 공백 없음
[ ] python ida_cli.py --check 통과
[ ] python ida_cli.py start <바이너리> → state=analyzing 확인
[ ] python ida_cli.py wait <id> → ready
[ ] python ida_cli.py -b <바이너리> functions 결과 반환
[ ] python ida_cli.py stop <id> → .i64 저장 확인
[ ] python ida_cli.py cleanup --dry-run → 고아 파일 목록 출력
```

---

## 7. Claude 워크플로우

```
[Android APK 네이티브 라이브러리 분석]

0. 최초 설정
   python ida_cli.py --init && pip install requests psutil

1. 인스턴스 시작
   bash: python ida_cli.py start libsecurity.so
   → id=a1b2, state=analyzing

2. 분석 완료 대기
   bash: python ida_cli.py wait a1b2 --timeout 300

3. 초기 정찰
   bash: python ida_cli.py -b libsecurity strings   --out C:/tmp/strings.json
   bash: python ida_cli.py -b libsecurity imports   --out C:/tmp/imports.json
   bash: python ida_cli.py -b libsecurity functions --filter "check" --out C:/tmp/funcs.json

4. 에러 시
   bash: python ida_cli.py logs a1b2 --tail 20

5. 핵심 로직 분석
   bash: python ida_cli.py -b libsecurity find_func "check"
   bash: python ida_cli.py -b libsecurity func_info check_root
   bash: python ida_cli.py -b libsecurity decompile check_root --out C:/tmp/check_root.c
   bash: python ida_cli.py -b libsecurity xrefs 0x1234 --direction both
   bash: python ida_cli.py -b libsecurity rename 0x1234 check_root_real
   bash: python ida_cli.py -b libsecurity disasm 0x1234 --count 30

5-1. 고급 분석
   bash: python ida_cli.py -b libsecurity imagebase
   bash: python ida_cli.py -b libsecurity bytes 0x1234 64
   bash: python ida_cli.py -b libsecurity find_pattern "48 8B ? ? 00" --max 20
   bash: python ida_cli.py -b libsecurity decompile_batch 0x1234 0x5678 check_root --out C:/tmp/batch.json

6. .i64 재사용 (재분석)
   bash: python ida_cli.py start libsecurity.so
   → .i64 감지 → binary_md5 검증 → open_database(idb_path) → 수 초 → ready
   → 바이너리 변경 시: WARNING → --fresh 또는 --force

7. 종료
   bash: python ida_cli.py stop a1b2
```

---

## 8. 기존 분석 스택과의 연동

```
Java/Kotlin 코드          → JADX MCP
네이티브 .so (간단 확인)    → Ghidra MCP
네이티브 .so (심층 분석)    → IDA CLI (idalib)
```

판단 트리:

```
.so 분석 필요
  ↓
Ghidra 디컴파일 결과로 충분한가?
  YES → 완료
  NO  → 보안 솔루션 핵심 로직 또는 Ghidra 결과 불명확?
          YES → IDA CLI 사용
```

---

## 9. 엣지 케이스 및 에러 처리

### v1.7에서 제거된 엣지 케이스

idalib 전환으로 **더 이상 해당하지 않는** 항목:

| 제거된 항목 | 이유 |
|------------|------|
| execute_sync 타임아웃/데드락 | execute_sync 자체 제거 |
| register_timer 라이프사이클 | register_timer 불필요 |
| auto_wait 백그라운드 스레드 데드락 | open_database가 일체형 처리 |
| ThreadingHTTPServer 스레드 안전성 | HTTPServer 단일 스레드 |
| notify_when(NW_TERMIDA) batch mode | notify_when 불필요 |
| params.json 미발견 | params.json 불필요 |
| idc.ARGV.count (IDC 문법) | idc.ARGV 불필요 (argparse) |
| idc.save_base() deprecated | idc 미사용 |
| get_kernel_version 스레드 안전성 | 단일 스레드, 캐싱 불필요 |
| analyzing 상태 execute_sync 미사용 | HTTP 자체 미가동 |
| status analyzing vs ready 이원화 | ready에서만 HTTP |
| per-API execute_sync 타임아웃 | 직접 호출, 별도 타임아웃 불필요 |
| stale_threshold vs batch ops 충돌 | execute_sync 없으므로 충돌 없음 |
| qexit 비메인 스레드 안전성 | qexit 미사용 |
| NW_TERMIDA 모듈 혼동 (ida_idaapi vs ida_idp) | notify_when 불필요 |
| idat -S 스크립트 반환 시 IDA 자동 종료 | idalib에서는 해당 없음 |
| script_path 공백 문제 (-S 플래그) | -S 플래그 미사용 |

### 유지되는 엣지 케이스

| 케이스 | 처리 방법 |
|--------|----------|
| FAT 바이너리 | 슬라이스 목록 출력 → --arch 수동 선택 |
| Raw 펌웨어 | --arch 필수 |
| DEX/APK | JADX로 리다이렉트 |
| 인스턴스 크래시 | 모든 명령어에서 자동 스테일 정리 (heartbeat + PID 확인) |
| initializing 30초+ | 스테일로 처리, 자동 정리 |
| 포트 충돌 | port 0 (OS 자동 할당) |
| 플러그인 로드 실패 | 어셈블리 전용 폴백 |
| .i64 손상 | --fresh 제안 |
| 컨텍스트 오버플로 | --out 강제, 파일 읽기 모드로 전환 |
| config.json 없음 | 기본값으로 폴백 + 경고 |
| 디렉토리 없음 | 자동 생성 |
| 비ASCII 경로 | 경고 + ASCII 경로 제안 |
| 레지스트리 lock 타임아웃 | 스테일 lock 제거, 재시도 |
| stop 무응답 | psutil로 강제 종료 + 수동 레지스트리 정리 |
| exec_enabled=false | EXEC_DISABLED |
| 중복 바이너리 로드 | 경고 후 종료, --force로 별도 인스턴스 |
| --out 저장 실패 | SAVE_FAILED, 결과는 응답 본문에 포함 |
| 심볼 이름 주소 해석 실패 | INVALID_ADDRESS + find_func 제안 |
| Windows PID 재사용 | pid_create_time 저장 + 비교 |
| subprocess 분리 | DETACHED_PROCESS \| CREATE_NEW_PROCESS_GROUP |
| .i64 재사용 시 바이너리 변경 | binary_md5 비교 → 경고 |
| decompile_batch 개별 실패 | error 필드 포함, 나머지 정상 반환 |
| decompile_batch addrs 초과 | 최대 20개, INVALID_PARAMS |
| DNS rebinding | Host 헤더 검증 |
| CSRF | Bearer 토큰 필수 |
| get_bytes 크기 제한 | 최대 4096, INVALID_PARAMS |
| find_bytes API 변경 (IDA 9.0+) | `ida_bytes.find_bytes()` 사용 (`parse_binpat_str`/`bin_search` deprecated, `idc.find_binary` 제거됨). 단일 ea_t 반환 |
| 로그 비대화 | RotatingFileHandler (50MB/3백업) |
| 고아 파일 | cleanup 명령어 |
| exec stdout 캡처 | contextlib.redirect_stdout |
| save_database 버그 | `ida_loader.save_database(path, 0)` — flags=0 명시 전달 워크어라운드 |
| ida_struct 제거됨 (IDA 9.x) | ida_typeinf 전용 사용 |
| IDA 라이선스 만료 | import idapro 실패 → --check에서 감지 |
| max_instances 초과 | 에러 메시지 후 종료 |

### v2.0 신규 엣지 케이스

| 케이스 | 처리 방법 |
|--------|----------|
| idapro import 실패 | IDADIR 미설정 또는 idalib.dll 미발견 → --check에서 안내 |
| open_database 반환값 != 0 | state=error, 로그에 에러 코드 기록, sys.exit(1) |
| open_database 타임아웃 | 워치독 스레드 600초 후 os._exit(1) |
| analyzing 상태에서 stop | HTTP 미가동 → ida_cli.py가 PID로 강제 종료 |
| idalib 단일 스레드 위반 | HTTPServer (단일 스레드) 사용으로 원천 차단 |
| close_database 실패 | try/except 후 로그, 프로세스 종료 |
| -o 플래그 (IDA 9.1+) | 지원됨. -o는 -c imply → 신규 분석 전용. 재사용 시 .i64 직접 열기 |
| -o 플래그 미지원 (IDA 9.0) | 폴백: 바이너리를 idb_dir에 hardlink/복사 후 open_database |
| idapro whl Python 버전 불일치 | .pyd 로드 실패 → import 에러 → --check에서 감지 |
| Python 3.14 사용 | IDA 9.3 Known Issue ("PySide6 crashes") → --check에서 경고 |
| serve_forever 중 장시간 요청 | 단일 스레드이므로 다른 요청 대기; Claude 순차 호출이므로 문제 없음 |
| server.shutdown 핸들러 내 호출 | 별도 스레드에서 호출 (데드락 방지, Python 공식 권장) |
| analyzing stop 시 .i64 손상 | proc.kill() 후 불완전 .i64 가능 → --fresh로 재생성 안내 |
| .i64.meta.json 누락 | 경고 출력 후 MD5 검증 생략, 정상 진행 |
| exec 무한 루프 | 서버 측 타임아웃 없음 → 클라이언트 request_timeout_batch로 간접 보호 |
| exec에서 idc.qexit() 호출 | 서버 프로세스 종료됨 → _exec_namespace에서 제거 검토 |
| 멀티 인스턴스 IDA 라이선스 | open_database 실패 → state=error + 기존 인스턴스 중지 제안 |
| wait 타임아웃 | 메시지 출력 + 현재 상태, logs 확인 제안 |
| logs --follow Ctrl+C | KeyboardInterrupt catch → 정상 종료 |
| auth_token 파일 권한 | Windows: 기본 ACL 상속 (소유자 읽기 권장) |
| 동시 start 호출 (같은 바이너리) | 레지스트리 lock으로 직렬화, 두 번째 호출은 중복 감지 |
| 디스크 공간 부족 (save_db) | save_db 실패 로그 + SAVE_FAILED 에러 |
| 바이너리 삭제 (분석 중) | open_database는 초기에 로드 완료 → 영향 없음. 재시작 시 바이너리 미발견 에러 |
| open_database 에러 코드 해석 | 코드별 의미 로깅 (라이선스, 포맷 미지원, 파일 미발견 등) |
| idb_path MD5가 파일 내용이 아닌 경로 해시 | 의도적 설계: 같은 파일 다른 경로 → 별도 .i64 생성 |
| atexit Python 3.12+ thread 제한 | close_database()가 내부 thread 생성 시 RuntimeError 가능 → 테스트 필요 |
| close_database double-close | _db_closed guard로 정상 종료 + atexit 이중 호출 방지 |
| HTTP 403 응답 파싱 | 서버가 JSON 형식으로 에러 반환 (send_error 미사용), 클라이언트도 non-JSON 방어 |
| error 상태 레지스트리 잔존 | cleanup_stale에서 error 상태 + PID 종료 확인 시 자동 정리 |
| heartbeat=null 레지스트리 항목 | cleanup_stale에서 PID 생존 여부로 판단 (워치독 종료 케이스) |
| idb_dir 쓰기 권한 없음 | open_database 실패 → state=error. --check에서 쓰기 권한 검증 추가 권장 |
| 동시 start TOCTOU race | 중복 체크를 레지스트리 lock 내에서 수행하여 직렬화 |
| decompiler 32/64-bit 플러그인 불일치 | `ida_ida.inf_is_64bit()`로 bitness 확인 후 정확한 플러그인 선택 (예: hexarm vs hexarm64). IDA 9.x에서도 플러그인은 32/64 분리 유지 |
| malformed HTTP 요청 (Content-Length 누락, 잘못된 JSON) | JSON 파싱을 try/except 내에 포함, INVALID_PARAMS 에러 코드로 JSON 응답 반환 (Python 기본 500 에러 방지) |

---

## 10. 구현 순서

```
Step 1: arch_detect.py + config.json
        → ELF/PE/Mach-O 헤더 파싱
        → config.json 로드 / 기본값 / 환경 변수 치환
        → --init (디렉토리 자동 생성)
        → --check (idapro import, Python 버전, psutil, 경로 검증)

Step 2: ida_server.py (idalib 기반)
        → argparse 인자 수신
        → import idapro → open_database (블로킹)
        → open_db_timeout 워치독
        → _DECOMPILER_MAP 기반 플러그인 로드
        → save_db (ida_loader.save_database flags=0 워크어라운드)
        → HTTPServer (단일 스레드) + 보안 (토큰 + Host 검증)
        → 전체 API 구현 (24개)
        → heartbeat (레지스트리만 갱신, IDA API 미호출)
        → 종료: close_database + atexit 정리
        → 로그: RotatingFileHandler

Step 3: ida_cli.py
        → start 명령어 (v1.7 start_ida.py 역할 흡수):
          instance_id 생성, .i64 경로 결정, MD5 검증,
          중복 감지, 레지스트리 등록, subprocess 실행
        → 인증 토큰 로드 + 연결 재시도 (3회)
        → cleanup_stale() psutil + pid_create_time
        → cleanup 명령어 (--dry-run)
        → --json 글로벌 출력 모드
        → xrefs --direction to|from|both
        → logs --follow: 0.5초 폴링
        → wait: 레지스트리 폴링 (analyzing 시 HTTP 미사용)
        → stop: 정상 종료 후 강제 종료 폴백

Step 4: 통합 테스트 + 엣지 케이스 강화

Step 5: Claude 스킬 업데이트
```

v1.7 대비 변경:
- start_ida.py (Step 3) 제거 → ida_cli.py에 병합
- ida_server.py에서 execute_sync/register_timer/ThreadingHTTPServer 관련 코드 전부 제거
- --check에서 idat.exe 확인 대신 idapro import 확인

---

## 11. 버전 히스토리

| 버전 | 변경 사항 |
|------|----------|
| v0.1 ~ v1.7 | idat -S 기반 아키텍처 (상세 내역은 headless_ida_plan_v1.7.md 참조) |
| v2.0 | **idalib 전환**: idat -S → idalib (Hex-Rays 공식 헤드리스 라이브러리) 전면 전환. **제거**: start_ida.py, params.json, execute_sync, register_timer, ThreadingHTTPServer, notify_when(NW_TERMIDA), idat.exe 경로 관리, -S/-A/-c 플래그 관리. **단순화**: HTTPServer 단일 스레드 (데드락 불가), idapro.open_database() 일체형 분석+대기, idapro.close_database() 깔끔한 종료, atexit 단독 방어 (이중 방어 불필요), argparse 인자 수신 (idc.ARGV 불필요). **신규**: analyzing 상태 HTTP 미가동 (레지스트리 폴링), open_db_timeout 워치독, idapro --check 검증, -o 플래그 idb 경로 제어. **유지**: HTTP JSON-RPC 프로토콜, 24개 API, 보안 3중 방어, .i64 재사용 + MD5 검증, heartbeat + 스테일 정리, 레지스트리 lock, 전체 CLI 명령어. |
| v2.0.1 | **기술 검증 반영**: IDA 9.0 → **9.1+ 요구** (open_database args 파라미터 9.1에서 추가). Python **3.12/3.13 권장**, 3.14 비호환 경고 (Known Issue). -o 플래그 지원 확인 (IDA 9.1+, -c imply). analyzing 상태 port=null 수정 (모순 해소). RISC-V ELF e_machine 감지 추가 (0xF3). INTERNAL 에러코드 추가. find_bytes start 파라미터 추가. **타임아웃 분기**: request_timeout(35s) / request_timeout_batch(300s). config_path 변수 정의. SERVER_VERSION 상수. **atexit 상세화**: 동작 범위 표, Python 3.12+ thread 제한 주의. exec 보안 주의사항. shutdown race condition 문서화. --arch 옵션 동작 설명. **엣지 케이스 20건 추가**: analyzing stop .i64 손상, exec 무한루프, idc.qexit 방어, 멀티 인스턴스 라이선스, 동시 start 직렬화, 디스크 부족, atexit thread 제한 등. |
| v2.0.2 | **일관성 검토**: HTTP 403 응답을 JSON 형식으로 변경 (send_error→_send_json, FORBIDDEN_HOST/AUTH_FAILED 에러 코드 실제 반환). post_rpc에 non-JSON 응답 방어 코드 추가. **cleanup_stale 강화**: error 상태 + PID 종료 시 자동 정리, heartbeat=null 항목 PID 기반 판단, _is_process_alive 헬퍼 추출. **close_database double-close 방지**: _db_closed guard 추가. **CLI 보완**: --init/--check 명령어 목록에 추가, list 구현 정의, save CLI 명령어 추가, find_func --regex/--max 옵션, comment --repeatable 옵션, xrefs --direction both 동작 정의. **수정**: find_func 예시 total 불일치 (3→2), auth_token 파일 설명 정확화, API 개수 22→24, 설치 단계 IDA 9.0→9.1. **엣지 케이스 7건 추가**: double-close, HTTP 403 파싱, error 상태 잔존, heartbeat null, idb_dir 권한, TOCTOU race. |
| v2.0.3 | **에러 핸들링 정합성**: do_POST에 RpcError catch 분기 추가 (_dispatch의 RpcError 예외가 정상적으로 {"error": ...} 형식 응답 생성). **예시 데이터 정합성**: decompile_batch 예시에 누락된 0x5678 성공 항목 추가 (total=3에 맞게 3개 항목). analyzing 상태 레지스트리 예시 last_heartbeat를 null로 수정 (heartbeat 스레드는 open_database 완료 후 시작, stale_threshold < open_db_timeout 충돌 방지). **--check 강화**: idb 디렉토리 쓰기 권한 검증 항목 추가 (tempfile 기반). cleanup_stale 호출 시 stale_threshold 인자 누락 수정. |
| v2.0.4 | **구현 검증 (웹 리서치 기반)**: _DECOMPILER_MAP을 `(proc_id, is_64bit)` 튜플 키로 전면 교체 — IDA 9.x에서도 decompiler 플러그인은 32/64-bit 분리 유지 (hexrays/hexx64, hexarm/hexarm64 등). `ida_ida.inf_is_64bit()` 체크 추가. Section 3-2 플러그인 표 및 Section 5-2 코드 양쪽 모두 반영. **레지스트리 lock 보호 강화**: cleanup_stale, cmd_start, cmd_list, cmd_stop 모든 레지스트리 수정 경로에 acquire_lock/release_lock try/finally 래핑. **cmd_start TOCTOU 수정**: max_instances 확인 + 중복 체크 + register를 **단일 lock 범위 내**에서 원자적 수행 (기존: lock 해제 후 검증→등록하여 race 가능). **레지스트리 파일 위치 통일**: tools/ 디렉토리에서 ida_servers.json 제거, %USERPROFILE%/.ida-headless/ 디렉토리 구조에 정확히 반영. **psutil 정밀도 문서화**: _is_process_alive에 create_time() ~1초 정밀도 주의사항 주석 추가. **함수명 통일**: ida_cli.py 내 `_save_registry`/`_load_registry` → `save_registry`/`load_registry` (ida_server.py는 underscore 유지). find_bytes max_results 중복 기술 제거. **엣지 케이스 1건 추가**: decompiler 32/64-bit 플러그인 불일치. |
| v2.0.5 | **do_POST 에러 핸들링 강화**: JSON 파싱을 try/except 범위 안으로 이동 — malformed request(Content-Length 누락, 잘못된 JSON)에도 JSON 에러 응답 반환 (`json.JSONDecodeError` → INVALID_PARAMS). **set_comment API 명세 보완**: `type` 파라미터 추가 (`"line"` 기본값, `"func"`이면 함수 주석 — `idc.set_func_cmt()` 사용). CLI에도 `--type line\|func` 옵션 추가. **exec_namespace 보완**: `ida_ida` 모듈 추가. **엣지 케이스 1건 추가**: malformed HTTP 요청. |
| v2.0.6 | **API 구현 검증 (웹 리서치 기반)**: **idaapi umbrella 모듈 정리** — Hex-Rays 권장에 따라 originating module 직접 사용. `save_db()`에서 `idaapi.get_path`/`idaapi.save_database` → `ida_loader.get_path`/`ida_loader.save_database`로 변경. 캐싱 값 수집에서 `idaapi.get_kernel_version()` → `ida_kernwin.get_kernel_version()`. **find_bytes deprecated API 교체**: `parse_binpat_str` + `bin_search` 조합은 IDA 9.0 포팅 가이드에서 deprecated. `ida_bytes.find_bytes()` 고수준 API로 전면 교체 (단일 ea_t 반환, tuple 아님). `idc.find_binary`/`ida_search.find_binary`도 IDA 9.0에서 제거됨 명시. **확인된 API (변경 없음)**: `idc.get_name_ea_simple` (BADADDR 반환 확인), `ida_hexrays.decompile` (cfuncptr_t 반환), `idautils.Functions` (generator), SEGPERM 값 (R=4,W=2,X=1), `idc.set_cmt`/`set_func_cmt` 시그니처. |
