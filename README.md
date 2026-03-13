# Headless IDA

[한국어](#한국어) | [English](#english)

---

## English

A CLI-based binary analysis system powered by **idalib** (Hex-Rays official headless library), eliminating the need for IDA Pro GUI.

AI assistants (Claude Code, Cursor, etc.) call `ida_cli.py` via shell to perform automated binary analysis — **no MCP required**.

### Architecture

```text
User/AI → ida_cli.py → HTTP JSON-RPC → ida_server.py (idalib)
```

- **No MCP layer** — Pure HTTP JSON-RPC communication
- **Single-threaded HTTPServer** — Compliant with idalib's single-thread constraint
- **.i64 reuse** — Reloads in seconds for repeated analysis
- **Auth tokens** — Per-instance Bearer token auto-generation

### Why No MCP?

This project intentionally uses plain HTTP JSON-RPC instead of MCP (Model Context Protocol).

| | HTTP JSON-RPC (this project) | MCP |
| --- | --- | --- |
| **Dependencies** | Python stdlib only (`http.server`) | MCP SDK + transport layer required |
| **Debugging** | `curl` one-liner testable | Requires MCP-aware client |
| **AI compatibility** | Any AI with shell access (Claude Code, Cursor, etc.) | MCP-compatible clients only |
| **Context window** | Zero overhead — just bash commands | Tool schemas loaded into AI context, consuming tokens |
| **Script automation** | Directly callable from bash/Python scripts | Requires MCP client library |
| **Deployment** | Single `.py` file, zero config | Server manifest + schema registration needed |
| **idalib constraint** | Single-thread `HTTPServer` maps 1:1 | MCP async model conflicts with single-thread restriction |

> **TL;DR** — Any AI with shell access can use it immediately. No SDK, no schema registration, no token overhead.

### Requirements

| Component | Version |
| --------- | ------- |
| IDA Pro | 9.1+ (idalib support required) |
| Python | 3.12 or 3.13 (must match IDA's bundled version) |
| OS | Windows 10/11 |

> **Warning**: Python 3.14 is incompatible — IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14").

### Setup

#### Step 1. Install idalib Python package

```bash
pip install "<IDA_DIR>/idalib/python/idapro-*.whl"
```

The `.whl` file is included in your IDA Pro installation directory.

#### Step 2. Register IDA path (choose one)

```bash
# Option A: Run the activation script (recommended)
python "<IDA_DIR>/idalib/python/py-activate-idalib.py"

# Option B: Set environment variable
set IDADIR=C:\Program Files\IDA Professional 9.3
```

#### Step 3. Install dependencies

```bash
pip install requests psutil
```

#### Step 4. Verify and initialize

```bash
# Check environment
python tools/ida_cli.py --check

# Create working directories
python tools/ida_cli.py --init
```

#### Step 5. Configuration (optional)

Edit `tools/config.json` to set IDA path and other options:

```json
{
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3"
  },
  "paths": {
    "idb_dir": "%USERPROFILE%/.ida-headless/idb",
    "log_dir": "%USERPROFILE%/.ida-headless/logs"
  },
  "analysis": {
    "max_instances": 3
  }
}
```

#### Step 6. Test it works

```bash
# Start an instance with any binary
python tools/ida_cli.py start ./samples/target.exe

# Check status
python tools/ida_cli.py list

# Stop
python tools/ida_cli.py stop <id>
```

If you see `Instance started: id=xxxx` and the instance appears in `list`, the setup is complete.

### AI Integration

Once the environment is set up, AI assistants use `ida_cli.py` commands via shell. You don't need to memorize these — the AI handles it.

#### Claude Code

A skill file is included at `.claude/commands/ida.md`. Use it with:

```text
/ida ./target.so
```

Claude will automatically start an instance, analyze the binary, and report findings.

#### Other AI Tools (Cursor, GPT, etc.)

Any AI with shell/terminal access can call `ida_cli.py` directly. Point the AI to `CLAUDE.md` for the full command reference.

### Command Reference

Commands are primarily used by AI, listed here for reference.

#### Instance Management

| Command | Description |
| ------- | ----------- |
| `start <binary>` | Start analysis instance |
| `stop <id>` | Stop instance |
| `wait <id>` | Wait for analysis to complete |
| `list` | List running instances |
| `status [<id>]` | Show instance status |
| `logs <id>` | View instance logs |
| `cleanup` | Remove stale instances |

#### Analysis (24 APIs)

| Command | Description |
| ------- | ----------- |
| `functions` | List functions |
| `strings` | List strings |
| `imports` / `exports` | List imports/exports |
| `segments` | List segments |
| `decompile <addr\|name>` | Decompile function |
| `disasm <addr\|name>` | Disassemble |
| `xrefs <addr>` | Cross-references |
| `find_func <name>` | Search functions |
| `func_info <addr\|name>` | Function details |
| `bytes <addr> <size>` | Read raw bytes |
| `find_pattern <hex>` | Byte pattern search |

#### Modification

| Command | Description |
| ------- | ----------- |
| `rename <addr> <name>` | Rename symbol |
| `comment <addr> "text"` | Add comment |
| `save` | Save database |

#### Common Options

| Option | Description |
| ------ | ----------- |
| `--json` | JSON output |
| `-i <id>` | Specify instance ID |
| `-b <hint>` | Auto-select by binary name |
| `--out FILE` | Save output to file |

### Supported Formats

PE, ELF, Mach-O, FAT, .so, dylib, Raw binary, Intel HEX, SREC

Decompiler: x86/x64, ARM/ARM64, MIPS, PowerPC, RISC-V

### License

**Apache License 2.0** — See [LICENSE](LICENSE).

A valid **IDA Pro license** is required separately. Hex-Rays decompiler license is optional.

---

## 한국어

IDA Pro GUI 없이 **idalib** (Hex-Rays 공식 헤드리스 라이브러리)을 사용하여 CLI에서 바이너리 분석을 수행하는 시스템.

AI 어시스턴트(Claude Code, Cursor 등)가 shell로 `ida_cli.py`를 호출하여 자동 바이너리 분석 — **MCP 불필요**.

### 아키텍처

```text
User/AI → ida_cli.py → HTTP JSON-RPC → ida_server.py (idalib)
```

- **MCP 레이어 없음** — 순수 HTTP JSON-RPC 통신
- **단일 스레드 HTTPServer** — idalib 단일 스레드 제약 준수
- **.i64 재사용** — 반복 분석 시 수 초 만에 로드
- **인증 토큰** — 인스턴스별 Bearer token 자동 생성

### 왜 MCP를 안 쓰나?

이 프로젝트는 MCP(Model Context Protocol) 대신 순수 HTTP JSON-RPC를 의도적으로 사용합니다.

| | HTTP JSON-RPC (이 프로젝트) | MCP |
| --- | --- | --- |
| **의존성** | Python 표준 라이브러리만 (`http.server`) | MCP SDK + transport 레이어 필요 |
| **디버깅** | `curl` 한 줄로 테스트 가능 | MCP 지원 클라이언트 필요 |
| **AI 호환성** | shell 접근 가능한 모든 AI (Claude Code, Cursor 등) | MCP 호환 클라이언트에만 종속 |
| **컨텍스트 윈도우** | 오버헤드 없음 — bash 명령어만 사용 | tool schema가 AI 컨텍스트에 로드되어 토큰 소모 |
| **스크립트 자동화** | bash/Python에서 바로 호출 가능 | MCP 클라이언트 라이브러리 필요 |
| **배포** | `.py` 파일 하나, 별도 설정 없음 | 서버 manifest + 스키마 등록 필요 |
| **idalib 제약** | 단일 스레드 `HTTPServer`가 1:1 매핑 | MCP async 모델이 단일 스레드 제약과 충돌 |

> **요약** — shell 접근 가능한 AI면 바로 사용 가능. SDK 불필요, 스키마 등록 불필요, 토큰 오버헤드 없음.

### 요구사항

| 항목 | 버전 |
| ---- | ---- |
| IDA Pro | 9.1 이상 (idalib 지원 필수) |
| Python | 3.12 또는 3.13 (IDA 번들 버전과 일치 필수) |
| OS | Windows 10/11 |

> **Warning**: Python 3.14는 IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14")로 비호환.

### 환경 구축

#### Step 1. idalib Python 패키지 설치

```bash
pip install "<IDA_DIR>/idalib/python/idapro-*.whl"
```

IDA Pro 설치 디렉토리에 `.whl` 파일이 포함되어 있습니다.

#### Step 2. IDA 경로 등록 (택일)

```bash
# 방법 A: 활성화 스크립트 실행 (권장)
python "<IDA_DIR>/idalib/python/py-activate-idalib.py"

# 방법 B: 환경 변수 설정
set IDADIR=C:\Program Files\IDA Professional 9.3
```

#### Step 3. 의존 패키지 설치

```bash
pip install requests psutil
```

#### Step 4. 검증 및 초기화

```bash
# 환경 검증
python tools/ida_cli.py --check

# 작업 디렉토리 생성
python tools/ida_cli.py --init
```

#### Step 5. 설정 (선택사항)

`tools/config.json`에서 IDA 경로 등 설정:

```json
{
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3"
  },
  "paths": {
    "idb_dir": "%USERPROFILE%/.ida-headless/idb",
    "log_dir": "%USERPROFILE%/.ida-headless/logs"
  },
  "analysis": {
    "max_instances": 3
  }
}
```

#### Step 6. 동작 테스트

```bash
# 아무 바이너리로 인스턴스 시작
python tools/ida_cli.py start ./samples/target.exe

# 상태 확인
python tools/ida_cli.py list

# 종료
python tools/ida_cli.py stop <id>
```

`Instance started: id=xxxx`가 출력되고 `list`에 나타나면 환경 구축 완료.

### AI 연동

환경 구축 완료 후, AI 어시스턴트가 shell로 `ida_cli.py` 명령어를 호출합니다. 사용자가 명령어를 외울 필요 없습니다.

#### Claude Code

`.claude/commands/ida.md` 스킬 파일이 포함되어 있습니다:

```text
/ida ./target.so
```

Claude가 자동으로 인스턴스를 시작하고, 바이너리를 분석하고, 결과를 보고합니다.

#### 다른 AI 도구 (Cursor, GPT 등)

shell/터미널 접근이 가능한 AI면 `ida_cli.py`를 직접 호출할 수 있습니다. `CLAUDE.md`에 전체 명령어 레퍼런스가 있으므로 AI에게 참고하게 하면 됩니다.

### 명령어 레퍼런스

명령어는 주로 AI가 사용하며, 참고용으로 정리합니다.

#### 인스턴스 관리

| 명령어 | 설명 |
| ------- | ---- |
| `start <binary>` | 분석 인스턴스 시작 |
| `stop <id>` | 인스턴스 종료 |
| `wait <id>` | 분석 완료 대기 |
| `list` | 실행 중인 인스턴스 목록 |
| `status [<id>]` | 인스턴스 상태 확인 |
| `logs <id>` | 인스턴스 로그 보기 |
| `cleanup` | 비정상 인스턴스 정리 |

#### 분석 (24개 API)

| 명령어 | 설명 |
| ------- | ---- |
| `functions` | 함수 목록 |
| `strings` | 문자열 목록 |
| `imports` / `exports` | imports/exports 목록 |
| `segments` | 세그먼트 목록 |
| `decompile <addr\|name>` | 함수 디컴파일 |
| `disasm <addr\|name>` | 디스어셈블 |
| `xrefs <addr>` | 크로스 레퍼런스 |
| `find_func <name>` | 함수 검색 |
| `func_info <addr\|name>` | 함수 상세 정보 |
| `bytes <addr> <size>` | Raw 바이트 읽기 |
| `find_pattern <hex>` | 바이트 패턴 검색 |

#### 수정

| 명령어 | 설명 |
| ------- | ---- |
| `rename <addr> <name>` | 심볼 이름 변경 |
| `comment <addr> "text"` | 주석 추가 |
| `save` | 데이터베이스 저장 |

#### 공통 옵션

| 옵션 | 설명 |
| ---- | ---- |
| `--json` | JSON 출력 |
| `-i <id>` | 인스턴스 ID 지정 |
| `-b <hint>` | 바이너리 이름으로 자동 선택 |
| `--out FILE` | 결과를 파일로 저장 |

### 지원 포맷

PE, ELF, Mach-O, FAT, .so, dylib, Raw binary, Intel HEX, SREC

디컴파일러: x86/x64, ARM/ARM64, MIPS, PowerPC, RISC-V

### 라이선스

**Apache License 2.0** — [LICENSE](LICENSE) 참조.

이 프로젝트를 사용하려면 별도로 유효한 **IDA Pro 라이선스**가 필요합니다. Hex-Rays 디컴파일러 라이선스는 선택 사항.
