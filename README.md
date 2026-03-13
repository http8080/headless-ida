# Headless IDA

[한국어](#한국어) | [English](#english)

---

## English

A CLI-based binary analysis system powered by **idalib** (Hex-Rays official headless library), eliminating the need for IDA Pro GUI.

Integrates with Claude Code's bash_tool for AI-driven automated binary analysis.

### Architecture

```text
User/Claude → ida_cli.py → HTTP JSON-RPC → ida_server.py (import idapro)
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
| **AI tool compatibility** | Works with any AI that has shell access (Claude Code, Cursor, etc.) | Tied to MCP-compatible clients only |
| **Deployment** | Single `.py` file, zero config | Server manifest + schema registration needed |
| **Transparency** | Raw JSON request/response visible in logs | Abstracted behind protocol layers |
| **idalib constraint** | Single-thread `HTTPServer` maps 1:1 to idalib's requirement | MCP's async model conflicts with idalib's single-thread restriction |
| **Context window** | Zero overhead — just bash commands | Tool schemas for all MCP methods loaded into AI context, consuming tokens |
| **Script automation** | Directly callable from bash/Python scripts | Requires MCP client library |

> **TL;DR** — For a tool that wraps a single-threaded native library (idalib), a simple HTTP server is more reliable and portable than MCP. Any AI assistant with bash/shell access can use it immediately.

### Requirements

| Component | Version |
| --------- | ------- |
| IDA Pro | 9.1+ (idalib + `open_database(args=...)` support) |
| Python | 3.12 or 3.13 (must match IDA's bundled version) |
| OS | Windows 10/11 |

> **Warning**: Python 3.14 is incompatible — IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14").

### Installation

```bash
# 1. Install idapro package (whl included in IDA install directory)
pip install "<IDA_DIR>/idalib/python/idapro-*.whl"

# 2. Register IDA install path (choose one)
python "<IDA_DIR>/idalib/python/py-activate-idalib.py"
# or
set IDADIR=C:\Program Files\IDA Professional 9.3

# 3. Install dependencies
pip install requests psutil

# 4. Verify environment
python tools/ida_cli.py --check

# 5. Initialize (create directories)
python tools/ida_cli.py --init
```

### Quick Start

```bash
# Start instance
python tools/ida_cli.py start ./samples/target.so
# Instance started: id=a1b2

# Wait for analysis to complete
python tools/ida_cli.py wait a1b2

# List functions
python tools/ida_cli.py functions --filter main

# Decompile
python tools/ida_cli.py decompile main --out /tmp/main.c

# Search strings
python tools/ida_cli.py strings --filter "password" --out /tmp/strings.txt

# Cross-references
python tools/ida_cli.py xrefs 0x401000 --direction both

# Stop instance
python tools/ida_cli.py stop a1b2
```

### Commands

#### Instance Management

```bash
ida_cli.py start   <binary> [--arch <arch>] [--fresh] [--force] [--idb-dir <path>]
ida_cli.py stop    <id>
ida_cli.py status  [<id>]
ida_cli.py wait    <id> [--timeout 300]
ida_cli.py list
ida_cli.py logs    <id> [--tail N]
ida_cli.py cleanup [--dry-run]
```

#### Analysis

```bash
ida_cli.py functions    [--count N] [--filter STR] [--out FILE]
ida_cli.py strings      [--count N] [--filter STR] [--out FILE]
ida_cli.py imports      [--count N] [--out FILE]
ida_cli.py exports      [--count N] [--out FILE]
ida_cli.py segments     [--out FILE]
ida_cli.py decompile    <addr|name> [--out FILE]
ida_cli.py disasm       <addr|name> [--count N] [--out FILE]
ida_cli.py xrefs        <addr> [--direction to|from|both] [--out FILE]
ida_cli.py find_func    <name> [--regex] [--max N]
ida_cli.py func_info    <addr|name>
ida_cli.py imagebase
ida_cli.py bytes        <addr> <size>
ida_cli.py find_pattern <hex_pattern> [--max N]
```

#### Modification

```bash
ida_cli.py rename  <addr> <new_name>
ida_cli.py comment <addr> "text" [--type func]
ida_cli.py save
```

#### Global Options

| Option | Description |
| ------ | ----------- |
| `--json` | JSON output mode |
| `-i <id>` | Specify instance ID directly |
| `-b <hint>` | Auto-select instance by binary name substring |
| `--out FILE` | Save output to file (saves context window) |
| `--idb-dir <path>` | Override IDB save directory (start only) |

### Project Structure

```text
tools/
├── config.json      # Global settings (paths, analysis params, security)
├── common.py        # Shared module (config, registry, lock, file_md5)
├── arch_detect.py   # Binary header parsing (ELF, PE, Mach-O, FAT)
├── ida_server.py    # idalib HTTP JSON-RPC server (24 APIs)
└── ida_cli.py       # CLI entry point (instance management + analysis proxy)
```

#### Runtime Files

```text
%USERPROFILE%\.ida-headless\
├── ida_servers.json       # Instance registry
├── auth_token             # Auth tokens (instance_id:port:token)
├── idb\                   # IDB files (.i64)
└── logs\                  # Instance logs
```

### Configuration

Place in `tools/config.json` or `%USERPROFILE%\.ida-headless\config.json`:

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
    "max_instances": 3,
    "open_db_timeout": 600,
    "request_timeout": 35
  },
  "security": {
    "exec_enabled": false
  }
}
```

### Supported Formats

| Platform | Formats |
| -------- | ------- |
| Windows | PE32, PE64, .NET, DOS MZ |
| Linux | ELF32, ELF64 |
| macOS/iOS | Mach-O 32/64, FAT, dylib |
| Android | ELF ARM/ARM64/x86, .so |
| Firmware | Raw binary, Intel HEX, SREC |

#### Decompiler Architectures

| Architecture | 32-bit | 64-bit |
| ------------ | ------ | ------ |
| x86 | hexrays | hexx64 |
| ARM | hexarm | hexarm64 |
| MIPS | hexmips | hexmips64 |
| PowerPC | hexppc | hexppc64 |
| RISC-V | hexrv | hexrv64 |

### Claude Code Integration

Register as a Claude Code skill to start automated analysis with `/ida <binary>`.

```bash
# Skill file included at .claude/commands/ida.md
# Usage: /ida ./target.so in Claude Code
```

### License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

A valid **IDA Pro license** is required separately to use this project.
Hex-Rays decompiler license is optional (assembly-only mode without it).

---

## 한국어

IDA Pro GUI 없이 **idalib** (Hex-Rays 공식 헤드리스 라이브러리)을 사용하여 CLI에서 바이너리 분석을 수행하는 시스템.

Claude Code의 bash_tool과 연동하여 AI 기반 자동 바이너리 분석에 활용할 수 있습니다.

### 아키텍처

```text
User/Claude → ida_cli.py → HTTP JSON-RPC → ida_server.py (import idapro)
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
| **AI 도구 호환성** | shell 접근 가능한 모든 AI에서 동작 (Claude Code, Cursor 등) | MCP 호환 클라이언트에만 종속 |
| **배포** | `.py` 파일 하나, 별도 설정 없음 | 서버 manifest + 스키마 등록 필요 |
| **투명성** | Raw JSON 요청/응답이 로그에 그대로 노출 | 프로토콜 레이어 뒤에 추상화됨 |
| **idalib 제약** | 단일 스레드 `HTTPServer`가 idalib 제약과 1:1 매핑 | MCP의 async 모델이 idalib 단일 스레드 제약과 충돌 |
| **컨텍스트 윈도우** | 오버헤드 없음 — bash 명령어만 사용 | 모든 MCP 메서드의 tool schema가 AI 컨텍스트에 로드되어 토큰 소모 |
| **스크립트 자동화** | bash/Python 스크립트에서 바로 호출 가능 | MCP 클라이언트 라이브러리 필요 |

> **요약** — 단일 스레드 네이티브 라이브러리(idalib)를 감싸는 도구에는 MCP보다 단순한 HTTP 서버가 더 안정적이고 이식성이 높습니다. bash/shell 접근이 가능한 모든 AI 어시스턴트에서 즉시 사용할 수 있습니다.

### 요구사항

| 항목 | 버전 |
| ---- | ---- |
| IDA Pro | 9.1 이상 (idalib + `open_database(args=...)` 지원) |
| Python | 3.12 또는 3.13 (IDA 번들 버전과 일치 필수) |
| OS | Windows 10/11 |

> **Warning**: Python 3.14는 IDA 9.3 Known Issue ("PySide6 crashes under Python 3.14")로 비호환.

### 설치

```bash
# 1. idapro 패키지 설치 (IDA 설치 디렉토리에 포함된 whl)
pip install "<IDA_DIR>/idalib/python/idapro-*.whl"

# 2. IDA 설치 경로 등록 (택일)
python "<IDA_DIR>/idalib/python/py-activate-idalib.py"
# 또는
set IDADIR=C:\Program Files\IDA Professional 9.3

# 3. 의존 패키지 설치
pip install requests psutil

# 4. 환경 검증
python tools/ida_cli.py --check

# 5. 초기 설정 (디렉토리 생성)
python tools/ida_cli.py --init
```

### 빠른 시작

```bash
# 인스턴스 시작
python tools/ida_cli.py start ./samples/target.so
# Instance started: id=a1b2

# 분석 완료 대기
python tools/ida_cli.py wait a1b2

# 함수 목록
python tools/ida_cli.py functions --filter main

# 디컴파일
python tools/ida_cli.py decompile main --out /tmp/main.c

# 문자열 검색
python tools/ida_cli.py strings --filter "password" --out /tmp/strings.txt

# 크로스 레퍼런스
python tools/ida_cli.py xrefs 0x401000 --direction both

# 종료
python tools/ida_cli.py stop a1b2
```

### 명령어

#### 인스턴스 관리

```bash
ida_cli.py start   <binary> [--arch <arch>] [--fresh] [--force] [--idb-dir <path>]
ida_cli.py stop    <id>
ida_cli.py status  [<id>]
ida_cli.py wait    <id> [--timeout 300]
ida_cli.py list
ida_cli.py logs    <id> [--tail N]
ida_cli.py cleanup [--dry-run]
```

#### 분석

```bash
ida_cli.py functions    [--count N] [--filter STR] [--out FILE]
ida_cli.py strings      [--count N] [--filter STR] [--out FILE]
ida_cli.py imports      [--count N] [--out FILE]
ida_cli.py exports      [--count N] [--out FILE]
ida_cli.py segments     [--out FILE]
ida_cli.py decompile    <addr|name> [--out FILE]
ida_cli.py disasm       <addr|name> [--count N] [--out FILE]
ida_cli.py xrefs        <addr> [--direction to|from|both] [--out FILE]
ida_cli.py find_func    <name> [--regex] [--max N]
ida_cli.py func_info    <addr|name>
ida_cli.py imagebase
ida_cli.py bytes        <addr> <size>
ida_cli.py find_pattern <hex_pattern> [--max N]
```

#### 수정

```bash
ida_cli.py rename  <addr> <new_name>
ida_cli.py comment <addr> "text" [--type func]
ida_cli.py save
```

#### 글로벌 옵션

| Option | Description |
| ------ | ----------- |
| `--json` | JSON 출력 모드 |
| `-i <id>` | 인스턴스 ID 직접 지정 |
| `-b <hint>` | 바이너리 이름 일부로 인스턴스 자동 선택 |
| `--out FILE` | 결과를 파일로 저장 (컨텍스트 절약) |
| `--idb-dir <path>` | IDB 저장 디렉토리 오버라이드 (start 전용) |

### 프로젝트 구조

```text
tools/
├── config.json      # 전역 설정 (경로, 분석 파라미터, 보안)
├── common.py        # 공유 모듈 (config, registry, lock, file_md5)
├── arch_detect.py   # 바이너리 헤더 파싱 (ELF, PE, Mach-O, FAT)
├── ida_server.py    # idalib HTTP JSON-RPC 서버 (24개 API)
└── ida_cli.py       # CLI 진입점 (인스턴스 관리 + 분석 프록시)
```

#### 런타임 파일

```text
%USERPROFILE%\.ida-headless\
├── ida_servers.json       # 인스턴스 레지스트리
├── auth_token             # 인증 토큰 (instance_id:port:token)
├── idb\                   # IDB 파일 (.i64)
└── logs\                  # 인스턴스 로그
```

### 설정

`tools/config.json` 또는 `%USERPROFILE%\.ida-headless\config.json`에 설정:

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
    "max_instances": 3,
    "open_db_timeout": 600,
    "request_timeout": 35
  },
  "security": {
    "exec_enabled": false
  }
}
```

### 지원 포맷

| Platform | Formats |
| -------- | ------- |
| Windows | PE32, PE64, .NET, DOS MZ |
| Linux | ELF32, ELF64 |
| macOS/iOS | Mach-O 32/64, FAT, dylib |
| Android | ELF ARM/ARM64/x86, .so |
| Firmware | Raw binary, Intel HEX, SREC |

#### 디컴파일러 아키텍처

| Architecture | 32-bit | 64-bit |
| ------------ | ------ | ------ |
| x86 | hexrays | hexx64 |
| ARM | hexarm | hexarm64 |
| MIPS | hexmips | hexmips64 |
| PowerPC | hexppc | hexppc64 |
| RISC-V | hexrv | hexrv64 |

### Claude Code 연동

Claude Code 스킬로 등록하여 `/ida <binary>` 명령으로 자동 분석을 시작할 수 있습니다.

```bash
# .claude/commands/ida.md 스킬 파일 포함
# 사용법: Claude Code에서 /ida ./target.so
```

### 라이선스

이 프로젝트는 **Apache License 2.0**으로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)를 참조하세요.

이 프로젝트를 사용하려면 별도로 유효한 **IDA Pro 라이선스**가 필요합니다.
Hex-Rays 디컴파일러 라이선스는 선택 사항 (없으면 어셈블리 전용 모드).
