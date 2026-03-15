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
| Python | 3.12+ |
| OS | Windows, Linux, macOS |

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
# Windows
set IDADIR=C:\Program Files\IDA Professional 9.3
# Linux/macOS
export IDADIR=/opt/ida-9.3
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

> **Note**: `%USERPROFILE%` is automatically mapped to `$HOME` on Linux/macOS. On Linux/macOS, set `install_dir` to your IDA path (e.g., `/opt/ida-9.3`).

#### Step 6. Global CLI (optional, recommended)

Add `bin/` to your system PATH so you can run `ida-cli` from any directory:

```bash
# Windows (PowerShell, permanent)
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";<headless-ida>\bin", "User")

# Linux/macOS
echo 'export PATH="$PATH:<headless-ida>/bin"' >> ~/.bashrc
source ~/.bashrc
```

After this, you can use `ida-cli` instead of `python tools/ida_cli.py` from any directory.

#### Step 7. Test it works

```bash
# Start an instance with any binary
ida-cli start ./samples/target.exe --idb-dir .

# Check status
ida-cli list

# Stop
ida-cli stop <id>
```

If you see `Instance started: id=xxxx` and the instance appears in `list`, the setup is complete.

### AI Integration

Once the environment is set up, AI assistants use `ida_cli.py` commands via shell. You don't need to memorize these — the AI handles it.

#### Claude Code

1. Copy the skill file to your project:

```bash
# Create skill directory
mkdir -p .claude/commands

# Copy skill file
cp <headless-ida>/tools/ida_cli.py tools/
cp <headless-ida>/.claude/commands/ida.md .claude/commands/
```

2. Copy `CLAUDE.md` to your project root (AI reads this for command reference):

```bash
cp <headless-ida>/CLAUDE.md .
```

3. Use in Claude Code:

```text
/ida ./target.so
```

Claude will automatically start an instance, analyze the binary, and report findings.

> **Note**: `ida.md` and `CLAUDE.md` are templates. Modify paths, analysis strategies, and options to fit your project and environment.

#### Other AI Tools (Cursor, GPT, etc.)

Any AI with shell/terminal access can call `ida_cli.py` directly. Add `CLAUDE.md` content to your AI's system prompt or project context so it knows the available commands.

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

#### Analysis

| Command | Description |
| ------- | ----------- |
| `functions` | List functions |
| `strings` | List strings |
| `imports` / `exports` | List imports/exports |
| `segments` | List segments |
| `decompile <addr\|name>` | Decompile function |
| `decompile_batch <addrs>` | Batch decompile multiple functions |
| `disasm <addr\|name>` | Disassemble |
| `xrefs <addr>` | Cross-references |
| `find_func <name>` | Search functions |
| `func_info <addr\|name>` | Function details |
| `imagebase` | Get image base address |
| `bytes <addr> <size>` | Read raw bytes |
| `find_pattern <hex>` | Byte pattern search |
| `comments <addr>` | Get comments at address |
| `methods <class>` | List class methods |
| `summary` | Comprehensive binary overview (segments, imports, functions, strings) |
| `search-code <query>` | Search within decompiled pseudocode |
| `diff <a> <b>` | Compare functions between two instances |
| `code-diff <inst_a> <inst_b>` | Diff decompiled pseudocode between instances |
| `batch <dir>` | Batch analyze all binaries in a directory |
| `profile run <name>` | Run analysis profile (malware, firmware, vuln) |
| `bookmark add <addr> <tag>` | Tag an address with a bookmark |
| `bookmark list [--tag]` | List bookmarks |

#### Modification

| Command | Description |
| ------- | ----------- |
| `rename <addr> <name>` | Rename symbol |
| `set_type <addr> <type>` | Set function/variable type |
| `comment <addr> "text"` | Add comment |
| `save` | Save database |
| `exec <expr>` | Execute IDAPython expression (disabled by default) |
| `patch <addr> <hex bytes>` | Patch bytes at address |
| `auto-rename [--apply]` | Heuristic rename sub_ functions |
| `shell` | Interactive IDA Python REPL |

#### Structs & Types

| Command | Description |
| ------- | ----------- |
| `structs list [--filter]` | List all structs/unions |
| `structs show <name>` | Show struct details with members |
| `structs create <name> --members` | Create new struct |
| `enums list [--filter]` | List all enumerations |
| `enums show <name>` | Show enum details with members |
| `enums create <name> --members` | Create new enum |
| `search-const <value>` | Search for constant/immediate values |
| `callgraph <addr> [--depth] [--format]` | Generate function call graph (mermaid/DOT) |
| `vtables [--min-entries]` | Detect virtual function tables |
| `sigs list` | List available FLIRT signatures |
| `sigs apply <name>` | Apply FLIRT signature |

#### Report & Export

| Command | Description |
| ------- | ----------- |
| `report <output.md>` | Generate markdown analysis report |
| `report <output.html>` | Generate HTML analysis report |
| `report <out> --functions <addrs>` | Include function decompilations in report |
| `decompile <addr> --out result.md` | Decompile to markdown format |
| `annotations export --output <file>` | Export names/comments/types as JSON |
| `annotations import <file>` | Import annotations from JSON |
| `snapshot save [--description]` | Save IDB snapshot |
| `snapshot list` | List available snapshots |
| `snapshot restore <file>` | Restore IDB from snapshot |
| `export-script --output <file>` | Generate reproducible IDAPython script |
| `compare <binary_a> <binary_b>` | Patch diff two binary versions |
| `code-diff <inst_a> <inst_b>` | Diff decompiled pseudocode between instances |

#### Utilities

| Command | Description |
| ------- | ----------- |
| `update` | Self-update from git repository |
| `completions --shell <bash\|zsh\|powershell>` | Generate shell tab-completion script |

#### Common Options

| Option | Description |
| ------ | ----------- |
| `--json` | JSON output |
| `-i <id>` | Specify instance ID |
| `-b <hint>` | Auto-select by binary name |
| `--idb-dir <path>` | Save IDB to specified directory (or set `IDA_IDB_DIR` env var) |
| `--with-xrefs` | Include callers/callees in decompile output |

### Supported Formats

PE, ELF, Mach-O, FAT, .so, dylib, Raw binary, Intel HEX, SREC

Decompiler: x86/x64, ARM/ARM64, MIPS, PowerPC, RISC-V, V850, ARC

### License

**Apache License 2.0** — See [LICENSE](LICENSE).

A valid **IDA Pro license** is required separately. Hex-Rays decompiler license is optional (required for `decompile` commands).

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
| Python | 3.12+ |
| OS | Windows, Linux, macOS |

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
# Windows
set IDADIR=C:\Program Files\IDA Professional 9.3
# Linux/macOS
export IDADIR=/opt/ida-9.3
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

> **참고**: `%USERPROFILE%`은 Linux/macOS에서 자동으로 `$HOME`으로 매핑됩니다. Linux/macOS에서는 `install_dir`을 IDA 경로로 설정하세요 (예: `/opt/ida-9.3`).

#### Step 6. 글로벌 CLI (선택, 권장)

`bin/` 디렉토리를 시스템 PATH에 추가하면 어디서든 `ida-cli` 명령어로 실행 가능:

```bash
# Windows (PowerShell, 영구 설정)
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";<headless-ida>\bin", "User")

# Linux/macOS
echo 'export PATH="$PATH:<headless-ida>/bin"' >> ~/.bashrc
source ~/.bashrc
```

설정 후 `python tools/ida_cli.py` 대신 `ida-cli`로 어디서든 실행 가능합니다.

#### Step 7. 동작 테스트

```bash
# 아무 바이너리로 인스턴스 시작 (IDB를 현재 폴더에 저장)
ida-cli start ./samples/target.exe --idb-dir .

# 상태 확인
ida-cli list

# 종료
ida-cli stop <id>
```

`Instance started: id=xxxx`가 출력되고 `list`에 나타나면 환경 구축 완료.

### AI 연동

환경 구축 완료 후, AI 어시스턴트가 shell로 `ida_cli.py` 명령어를 호출합니다. 사용자가 명령어를 외울 필요 없습니다.

#### Claude Code

프로젝트에 스킬 파일을 복사합니다:

```bash
# 스킬 디렉토리 생성
mkdir -p .claude/commands

# 스킬 파일 복사
cp <headless-ida>/tools/ida_cli.py tools/
cp <headless-ida>/.claude/commands/ida.md .claude/commands/
```

프로젝트 루트에 `CLAUDE.md` 복사 (AI가 명령어 레퍼런스로 참조):

```bash
cp <headless-ida>/CLAUDE.md .
```

Claude Code에서 사용:

```text
/ida ./target.so
```

Claude가 자동으로 인스턴스를 시작하고, 바이너리를 분석하고, 결과를 보고합니다.

> **참고**: `ida.md`와 `CLAUDE.md`는 템플릿입니다. 경로, 분석 전략, 옵션 등을 본인의 프로젝트와 환경에 맞게 수정하세요.

#### 다른 AI 도구 (Cursor, GPT 등)

shell/터미널 접근이 가능한 AI면 `ida_cli.py`를 직접 호출할 수 있습니다. `CLAUDE.md` 내용을 AI의 system prompt나 프로젝트 컨텍스트에 추가하면 됩니다.

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

#### 분석

| 명령어 | 설명 |
| ------- | ---- |
| `functions` | 함수 목록 |
| `strings` | 문자열 목록 |
| `imports` / `exports` | imports/exports 목록 |
| `segments` | 세그먼트 목록 |
| `decompile <addr\|name>` | 함수 디컴파일 |
| `decompile_batch <addrs>` | 여러 함수 일괄 디컴파일 |
| `disasm <addr\|name>` | 디스어셈블 |
| `xrefs <addr>` | 크로스 레퍼런스 |
| `find_func <name>` | 함수 검색 |
| `func_info <addr\|name>` | 함수 상세 정보 |
| `imagebase` | 이미지 베이스 주소 |
| `bytes <addr> <size>` | Raw 바이트 읽기 |
| `find_pattern <hex>` | 바이트 패턴 검색 |
| `comments <addr>` | 주소의 주석 조회 |
| `methods <class>` | 클래스 메서드 목록 |
| `summary` | 바이너리 종합 개요 (세그먼트, 임포트, 함수, 문자열) |
| `search-code <query>` | 디컴파일된 의사코드 내 검색 |
| `diff <a> <b>` | 두 인스턴스 간 함수 비교 |
| `code-diff <inst_a> <inst_b>` | 두 인스턴스 간 디컴파일 코드 비교 |
| `batch <dir>` | 디렉토리 내 바이너리 일괄 분석 |
| `profile run <name>` | 분석 프로필 실행 (malware, firmware, vuln) |
| `bookmark add <addr> <tag>` | 주소에 북마크 태그 추가 |
| `bookmark list [--tag]` | 북마크 목록 조회 |

#### 수정

| 명령어 | 설명 |
| ------- | ---- |
| `rename <addr> <name>` | 심볼 이름 변경 |
| `set_type <addr> <type>` | 함수/변수 타입 설정 |
| `comment <addr> "text"` | 주석 추가 |
| `save` | 데이터베이스 저장 |
| `exec <expr>` | IDAPython 표현식 실행 (기본 비활성화) |
| `patch <addr> <hex bytes>` | 주소에 바이트 패치 |
| `auto-rename [--apply]` | sub_ 함수 휴리스틱 이름 추정 |
| `shell` | 대화형 IDA Python REPL |

#### 구조체 & 타입

| 명령어 | 설명 |
| ------- | ---- |
| `structs list [--filter]` | 구조체/유니온 목록 조회 |
| `structs show <name>` | 구조체 상세 (멤버 포함) |
| `structs create <name> --members` | 새 구조체 생성 |
| `enums list [--filter]` | 열거형 목록 조회 |
| `enums show <name>` | 열거형 상세 (멤버 포함) |
| `enums create <name> --members` | 새 열거형 생성 |
| `search-const <value>` | 상수/즉시값 검색 |
| `callgraph <addr> [--depth] [--format]` | 함수 콜그래프 생성 (mermaid/DOT) |
| `vtables [--min-entries]` | 가상 함수 테이블 탐지 |
| `sigs list` | FLIRT 시그니처 목록 |
| `sigs apply <name>` | FLIRT 시그니처 적용 |

#### 리포트 & 내보내기

| 명령어 | 설명 |
| ------- | ---- |
| `report <output.md>` | 마크다운 분석 리포트 생성 |
| `report <output.html>` | HTML 분석 리포트 생성 |
| `report <out> --functions <addrs>` | 함수 디컴파일 포함 리포트 |
| `decompile <addr> --out result.md` | 마크다운 형식으로 디컴파일 |
| `annotations export --output <file>` | 이름/주석/타입 JSON 내보내기 |
| `annotations import <file>` | JSON에서 분석 결과 가져오기 |
| `snapshot save [--description]` | IDB 스냅샷 저장 |
| `snapshot list` | 스냅샷 목록 조회 |
| `snapshot restore <file>` | 스냅샷에서 IDB 복원 |
| `export-script --output <file>` | 재현 가능한 IDAPython 스크립트 생성 |
| `compare <binary_a> <binary_b>` | 두 바이너리 패치 디핑 |
| `code-diff <inst_a> <inst_b>` | 두 인스턴스 간 디컴파일 코드 비교 |

#### 유틸리티

| 명령어 | 설명 |
| ------- | ---- |
| `update` | git 저장소에서 자동 업데이트 |
| `completions --shell <bash\|zsh\|powershell>` | 셸 탭 자동완성 스크립트 생성 |

#### 공통 옵션

| 옵션 | 설명 |
| ---- | ---- |
| `--json` | JSON 출력 |
| `-i <id>` | 인스턴스 ID 지정 |
| `-b <hint>` | 바이너리 이름으로 자동 선택 |
| `--idb-dir <path>` | IDB 저장 디렉토리 지정 (`IDA_IDB_DIR` 환경변수로도 설정 가능) |
| `--with-xrefs` | 디컴파일 시 호출자/피호출자 정보 포함 |

### 지원 포맷

PE, ELF, Mach-O, FAT, .so, dylib, Raw binary, Intel HEX, SREC

디컴파일러: x86/x64, ARM/ARM64, MIPS, PowerPC, RISC-V, V850, ARC

### 라이선스

**Apache License 2.0** — [LICENSE](LICENSE) 참조.

이 프로젝트를 사용하려면 별도로 유효한 **IDA Pro 라이선스**가 필요합니다. Hex-Rays 디컴파일러 라이선스는 선택 사항 (`decompile` 명령어 사용 시 필요).
