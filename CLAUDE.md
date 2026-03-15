# Headless IDA Project

## 프로젝트 개요
IDA Pro GUI 없이 idalib(Hex-Rays 공식 헤드리스 라이브러리)을 사용하여
Claude가 bash_tool만으로 바이너리 분석을 수행하는 시스템.

## 아키텍처
```
Claude → bash_tool → ida_cli.py → HTTP JSON-RPC → ida_server.py (import idapro)
```
- MCP 레이어 없음 — 순수 HTTP JSON-RPC
- 단일 스레드 HTTPServer (idalib 단일 스레드 제약)
- .i64 재사용으로 반복 분석 시간 단축
- Windows, Linux, macOS 지원

## 핵심 파일
- `tools/ida_cli.py` — CLI 진입점 (thin wrapper → `cli/` 패키지)
- `tools/ida_server.py` — 서버 진입점 (thin wrapper → `server/` 패키지)
- `tools/cli/` — CLI 패키지 (main.py: argparse/dispatch, core.py: 인스턴스 관리, commands.py: 분석 명령)
- `tools/server/` — 서버 패키지 (framework.py: HTTP/lifecycle, handlers.py: RPC 핸들러)
- `tools/shared/` — 공유 패키지 (common.py: config/registry/lock, arch_detect.py: 바이너리 헤더 파싱, config.json: 설정)

## 바이너리 분석 시 ida_cli.py 사용법

### 인스턴스 관리
```bash
python tools/ida_cli.py start <binary>       # 인스턴스 시작 (--idb-dir로 저장 경로 지정)
python tools/ida_cli.py wait <id>             # 분석 완료 대기
python tools/ida_cli.py stop <id>             # 종료
python tools/ida_cli.py list                  # 활성 인스턴스 목록
python tools/ida_cli.py status [<id>]         # 인스턴스 상태 확인
python tools/ida_cli.py logs <id>             # 로그 보기
python tools/ida_cli.py cleanup               # 비정상 인스턴스 정리
python tools/ida_cli.py batch <dir>           # 디렉토리 내 바이너리 일괄 분석
```

### 정찰 명령어
```bash
python tools/ida_cli.py summary               # 종합 개요
python tools/ida_cli.py functions [--count N] [--filter STR] [--offset N]
python tools/ida_cli.py strings [--count N] [--filter STR]
python tools/ida_cli.py imports [--count N]
python tools/ida_cli.py exports
python tools/ida_cli.py segments
python tools/ida_cli.py imagebase
```

### 분석 명령어
```bash
python tools/ida_cli.py decompile <addr|name> [--out FILE] [--with-xrefs]
python tools/ida_cli.py decompile_batch <addr1> <addr2> ... [--out FILE]
python tools/ida_cli.py decompile-all --out FILE [--filter STR]
python tools/ida_cli.py disasm <addr|name> [--count N]
python tools/ida_cli.py xrefs <addr> [--direction to|from|both]
python tools/ida_cli.py find_func <name> [--regex]
python tools/ida_cli.py func_info <addr|name>
python tools/ida_cli.py bytes <addr> <size>
python tools/ida_cli.py find_pattern <hex_pattern> [--max N]
python tools/ida_cli.py comments <addr>
python tools/ida_cli.py methods
python tools/ida_cli.py search-code <query> [--max N]
python tools/ida_cli.py search-const <value> [--max N]
python tools/ida_cli.py callgraph <addr|name> [--depth N] [--direction callees|callers] [--format mermaid|dot]
python tools/ida_cli.py cross-refs <addr|name> [--depth N] [--direction to|from|both] [--format mermaid|dot]
python tools/ida_cli.py basic-blocks <addr|name> [--format mermaid|dot] [--graph-only]
python tools/ida_cli.py func-similarity <addrA> <addrB>
python tools/ida_cli.py strings-xrefs [--filter STR] [--min-refs N] [--max N]
python tools/ida_cli.py data-refs [--segment NAME] [--filter STR] [--max N]
python tools/ida_cli.py type-info list [--kind typedef|funcptr|struct|enum|other] [--count N]
python tools/ida_cli.py type-info show <name>
```

### 수정 명령어
```bash
python tools/ida_cli.py rename <addr> <new_name>
python tools/ida_cli.py set_type <addr> "C type declaration"
python tools/ida_cli.py comment <addr> "text"
python tools/ida_cli.py patch <addr> <hex bytes>
python tools/ida_cli.py auto-rename [--apply] [--max-funcs N]
python tools/ida_cli.py save
python tools/ida_cli.py exec "<idapython_expr>"    # config에서 exec_enabled=true 필요
```

### 구조체 & 타입
```bash
python tools/ida_cli.py structs list [--filter STR] [--count N] [--offset N]
python tools/ida_cli.py structs show <name>
python tools/ida_cli.py structs create <name> --members "field1:4" "field2:8"
python tools/ida_cli.py enums list [--filter STR] [--count N] [--offset N]
python tools/ida_cli.py enums show <name>
python tools/ida_cli.py enums create <name> --members "OK=0" "ERR=1"
python tools/ida_cli.py vtables [--min-entries N]
python tools/ida_cli.py sigs list
python tools/ida_cli.py sigs apply <name>
```

### 리포트 & 내보내기
```bash
python tools/ida_cli.py report <output.md|.html> [--functions <addrs>]
python tools/ida_cli.py annotations export --output <file>
python tools/ida_cli.py annotations import <file>
python tools/ida_cli.py snapshot save [--description TEXT]
python tools/ida_cli.py snapshot list
python tools/ida_cli.py snapshot restore <filename>
python tools/ida_cli.py export-script --output <file>
python tools/ida_cli.py bookmark add <addr> <tag> [--note TEXT]
python tools/ida_cli.py bookmark list [--tag TAG]
python tools/ida_cli.py bookmark remove <addr>
```

### 멀티 인스턴스
```bash
python tools/ida_cli.py diff <inst_a> <inst_b>
python tools/ida_cli.py code-diff <inst_a> <inst_b> [--functions func1 func2]
python tools/ida_cli.py compare <binary_a> <binary_b> [--out diff.json]
python tools/ida_cli.py profile run <malware|firmware|vuln>
```

### 글로벌 옵션
- `--json` : JSON 출력 모드
- `-i <id>` : 인스턴스 ID 지정
- `-b <hint>` : 바이너리 이름으로 자동 선택
- `--out <file>` : 결과를 파일로 저장 (컨텍스트 절약)

### start 전용 옵션
- `--fresh` : 기존 .i64를 무시하고 처음부터 분석
- `--force` : 동일 바이너리 중복 인스턴스 허용
- `--idb-dir <경로>` : IDB 저장 디렉토리 오버라이드

## 디컴파일러 지원 아키텍처
x86/x64, ARM/ARM64, MIPS, PowerPC, RISC-V, V850, ARC

## 주의사항
- IDA 모듈(idapro, idc 등)은 런타임에만 사용 가능 — IDE 정적 분석 경고 무시
- `exec` 명령어는 `shared/config.json`의 `security.exec_enabled`가 true일 때만 동작
- `%USERPROFILE%`은 Linux/macOS에서 자동으로 `$HOME`으로 매핑됨
