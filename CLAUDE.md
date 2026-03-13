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

## 핵심 파일
- `tools/ida_cli.py` — Claude용 유일한 진입점 (인스턴스 관리 + 분석 프록시)
- `tools/ida_server.py` — idalib 기반 HTTP JSON-RPC 서버 (24개 API)
- `tools/common.py` — 공유 모듈 (config, registry, lock, file_md5, auth_token)
- `tools/config.json` — 전역 설정
- `tools/arch_detect.py` — 바이너리 헤더 파싱

## 바이너리 분석 시 ida_cli.py 사용법

### 인스턴스 시작/종료
```bash
python tools/ida_cli.py start <binary>       # 인스턴스 시작 (--idb-dir로 저장 경로 지정 가능)
python tools/ida_cli.py wait <id>             # 분석 완료 대기
python tools/ida_cli.py stop <id>             # 종료
python tools/ida_cli.py list                  # 활성 인스턴스 목록
```

### 분석 명령어 (인스턴스 1개일 때 -i 생략 가능)
```bash
python tools/ida_cli.py functions [--count N] [--filter STR]
python tools/ida_cli.py strings [--count N] [--filter STR]
python tools/ida_cli.py imports [--count N]
python tools/ida_cli.py exports [--count N]
python tools/ida_cli.py segments
python tools/ida_cli.py decompile <addr|name> [--out FILE]
python tools/ida_cli.py disasm <addr|name> [--count N]
python tools/ida_cli.py xrefs <addr> [--direction to|from|both]
python tools/ida_cli.py find_func <name> [--regex]
python tools/ida_cli.py func_info <addr|name>
python tools/ida_cli.py imagebase
python tools/ida_cli.py bytes <addr> <size>
python tools/ida_cli.py find_pattern <hex_pattern> [--max N]
```

### 수정 명령어
```bash
python tools/ida_cli.py rename <addr> <new_name>
python tools/ida_cli.py comment <addr> "text" [--type func]
python tools/ida_cli.py save
```

### 글로벌 옵션
- `--json` : JSON 출력 모드
- `-i <id>` : 인스턴스 ID 지정
- `-b <hint>` : 바이너리 이름으로 자동 선택
- `--out FILE` : 결과를 파일로 저장 (컨텍스트 절약)

### start 전용 옵션

- `--idb-dir <경로>` : IDB 저장 디렉토리 오버라이드 (기본: config의 paths.idb_dir)

## 주의사항
- IDA 모듈(idapro, idc 등)은 런타임에만 사용 가능 — IDE 정적 분석 경고 무시
- `exec` 명령어는 `config.json`의 `security.exec_enabled`가 true일 때만 동작
- Windows에서 경로 비교는 `os.path.normcase()` 사용 필수
- Python 3.14는 IDA 9.3 Known Issue로 비호환 (3.12/3.13 권장)
