---
description: IDA Pro 헤드리스 바이너리 분석 (idalib)
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
---

# IDA Headless 바이너리 분석

모든 IDA 작업은 `ida-cli` 명령어로 수행합니다. (PATH에 등록된 글로벌 명령어)
프로젝트 디렉토리에서는 `python tools/ida_cli.py`로도 실행 가능합니다.
MCP나 다른 도구를 사용하지 않습니다.

## 빠른 시작

```bash
# 1. 환경 확인 (최초 1회)
ida-cli --check
ida-cli --init

# 2. 인스턴스 시작 (IDB를 현재 프로젝트에 저장)
ida-cli start <바이너리_경로> --idb-dir .
ida-cli wait <id> --timeout 300

# 3. 종합 개요
ida-cli -b <hint> summary

# 4. 분석
ida-cli -b <hint> decompile <주소|이름>
ida-cli -b <hint> xrefs <주소> --direction both

# 5. 종료
ida-cli stop <id>
```

## 전체 명령어 레퍼런스

### 환경 & 설정
```bash
ida-cli --check                           # IDA/Python 환경 확인
ida-cli --init                            # 디렉토리 초기화
```

### 인스턴스 관리
```bash
ida-cli start <바이너리> --idb-dir .      # 분석 시작 (항상 --idb-dir . 사용)
  # 옵션: --fresh (기존 .i64 무시, 재분석), --force (동일 바이너리 중복 허용)
ida-cli stop <id>                         # 인스턴스 종료
ida-cli status                            # 상태 확인 (-b 힌트 자동 resolve)
ida-cli wait <id> --timeout 300           # 분석 완료 대기
ida-cli list                              # 전체 인스턴스 목록
ida-cli list --json                       # JSON 형식 인스턴스 목록 (idb_path 포함)
ida-cli logs <id> --tail 20               # 인스턴스 로그 조회
ida-cli cleanup                           # 비활성 인스턴스 정리
ida-cli save                              # IDB 저장
```

### 초기 정찰
```bash
ida-cli -b <hint> summary                 # 종합 개요 (세그먼트, 임포트, 함수, 문자열)
ida-cli -b <hint> segments                # 메모리 레이아웃 (주소, 이름, 크기, 권한)
ida-cli -b <hint> imagebase               # 바이너리 베이스 주소

# 데이터 수집 (--out으로 컨텍스트 절약)
ida-cli -b <hint> functions [--filter X] [--count N] [--offset N] [--out F]
ida-cli -b <hint> strings [--filter X] [--count N] [--offset N] [--out F]
ida-cli -b <hint> imports [--filter X] [--count N] [--out F]
ida-cli -b <hint> exports [--out F]
```

### 디컴파일 & 디스어셈블리
```bash
# 디컴파일 (--out 사용 시 inline 출력 생략, 파일만 저장)
ida-cli -b <hint> decompile <주소|이름> [--out /tmp/func.c]
ida-cli -b <hint> decompile <주소|이름> --with-xrefs    # 호출자/피호출자 포함
ida-cli -b <hint> decompile <주소|이름> --out result.md  # 마크다운 출력

# 일괄 디컴파일 (--out 사용 시 inline 출력 생략)
ida-cli -b <hint> decompile_batch <a1> <a2> ... [--out /tmp/batch.c]
ida-cli -b <hint> decompile_batch <a1> <a2> --out batch.md  # 마크다운 출력

# 전체 함수 일괄 디컴파일
ida-cli -b <hint> decompile-all --out /tmp/all.c [--filter X]
  # 옵션: --include-thunks, --include-libs

# 디스어셈블리
ida-cli -b <hint> disasm <주소|이름> --count 50
```

### 함수 분석
```bash
ida-cli -b <hint> find_func <이름> [--regex]            # 함수명으로 검색
ida-cli -b <hint> func_info <주소|이름>                  # 함수 상세 정보 (크기, 인자, 타입)
ida-cli -b <hint> func-similarity <주소A> <주소B>        # 두 함수 유사도 비교
ida-cli -b <hint> auto-rename [--apply] [--max-funcs 200]  # sub_ 함수 휴리스틱 이름 추정
```

### 크로스 레퍼런스
```bash
ida-cli -b <hint> xrefs <주소> --direction to|from|both
ida-cli -b <hint> cross-refs <주소|이름> --depth 3 --direction to|from|both
  # 옵션: --format mermaid|dot, --out F
```

### 콜그래프 & 제어 흐름
```bash
# 콜그래프 (mermaid 또는 DOT 형식)
ida-cli -b <hint> callgraph <주소|이름> --depth 3 --direction callers|callees
ida-cli -b <hint> callgraph <주소> --format dot --out graph.dot

# 기본 블록 + CFG
ida-cli -b <hint> basic-blocks <주소|이름>
ida-cli -b <hint> basic-blocks <주소> --format dot --out cfg.dot
ida-cli -b <hint> basic-blocks <주소> --graph-only   # 그래프만 출력
```

### 검색
```bash
ida-cli -b <hint> search-code "키워드" --max 10         # 디컴파일 결과 내 검색
  # 옵션: --max-funcs N (스캔할 함수 수 제한)
ida-cli -b <hint> search-const 0x1234 --max 20          # 상수값/즉시값 검색
ida-cli -b <hint> find_pattern "48 8B ? ? 00" --max 20  # 바이트 패턴 검색
ida-cli -b <hint> strings-xrefs --filter http --max 20   # 문자열 + 참조 함수
  # 옵션: --min-refs N, --out F
ida-cli -b <hint> data-refs --max 50                     # 데이터 참조 분석
  # 옵션: --segment .data, --filter X
```

### 원시 데이터
```bash
ida-cli -b <hint> bytes <주소> <크기>      # 바이트 읽기 (hex + base64)
ida-cli -b <hint> comments <주소>           # 주석 조회
```

### 타입 & 구조체
```bash
# Local Types
ida-cli -b <hint> type-info list [--kind typedef|funcptr|struct|enum|other]
ida-cli -b <hint> type-info show <타입_이름>

# 구조체
ida-cli -b <hint> structs list [--filter X] [--count N] [--offset N]
ida-cli -b <hint> structs show <구조체_이름>
ida-cli -b <hint> structs create <이름> --members "field1:4" "field2:8"

# 열거형
ida-cli -b <hint> enums list [--filter X] [--count N] [--offset N]
ida-cli -b <hint> enums show <열거형_이름>
ida-cli -b <hint> enums create <이름> --members "OK=0" "ERR=1"

# VTable 탐지
ida-cli -b <hint> vtables [--min-entries 3]

# FLIRT 시그니처
ida-cli -b <hint> sigs list
ida-cli -b <hint> sigs apply <시그니처_이름>
```

### 수정
```bash
ida-cli -b <hint> rename <주소> <새이름>
ida-cli -b <hint> set_type <주소> "int __fastcall func(int a, int b)"
ida-cli -b <hint> comment <주소> "설명 텍스트"
ida-cli -b <hint> patch <주소> 90 90 90                # NOP 패치 (exec_enabled 필요)
ida-cli -b <hint> save                                  # IDB 저장
```
> **반복 분석 패턴**: rename/set_type 적용 후 다시 decompile하면 변수명과 타입이
> 반영되어 훨씬 읽기 쉬운 코드가 됩니다. 핵심 함수는 이 과정을 반복하세요.

### 분석 결과 관리 & 스냅샷
```bash
# 이름/주석/타입 JSON 내보내기/가져오기
ida-cli -b <hint> annotations export --output analysis.json
ida-cli -b <hint> annotations import analysis.json

# IDB 스냅샷 (실험적 변경 전 백업)
ida-cli -b <hint> snapshot save --description "리팩토링 전"
ida-cli -b <hint> snapshot list                        # .meta.json에서 설명 표시
ida-cli -b <hint> snapshot restore <스냅샷_파일>       # IDB 디렉토리에서 자동 resolve

# IDAPython 스크립트 생성 (재현 가능한 분석)
ida-cli -b <hint> export-script --output analysis.py
```

### 북마크 (분석 세션 간 주소 태깅)
```bash
ida-cli bookmark add <주소> <태그> --note "설명" -b <hint>
ida-cli bookmark list
ida-cli bookmark list --tag vuln
ida-cli bookmark remove <주소>
```
> `.ida-bookmarks.json`으로 프로젝트 디렉토리에 저장됩니다.

### 리포트 생성
```bash
ida-cli -b <hint> report output.md                     # 마크다운 리포트
ida-cli -b <hint> report output.html                   # HTML 리포트
ida-cli -b <hint> report output.md --functions 0x401000 0x402000  # 함수 디컴파일 포함
```
> 포함 항목: summary, segments, imports, exports, strings, bookmarks, 선택적 함수 디컴파일

### 일괄 분석 & 프로필
```bash
# 디렉토리 내 모든 바이너리 한번에 분석
ida-cli batch <디렉토리> --idb-dir . --timeout 300

# 자동화된 분석 프로필
ida-cli -b <hint> profile run malware
ida-cli -b <hint> profile run vuln
ida-cli -b <hint> profile run firmware
```

### 바이너리 비교 (패치 디핑)
```bash
ida-cli -b <hint> compare old.exe new.exe --out diff.json
ida-cli -b <hint> code-diff <인스턴스_a> <인스턴스_b> [--functions func1 func2]
ida-cli -b <hint> diff                                 # 실행 중인 두 인스턴스 비교
```

### IDA Python 실행
```bash
# shared/config.json에서 security.exec_enabled=true 설정 필요
ida-cli -b <hint> exec "import idautils; print(len(list(idautils.Functions())))"
ida-cli -b <hint> exec "import idc; print(idc.get_segm_name(0x140001000))"
ida-cli -b <hint> shell                                # 대화형 IDA Python REPL
```

### 유틸리티
```bash
ida-cli -b <hint> methods                              # 사용 가능한 RPC 메서드 목록
ida-cli update                                         # git에서 도구 업데이트
ida-cli completions --shell bash|zsh|fish|powershell   # 셸 자동완성 생성
```

## 주요 글로벌 옵션

- `-b <hint>` -- 바이너리 이름 일부로 인스턴스 자동 선택 (예: `-b note`로 notepad.exe)
- `-i <id>` -- 인스턴스 ID로 직접 선택
- `--out <경로>` -- 파일로 저장 (decompile/decompile_batch는 inline 출력 생략)
- `--count N` / `--offset N` -- 대량 결과 페이징
- `--filter <키워드>` -- 이름으로 결과 필터링
- `--format mermaid|dot` -- 그래프 출력 형식 (callgraph, cross-refs, basic-blocks)
- `--json` -- JSON 출력 모드
- `--fresh` -- 기존 .i64 무시, 처음부터 재분석
- `--force` -- 동일 바이너리 중복 인스턴스 허용

## 멀티 인스턴스 워크플로우

```bash
# 여러 바이너리를 동시에 시작
ida-cli start ./main_binary --idb-dir .
ida-cli start ./libcrypto.so --idb-dir .

# -b 힌트로 각각 지정하여 분석
ida-cli -b main decompile 0x401000
ida-cli -b crypto decompile 0x12340

# 전체 인스턴스 확인
ida-cli list
ida-cli list --json
```

## 분석 전략

### 문자열 추적 패턴 (가장 기본적인 RE 기법)
1. `strings --filter <키워드>` -> 목표 문자열 발견
2. `xrefs <문자열_주소>` -> 참조하는 코드 위치
3. `decompile <xref_주소>` -> 함수 분석
4. 필요 시 xrefs를 다시 추적 (callers of callers)

### 반복 정제 패턴
1. `decompile <주소>` -> 원시 출력 확인
2. `rename` / `set_type` / `comment` -> 주석 추가
3. `decompile <주소>` 재실행 -> 훨씬 깔끔한 코드
4. 핵심 함수에 대해 반복

### 보안 솔루션 분석
strings/imports에서 검색: root, jailbreak, ssl, cert, integrity, frida, xposed, magisk, hook, patch

### 멀웨어 분석
1. `strings`로 C2 도메인, IP, 레지스트리 키, 파일 경로 검색
2. `imports`에서 네트워킹, 프로세스 주입, 파일 API 확인
3. `find_func --regex "crypt|encode|decode|xor"` → 암호화 루틴
4. `decompile_batch`로 의심 함수 일괄 분석
5. `find_pattern`으로 하드코딩된 키/IV/XOR 테이블 검색

### 취약점 연구
1. `imports`에서 위험 함수 검색 (memcpy, strcpy, sprintf, system, exec)
2. 각 위험 함수에 `xrefs` -> 호출 위치 파악
3. `decompile`로 버퍼 크기, 입력 검증 여부 분석
4. `func_info`로 함수 크기/인자 확인
5. `bytes`로 스택 버퍼 크기와 오프셋 확인

### 펌웨어/IoT 분석
1. `segments`로 메모리 레이아웃 파악 (ROM/RAM 영역)
2. `strings`로 디바이스 식별 정보, 명령어, 프로토콜 키워드 검색
3. `find_func --regex "uart|spi|i2c|gpio"` → HW 인터페이스 함수
4. `exports`로 공개 심볼 / 진입점 파악
5. `find_pattern`으로 매직 바이트/구조체 헤더 검색

## 컨텍스트 효율성 팁

- `--out /tmp/file`로 대량 결과 저장 후 `Read`로 읽기
- decompile/decompile_batch에 `--out` 사용하면 inline 출력 생략 (컨텍스트 절약)
- `--count`, `--filter`로 출력 범위 제한
- `--offset`으로 페이징 (대량 함수 탐색 시)
- `summary` 한 번으로 segments + imports + strings 대체
- `decompile_batch`로 여러 함수 한번에 디컴파일
- `profile run <type>`으로 자동화된 정찰
- `--json` 모드로 구조화된 데이터 활용

## 에러 대응

- 분석 실패: `logs <id> --tail 20`
- .i64 손상/잠김 (`open_database returned 2`): .i64 삭제 후 `--fresh`로 재시작
- .i64 재생성: `start <바이너리> --fresh`
- 인스턴스 문제: `list` → `cleanup`

## 판단 기준: IDA vs 다른 도구

| 바이너리 유형 | 도구 |
|-------------|------|
| Java/Kotlin (APK) | JADX |
| 네이티브 바이너리 (.so, .dll, .exe, .dylib) | **IDA CLI** |
| 보안 솔루션, 멀티 아키텍처 | **IDA CLI** |
| 펌웨어/IoT | **IDA CLI** |

## 사용자 인자: $ARGUMENTS
사용자가 `/ida <바이너리 경로>` 형태로 호출하면 해당 바이너리에 대해 즉시 분석을 시작합니다.
바이너리 경로가 제공되지 않으면 사용자에게 분석 대상을 확인합니다.