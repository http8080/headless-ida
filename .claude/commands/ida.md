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
ida-cli restart <id>                      # 종료 후 재시작 (같은 바이너리/IDB)
  # 옵션: --fresh (처음부터 재분석)
ida-cli status                            # 상태 확인 (-b 힌트 자동 resolve)
ida-cli wait <id> --timeout 300           # 분석 완료 대기
ida-cli list                              # 전체 인스턴스 목록
ida-cli list --json                       # JSON 형식 인스턴스 목록 (idb_path 포함)
ida-cli logs <id> --tail 20               # 인스턴스 로그 조회
ida-cli logs <id> --follow                # 실시간 로그 추적
ida-cli cleanup [--dry-run]               # 비활성 인스턴스 정리
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
  # 옵션: --encoding unicode|ascii (문자열 인코딩 필터)
ida-cli -b <hint> imports [--filter X] [--count N] [--out F]
ida-cli -b <hint> exports [--out F]
```

### 디컴파일 & 디스어셈블리
```bash
# 디컴파일 (--out 사용 시 inline 출력 생략, 파일만 저장)
ida-cli -b <hint> decompile <주소|이름> [--out /tmp/func.c]
ida-cli -b <hint> decompile <주소|이름> --raw            # 순수 C 코드 (헤더/주소 없음)
ida-cli -b <hint> decompile <주소|이름> --with-xrefs    # 호출자/피호출자 포함
ida-cli -b <hint> decompile <주소|이름> --out result.md  # 마크다운 출력

# 일괄 디컴파일 (--out 사용 시 inline 출력 생략)
ida-cli -b <hint> decompile_batch <a1> <a2> ... [--out /tmp/batch.c]
ida-cli -b <hint> decompile_batch <a1> <a2> --out batch.md  # 마크다운 출력

# 전체 함수 일괄 디컴파일
ida-cli -b <hint> decompile-all --out /tmp/all.c [--filter X]
  # 옵션: --include-thunks, --include-libs, --split (함수별 개별 파일)

# 디스어셈블리
ida-cli -b <hint> disasm <주소|이름> --count 50
```

### 함수 분석
```bash
ida-cli -b <hint> find_func <이름> [--regex] [--out F]   # 함수명으로 검색
ida-cli -b <hint> func_info <주소|이름>                  # 함수 상세 정보 (크기, 인자, 타입)
ida-cli -b <hint> stack-frame <주소|이름>                # 스택 프레임 레이아웃 (로컬 변수, 인자, 오프셋)
ida-cli -b <hint> switch-table <주소|이름>               # switch/jump 테이블 분석
ida-cli -b <hint> func-similarity <주소A> <주소B>        # 두 함수 유사도 비교
ida-cli -b <hint> auto-rename [--apply] [--max-funcs 200]  # sub_ 함수 휴리스틱 이름 추정
```

### 크로스 레퍼런스
```bash
# xrefs: 단일 레벨 크로스 레퍼런스 (직접 호출자/피호출자만)
ida-cli -b <hint> xrefs <주소> --direction to|from|both
ida-cli -b <hint> callers <주소>                           # 단축: xrefs --direction to
ida-cli -b <hint> callees <주소>                           # 단축: xrefs --direction from

# cross-refs: 다단계 체인 추적 (--depth 레벨까지 호출 체인 추적)
ida-cli -b <hint> cross-refs <주소|이름> --depth 3 --direction to|from|both
  # 옵션: --format mermaid|dot, --out F
```
> **xrefs vs cross-refs**: `xrefs`는 직접(1단계) 레퍼런스만 표시. `cross-refs`는 `--depth`까지 재귀적으로 체인을 추적하고 mermaid/DOT 그래프로 출력. 간단한 조회는 `xrefs`, 호출 체인 이해는 `cross-refs` 사용.

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
  # 옵션: --max-funcs N (스캔할 함수 수 제한), --case-sensitive
  # 주의: 모든 함수를 디컴파일하여 검색. 대형 바이너리(1000+)에서 느림.
  #       --max-funcs로 범위 제한하거나, 문자열 검색은 strings-xrefs 사용 권장.
ida-cli -b <hint> search-const 0x1234 --max 20 [--out F]  # 상수값/즉시값 검색
ida-cli -b <hint> find_pattern "48 8B ? ? 00" --max 20 [--out F]  # 바이트 패턴 검색
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
ida-cli -b <hint> rename-batch mapping.csv              # CSV(주소,이름) 또는 JSON 파일에서 일괄 이름 변경
ida-cli -b <hint> set_type <주소> "int __fastcall func(int a, int b)"
ida-cli -b <hint> comment <주소> "설명 텍스트" [--repeatable] [--type line|func]
ida-cli -b <hint> patch <주소> 90 90 90                # NOP 패치 (exec_enabled 필요)
ida-cli -b <hint> save                                  # IDB 저장
```
> **반복 분석 패턴**: rename/set_type 적용 후 다시 decompile하면 변수명과 타입이
> 반영되어 훨씬 읽기 쉬운 코드가 됩니다. 핵심 함수는 이 과정을 반복하세요.

### 분석 결과 관리 & 스냅샷
```bash
# 이름/주석/타입 JSON 내보내기/가져오기
ida-cli -b <hint> annotations export --out analysis.json
ida-cli -b <hint> annotations import analysis.json

# IDB 스냅샷 (실험적 변경 전 백업)
ida-cli -b <hint> snapshot save --description "리팩토링 전"
ida-cli -b <hint> snapshot list                        # .meta.json에서 설명 표시
ida-cli -b <hint> snapshot restore <스냅샷_파일>       # IDB 디렉토리에서 자동 resolve

# IDAPython 스크립트 생성 (재현 가능한 분석)
ida-cli -b <hint> export-script --out analysis.py
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
ida-cli -b <hint> profile run malware    # C2, 암호화, 안티분석, 네트워크 API
ida-cli -b <hint> profile run vuln       # 위험 함수 (memcpy, strcpy, sprintf, system)
ida-cli -b <hint> profile run firmware   # 주변장치 (UART/SPI/GPIO), 프로토콜, 부트
```

### 바이너리 비교 (패치 디핑)
```bash
ida-cli -b <hint> compare old.exe new.exe --out diff.json
ida-cli -b <hint> code-diff <인스턴스_a> <인스턴스_b> [--functions func1 func2]
ida-cli -b <hint> diff <인스턴스_a> <인스턴스_b>         # 실행 중인 두 인스턴스 비교
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
ida-cli completions --shell bash|zsh|powershell   # 셸 자동완성 생성
```

## 주요 글로벌 옵션

- `-b <hint>` -- 바이너리 이름 일부로 인스턴스 자동 선택 (예: `-b note`로 notepad.exe)
- `-i <id>` -- 인스턴스 ID로 직접 선택
- `--out <경로>` -- 파일로 저장 (decompile/decompile_batch는 inline 출력 생략)
- `--count N` / `--offset N` -- 리스트 명령어 페이징 (functions, strings, imports, exports, structs, enums)
- `--max N` -- 검색 명령어 결과 제한 (find_func, find_pattern, search-const, search-code, vtables, strings-xrefs, data-refs)
- `--filter <키워드>` -- 이름으로 결과 필터링
- `--format mermaid|dot` -- 그래프 출력 형식 (callgraph, cross-refs, basic-blocks)
- `--json` -- JSON 출력 모드
- `--fresh` -- 기존 .i64 무시, 처음부터 재분석
- `--force` -- 동일 바이너리 중복 인스턴스 허용
- `--count-only` -- 총 개수만 표시 (functions/strings/imports/exports)
- `--version` -- CLI 버전 표시

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

## 컨텍스트 절약 규칙

**중요: 컨텍스트 창 낭비를 방지하기 위해 반드시 따를 것.**

### 대량 출력은 항상 `--out` 사용
```bash
# 나쁨: 수백 줄이 컨텍스트에 쏟아짐
ida-cli -b <hint> decompile <addr>

# 좋음: 파일로 저장, "Saved to:"만 출력
ida-cli -b <hint> decompile <addr> --out /tmp/func.c
ida-cli -b <hint> functions --out /tmp/funcs.txt
```
`Read`의 offset/limit으로 필요한 부분만 읽기:
```
Read /tmp/funcs.txt offset=1 limit=50   # 처음 50줄만
```

### 검색 먼저, 디컴파일은 나중에
```bash
# 나쁨: 전체 디컴파일 후 수동 검색
ida-cli -b <hint> decompile-all --out /tmp/all.c

# 좋음: 검색 → 타겟 발견 → 해당 함수만 디컴파일
ida-cli -b <hint> search-code "password" --max 10
ida-cli -b <hint> strings --filter "http" --count 20
ida-cli -b <hint> decompile <found_addr> --out /tmp/target.c
```

### 통합 명령 사용
```bash
# 나쁨: 3번 호출 (컨텍스트 3배)
ida-cli -b <hint> strings --filter login
ida-cli -b <hint> xrefs <addr1>
ida-cli -b <hint> xrefs <addr2>

# 좋음: 1번 호출로 해결
ida-cli -b <hint> strings-xrefs --filter login --max 20
```

### 결과 수 공격적으로 제한
```bash
# 나쁨: 함수 2000개 전부 가져옴
ida-cli -b <hint> functions

# 좋음: 개수만 먼저 확인
ida-cli -b <hint> functions --count-only

# 좋음: --count와 --offset으로 페이징
ida-cli -b <hint> functions --count 30
ida-cli -b <hint> functions --count 30 --offset 30  # 다음 페이지
```

### Agent 서브에이전트로 독립 분석 위임
독립적인 분석은 서브에이전트에 위임하여 메인 컨텍스트 보호:
```
Agent: "바이너리 X의 암호화 함수 분석"
Agent: "바이너리 Y의 네트워크 관련 import 조사"
```
서브에이전트는 요약만 반환하므로 메인 컨텍스트가 깨끗하게 유지됨.

### 기타
- `summary` 한 번으로 segments + imports + strings 대체
- `decompile_batch`로 여러 함수 한번에 디컴파일
- `profile run <type>`으로 자동화된 정찰
- `--json` 모드로 구조화된 데이터 활용

## 출력 형식 예시

### summary
```
Binary:      example.exe
Decompiler:  True
IDA:         9.3
Functions:   521  (avg size: 293 bytes)
Strings:     584
Imports:     340
Exports:     1
```

### decompile
```
// wWinMain @ 0x140010100
int __stdcall wWinMain(HINSTANCE hInstance, ...) {
  /* 0x140010119 */ sub_rsp(0x90);
  ...
}
```

### decompile --raw
```
int __stdcall wWinMain(HINSTANCE hInstance, ...) {
  sub_rsp(0x90);
  ...
}
```
(헤더/주소 없음 — LLM 분석을 위한 최소 토큰)

### functions
```
0x140001000  sub_140001000                                     size=42
0x14000102A  wWinMain                                          size=1200
```

### xrefs / callers / callees
```
Xrefs TO 0x140010100 (3)
  0x14001A000  sub_14001A000                     Code_Near
  0x14001B200  __mainCRTStartup                  Code_Near
```

### func-similarity
```
  Function A: sub_140001000 (0x140001000)  size=256  blocks=12  callees=5
  Function B: sub_140002000 (0x140002000)  size=280  blocks=14  callees=6

  Similarity:
    Size ratio:      0.9143
    Block ratio:     0.8571
    Callee Jaccard:  0.6000
    Overall:         0.7905
```
(Overall 1.0 = 동일, 0.0 = 완전히 다름)

### stack-frame
```
  Function: process_data (0x140001000)
  Frame size: 120  (locals=96, args=16, retaddr=8)
  Members: 5

  | Offset |   Size | Name                           | Type                 | Kind |
  |     0  |     64 | buf                            | char[64]             | local|
  |    64  |      8 | result                         | __int64              | local|
  |    96  |      8 | return_addr                    |                      | retaddr|
  |   104  |      8 | arg_0                          | void *               | arg  |
```

### find_func
```
Query: 'main' (3 matches)
  0x140010100  wWinMain
  0x14001A000  __mainCRTStartup
  0x14001B200  mainCRTStartup
```

### search-const
```
  Value: 0x1234  Found: 2
    0x140001050  cmp     eax, 1234h  [sub_140001000]
    0x140002100  mov     ecx, 1234h  [process_data]
```

### find_pattern
```
Pattern: '48 8B ? ? 00' (5 matches)
  0x140001000
  0x140001200
  0x140002500
```

### vtables
```
VTables found: 2
  0x140050000  4 entries  [near CMyClass::vftable]
    [0] 0x140001000  sub_140001000
    [1] 0x140001200  sub_140001200
    [2] 0x140001400  sub_140001400
    [3] 0x140001600  sub_140001600
  0x140050040  3 entries
    [0] 0x140002000  sub_140002000
    [1] 0x140002200  sub_140002200
    [2] 0x140002400  sub_140002400
```

### decompile-all --split
`--split` 사용 시 `--out`은 디렉토리 경로로 취급. 각 함수가 개별 `.c` 파일로 저장:
```
output_dir/
  wWinMain.c
  sub_140001000.c
  process_data.c
  ...
```
`--split` 없으면 `// ── funcname` 헤더로 구분된 단일 파일.

### callgraph (mermaid)
```mermaid
graph TD
  main --> init_config
  main --> process_data
  process_data --> validate_input
```

## 분석 판단 플로우차트

```
무엇을 분석하려는가?
│
├─ 모르는 바이너리 (첫 분석)
│  → summary → strings --filter <키워드> → xrefs → decompile
│
├─ 특정 함수 찾기
│  → find_func <이름> [--regex] → decompile → callers / callees
│
├─ 취약점 탐색
│  → imports (memcpy, strcpy, sprintf, system, exec)
│  → 위험 함수에 xrefs → 호출 위치 decompile
│  → bytes로 버퍼 크기 확인
│
├─ 악성코드 분석
│  → profile run malware (자동 정찰)
│  → strings (C2, URL, 레지스트리) → imports (네트워크, 프로세스 API)
│  → find_func --regex "crypt|encode|xor" → decompile_batch
│
├─ 두 버전 비교 (패치 디핑)
│  → 양쪽 바이너리 start → code-diff 또는 compare
│
├─ 호출 흐름 이해
│  → callgraph <addr> --direction callees --depth 3
│  → basic-blocks <addr>로 CFG
│
├─ 벌크 분석 / 전체 덤프
│  → decompile-all --out /tmp/all.c [--filter X]
│  → decompile_batch <addr1> <addr2> ... --out /tmp/batch.c
│
└─ 펌웨어/IoT
   → segments (메모리 레이아웃) → strings (디바이스 ID, 프로토콜)
   → find_func --regex "uart|spi|i2c|gpio" → exports
```

## 흔한 실수

1. **start 후 wait 안 함** — `start`는 IDA 분석 중에 즉시 반환됨. 분석 명령 전에 반드시 `wait <id> --timeout 300`.

2. **decompile에 `--out` 안 씀** — 디컴파일 출력이 컨텍스트를 가득 채움. `--out /tmp/file`로 저장 후 `Read`.

3. **주소 형식** — IDA는 `0x` 접두사 16진수 (예: `0x140001000`). 함수 이름도 사용 가능 (예: `main`, `sub_140001000`).

4. **xrefs 방향 혼동** — `--direction to` = "누가 이걸 호출?" (callers), `--direction from` = "이게 뭘 호출?" (callees). `callers`/`callees` 단축 명령 사용 권장.

5. **.i64 잠김** — `open_database returned 2` 에러 = IDB 잠김/손상. `.i64` 삭제 후 `--fresh`로 재시작.

6. **디컴파일러 없음** — 모든 IDA에 Hex-Rays가 있지 않음. `summary`에서 `decompiler: true/false` 확인. 없으면 `disasm` 사용.

7. **저장 안 함** — `rename`/`set_type`/`comment` 후 `save` 실행해야 .i64에 영구 저장됨.

8. **대량 리스트로 컨텍스트 범람** — 함수/문자열을 한번에 전부 가져오지 말 것. `--count 30`과 `--offset` 사용.

## 에러 대응 & 트러블슈팅

| 에러 | 원인 | 해결 |
|------|------|------|
| `open_database returned 2` | .i64 잠김/손상 | .i64 삭제, `--fresh`로 재시작 |
| `CONNECTION_FAILED` | 서버 프로세스 크래시 | `cleanup` 후 `start` 재시작 |
| `NOT_A_FUNCTION` | 주소가 함수 내부가 아님 | 에러 힌트에서 가까운 함수 확인 |
| `INVALID_ADDRESS` | 심볼 이름 못 찾음 | `find_func --regex <이름>` 또는 `functions --filter <이름>` |
| `DECOMPILER_NOT_LOADED` | Hex-Rays 라이선스 없음 | `decompile` 대신 `disasm` 사용 |
| `EXEC_DISABLED` | exec 비활성화 | config.json에서 `security.exec_enabled=true` |
| `TIMEOUT` | 분석 시간 초과 | `--timeout` 증가, `logs <id>` 확인 |
| "analyzing" 상태 | 초기 자동 분석 진행 중 | `wait <id> --timeout 300` |

### 빠른 해결
- **분석 실패**: `logs <id> --tail 20`으로 원인 확인
- **비활성 인스턴스**: `list` → `cleanup`으로 제거
- **.i64 재생성**: `start <바이너리> --fresh` (기존 DB 무시)

## 판단 기준: IDA vs 다른 도구

| 바이너리 유형 | 도구 |
|-------------|------|
| Java/Kotlin (APK) | JADX |
| 네이티브 코드 (.so, .dll, .exe, .dylib), 보안 솔루션, 멀티 아키텍처 | **IDA CLI** |
| 펌웨어/IoT | **IDA CLI** |

## 사용자 인자: $ARGUMENTS
사용자가 `/ida <바이너리 경로>` 형태로 호출하면 해당 바이너리에 대해 즉시 분석을 시작합니다.
바이너리 경로가 제공되지 않으면 사용자에게 분석 대상을 확인합니다.