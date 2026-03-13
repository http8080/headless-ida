---
description: IDA Pro 헤드리스 바이너리 분석 (idalib)
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
---

# IDA Headless 바이너리 분석 스킬

바이너리 분석 요청 시 이 워크플로우를 따르세요.

## 진입점
모든 IDA 작업은 `python tools/ida_cli.py` 명령어로만 수행합니다.
MCP나 다른 도구를 사용하지 않습니다.

## 워크플로우

### 1. 환경 확인 (최초 1회)
```bash
python tools/ida_cli.py --check
python tools/ida_cli.py --init
```

### 2. 인스턴스 시작
```bash
python tools/ida_cli.py start <바이너리_경로>
# 프로젝트 로컬에 IDB 저장 시:
python tools/ida_cli.py start <바이너리_경로> --idb-dir <프로젝트_디렉토리>
# 출력에서 instance_id 확인
python tools/ida_cli.py wait <id> --timeout 300
```
- .i64가 이미 있으면 자동 재사용 (수 초 완료)
- `--idb-dir`로 IDB 저장 경로를 프로젝트별로 지정 가능
- 분석 대기 중 다른 작업 가능

### 3. 초기 정찰
아래 순서로 바이너리 개요를 파악합니다:
```bash
python tools/ida_cli.py -b <hint> imagebase
python tools/ida_cli.py -b <hint> segments
python tools/ida_cli.py -b <hint> strings --count 50 --out C:/tmp/strings.txt
python tools/ida_cli.py -b <hint> imports --count 50 --out C:/tmp/imports.txt
python tools/ida_cli.py -b <hint> exports --out C:/tmp/exports.txt
python tools/ida_cli.py -b <hint> functions --filter <keyword> --out C:/tmp/funcs.txt
```
- `--out`을 사용하여 컨텍스트 절약
- `-b <hint>`로 바이너리 이름 일부만으로 인스턴스 자동 선택

### 4. 심층 분석
```bash
# 함수 찾기
python tools/ida_cli.py -b <hint> find_func <이름> [--regex]

# 디컴파일
python tools/ida_cli.py -b <hint> decompile <주소|이름> [--out C:/tmp/func.c]

# 디스어셈블리
python tools/ida_cli.py -b <hint> disasm <주소|이름> --count 50

# 함수 상세 정보
python tools/ida_cli.py -b <hint> func_info <주소|이름>

# 크로스 레퍼런스
python tools/ida_cli.py -b <hint> xrefs <주소> --direction both

# 바이트 읽기
python tools/ida_cli.py -b <hint> bytes <주소> <크기>

# 바이트 패턴 검색
python tools/ida_cli.py -b <hint> find_pattern "48 8B ? ? 00" --max 20

# 일괄 디컴파일
python tools/ida_cli.py -b <hint> decompile_batch <addr1> <addr2> ... --out C:/tmp/batch.json
```

### 5. 수정 (필요 시)
```bash
python tools/ida_cli.py -b <hint> rename <주소> <새이름>
python tools/ida_cli.py -b <hint> comment <주소> "설명 텍스트"
python tools/ida_cli.py -b <hint> save
```

### 6. 종료
```bash
python tools/ida_cli.py stop <id>
```

## 분석 전략

### 보안 솔루션 분석 시
1. strings/imports로 보안 관련 키워드 검색 (root, jailbreak, ssl, cert, integrity 등)
2. find_func로 관련 함수 목록 확인
3. decompile로 핵심 함수 분석
4. xrefs로 호출 관계 추적
5. rename/comment로 분석 결과 기록

### 대용량 결과 처리
- 항상 `--out` 옵션으로 파일 저장 후 Read로 읽기
- `--count`, `--filter`로 결과 범위 제한
- `--json` 모드로 구조화된 데이터 활용

## 에러 대응
- 분석 실패 시: `python tools/ida_cli.py logs <id> --tail 20`
- .i64 손상 시: `python tools/ida_cli.py start <binary> --fresh`
- 인스턴스 목록: `python tools/ida_cli.py list`
- 정리: `python tools/ida_cli.py cleanup`

## 판단 기준: IDA vs 다른 도구
- Java/Kotlin 코드 → JADX
- 간단한 .so 확인 → Ghidra
- 보안 솔루션 핵심 로직, Ghidra 결과 불명확 → **IDA CLI 사용**

## 사용자 인자: $ARGUMENTS
사용자가 `/ida <바이너리 경로>` 형태로 호출하면 해당 바이너리에 대해 즉시 분석을 시작합니다.
바이너리 경로가 제공되지 않으면 사용자에게 분석 대상을 확인합니다.
