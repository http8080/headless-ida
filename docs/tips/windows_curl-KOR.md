# Windows curl 팁

## 문제: Single Quote가 동작하지 않음

Windows 환경(cmd, cmder, PowerShell)에서 curl로 JSON 전송 시 single quote(`'`)가 동작하지 않음.

```bash
# 실패 - single quote
curl -X POST http://127.0.0.1:13140 -d '{"method":"ping","id":1}'
# → 서버에서 json.JSONDecodeError 발생 (빈 body 수신)
```

## 해결: Escaped Double Quote 사용

```bash
# 성공 - escaped double quote
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"ping\",\"id\":1}"
```

## 대안: 파일 참조

```bash
# JSON 파일 생성 후 참조
echo {"method":"ping","id":1} > req.json
curl -X POST http://127.0.0.1:13140 --data-binary @req.json
```

## 원인

Windows shell은 single quote를 문자열 구분자로 인식하지 않아 JSON body가 빈 값으로 전달됨.

## 자주 쓰는 명령어 예시

```bash
# ping
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"ping\",\"id\":1}"

# status
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"status\",\"id\":1}"

# stop
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"stop\",\"id\":1}"

# decompile (주소 지정)
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"decompile\",\"params\":{\"ea\":\"0x140001000\"},\"id\":1}"
```
