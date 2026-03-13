# Windows curl Tips

## Problem: Single Quotes Don't Work

When sending JSON via curl on Windows (cmd, cmder, PowerShell), single quotes (`'`) don't work.

```bash
# Fails - single quote
curl -X POST http://127.0.0.1:13140 -d '{"method":"ping","id":1}'
# → Server throws json.JSONDecodeError (empty body received)
```

## Solution: Use Escaped Double Quotes

```bash
# Works - escaped double quote
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"ping\",\"id\":1}"
```

## Alternative: File Reference

```bash
# Create a JSON file and reference it
echo {"method":"ping","id":1} > req.json
curl -X POST http://127.0.0.1:13140 --data-binary @req.json
```

## Cause

Windows shell does not recognize single quotes as string delimiters, so the JSON body is passed as an empty value.

## Common Command Examples

```bash
# ping
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"ping\",\"id\":1}"

# status
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"status\",\"id\":1}"

# stop
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"stop\",\"id\":1}"

# decompile (specify address)
curl -X POST http://127.0.0.1:13140 -d "{\"method\":\"decompile\",\"params\":{\"ea\":\"0x140001000\"},\"id\":1}"
```
