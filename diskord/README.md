# Diskord (simple)

## Run (Linux/macOS)
```bash
chmod +x start.sh
./start.sh
```

Open: http://127.0.0.1:4000

### Recommended
Set a strong secret:
```bash
export PYCORD_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
```
