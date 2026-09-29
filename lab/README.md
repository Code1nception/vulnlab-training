# VulnLab

A local-only security learning playground with five intentionally vulnerable labs: IDOR, reflected XSS, SQL injection, broken authentication, and command injection. Every identity and record is synthetic. The app binds to `127.0.0.1` and does not scan or contact external targets.

## Run locally

Requires Python 3.10 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser. Stop the server with Ctrl+C. Keep the app on loopback: the endpoints are deliberately vulnerable and are not suitable for a public or shared network.

## Labs

- **IDOR:** Change the requested numeric profile ID to access another fictional profile.
- **XSS:** Reflect input as HTML and run a harmless proof only inside an opaque-origin sandboxed iframe. The frame blocks network access.
- **SQL injection:** Alter an interpolated SQLite lookup over three synthetic accounts in a temporary in-memory database.
- **Broken authentication:** Exploit a predictable password-reset token against the toy `admin` account, then retrieve the training flag.
- **Command injection:** Use a semicolon in a member lookup to trigger a second, fixed training action in a bounded simulator. The simulator never invokes an operating-system shell or external command.

Each lab has a guided walkthrough and a practice mode with hints and completion checks. Progress is saved in this browser's local storage; use **Reset all progress** in the sidebar to clear it.

## Verify

```powershell
python -m unittest
```

All vulnerabilities are intentional training examples. Do not deploy this app or reuse its patterns in production.
