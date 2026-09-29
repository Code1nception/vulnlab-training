import sqlite3
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Synthetic records only. This in-memory database is intentionally injectable.
database = sqlite3.connect(":memory:", check_same_thread=False)
database.row_factory = sqlite3.Row
database.executescript(
    """
    CREATE TABLE accounts (username TEXT, display_name TEXT, pin TEXT, department TEXT);
    INSERT INTO accounts VALUES
        ('mira', 'Mira Chen', '4821', 'Design'),
        ('owen', 'Owen Patel', '1379', 'Finance'),
        ('admin', 'Lab Administrator', '0000', 'Training');
    """
)

profiles = {
    1001: {"id": 1001, "name": "Avery Morgan", "plan": "Learner", "private_note": "Welcome to your practice account."},
    1002: {"id": 1002, "name": "Riley Park", "plan": "Pro", "private_note": "Synthetic secret: ORBIT-42"},
    1003: {"id": 1003, "name": "Jordan Lee", "plan": "Team", "private_note": "Synthetic secret: MAPLE-17"},
}
passwords = {"admin": "violet-owl-91", "learner": "learn-123"}


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/idor/profile")
def idor_profile():
    try:
        user_id = int(request.args.get("user_id", "1001"))
    except ValueError:
        return jsonify({"error": "User ID must be a number."}), 400
    profile = profiles.get(user_id)
    if profile is None:
        return jsonify({"error": "No training profile found for that ID."}), 404
    return jsonify(profile)


@app.get("/api/xss/render")
def xss_render():
    name = request.args.get("name", "")
    # Deliberately unsafe output for the XSS lesson; the client confines it to a sandbox.
    return jsonify({"html": f"<h2>Welcome, {name}</h2><p>Your practice message appears above.</p>"})


@app.post("/api/sqli/search")
def sqli_search():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))[:120]
    pin = str(data.get("pin", ""))[:120]
    # Deliberately unsafe interpolation against the lab-only in-memory database.
    query = f"SELECT username, display_name, department FROM accounts WHERE username = '{username}' AND pin = '{pin}' LIMIT 5"
    try:
        rows = database.execute(query).fetchall()
    except sqlite3.Error as error:
        return jsonify({"error": f"SQLite rejected the training query: {error}"}), 400
    return jsonify({"results": [dict(row) for row in rows], "count": len(rows)})


@app.post("/api/cmdi/run")
def command_injection_run():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))[:120]
    if not username.strip():
        return jsonify({"error": "Enter a training username."}), 400

    members = {
        "mira": "Mira Chen · Design",
        "owen": "Owen Patel · Finance",
        "admin": "Training Administrator · Training",
    }
    training_files = {
        "show-training-note": "Synthetic training note: CEDAR-17",
    }
    simulated_line = f"lookup-user {username}"
    commands = [part.strip() for part in simulated_line.split(";") if part.strip()]
    if len(commands) > 5:
        return jsonify({"error": "The training console accepts at most five simulated commands."}), 400

    results = []
    note_exposed = False
    for command in commands:
        parts = command.split()
        if len(parts) == 2 and parts[0] == "lookup-user":
            member = members.get(parts[1].lower())
            output = member or "No synthetic training account found."
        elif parts in (["ls"], ["list-files"]):
            output = "show-training-note"
        elif len(parts) == 2 and parts[0] == "cat":
            output = training_files.get(parts[1], "No synthetic training file found.")
            if output != "No synthetic training file found.":
                note_exposed = True
        elif parts == ["show-training-note"]:
            output = training_files["show-training-note"]
            note_exposed = True
        else:
            output = "Action blocked: command is not in the training simulator allowlist."
        results.append({"command": command[:120], "output": output})

    return jsonify({"results": results, "command_count": len(commands), "note_exposed": note_exposed})


@app.post("/api/auth/request-reset")
def request_reset():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))[:40]
    if username not in passwords:
        return jsonify({"message": "If that training account exists, reset instructions were sent."})
    # The real flaw is in reset_password: reset tokens are predictable and never expire.
    return jsonify({"message": "If that training account exists, reset instructions were sent."})


@app.post("/api/auth/reset-password")
def reset_password():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))[:40]
    token = str(data.get("token", ""))[:120]
    new_password = str(data.get("new_password", ""))[:120]
    if username not in passwords or not new_password:
        return jsonify({"error": "Unknown account or empty password."}), 400
    if token != f"reset-{username}":
        return jsonify({"error": "Invalid reset token."}), 403
    passwords[username] = new_password
    return jsonify({"message": "Password updated. This token should never have been predictable."})


@app.post("/api/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))[:40]
    password = str(data.get("password", ""))[:120]
    if passwords.get(username) != password:
        return jsonify({"error": "Incorrect training credentials."}), 401
    if username == "admin":
        return jsonify({"message": "Admin training access granted.", "flag": "VULNLAB{reset_tokens_should_be_random}"})
    return jsonify({"message": "Learner training access granted."})


if __name__ == "__main__":
    # Keep the intentionally vulnerable lab reachable only from this machine.
    app.run(host="127.0.0.1", port=5000, debug=False)
