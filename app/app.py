# ============================================================
#  VulnNotes (Python/Flask) — "The Leak" story-mode lab.
#  DELIBERATELY VULNERABLE. Templates/static handle design;
#  the vulnerable sinks are kept intact below. Do NOT deploy.
# ============================================================
import base64
import pickle
import sqlite3
import subprocess
import urllib.request

from flask import Flask, request, render_template, render_template_string
from markupsafe import escape

app = Flask(__name__)
DB = "/tmp/notes.sqlite"

CHAPTERS = [
    {"no":1,"route":"login","title":"The Front Door","level":"easy",
     "owasp":"A03 · SQL Injection",
     "desc":"SecureNote's login builds its query from your input. Sign in as anyone.",
     "story":"The login check glues your username and password straight into SQL. Rewrite the query."},
    {"no":2,"route":"greet","title":"Say My Name","level":"easy",
     "owasp":"A03 · Reflected XSS",
     "desc":"The welcome banner prints your name back, unfiltered.",
     "story":"Whatever you type as your name is painted into the page as-is. Paint a script."},
    {"no":3,"route":"note","title":"Shared Notes","level":"medium",
     "owasp":"A01 · IDOR",
     "desc":"Notes open by id. No check that the note is yours.",
     "story":"Your note is #1. The id in the URL is the only thing standing between you and everyone else's."},
    {"no":4,"route":"render","title":"Custom Templates","level":"medium",
     "owasp":"A03 · SSTI (Jinja2)",
     "desc":"The 'note template' field is rendered as a real template. All of it.",
     "story":"Your template string is compiled by Jinja server-side. Expressions evaluate. So does worse."},
    {"no":5,"route":"dns","title":"Server Diagnostics","level":"medium",
     "owasp":"A03 · OS Command Injection",
     "desc":"A host-lookup tool runs through a shell with your input attached.",
     "story":"The diagnostics tool shells out with your hostname glued on. Glue on a second command."},
    {"no":6,"route":"fetch","title":"Import from URL","level":"hard",
     "owasp":"A10 · SSRF",
     "desc":"Import a note from any URL — including schemes and hosts you shouldn't reach.",
     "story":"The server fetches your URL itself, with no allow-list. Point it somewhere private."},
    {"no":7,"route":"restore","title":"Resume Session","level":"insane",
     "owasp":"A08 · Pickle Deserialization",
     "desc":"Your session rides in a cookie as a pickle. Bake a malicious one.",
     "story":"The 'session' cookie is unpickled on arrival. A crafted pickle runs code on load."},
]


@app.context_processor
def inject_chapters():
    return {"chapters": CHAPTERS}


def chap(route):
    return next(c for c in CHAPTERS if c["route"] == route)


def out(text):
    return f"<div class=out>{escape(text)}</div>"


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, secret TEXT);
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
        """
    )
    if not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        con.executemany(
            "INSERT INTO users(username,password,role,secret) VALUES (?,?,?,?)",
            [("alice","password123","user","alice-key"),
             ("bob","hunter2","user","bob-key"),
             ("admin","S3cr3t_Adm1n_!","admin","FLAG{py_admin}")],
        )
        con.executemany(
            "INSERT INTO notes(owner_id,body) VALUES (?,?)",
            [(1,"alice note"),(2,"bob note"),(3,"admin: FLAG{py_idor}")],
        )
        con.commit()
    con.close()


@app.route("/")
def home():
    return render_template("index.html", active="home")


# -------- Ch1 · SQL Injection (EASY) --------
@app.route("/login")
def login():
    u = request.args.get("username", "")
    p = request.args.get("password", "")
    form = (f"<form class=vf method=get>"
            f"<div><label>Username</label><input name=username value='{escape(u)}' placeholder='alice'></div>"
            f"<div><label>Password</label><input name=password type=password placeholder='••••••••'></div>"
            f"<button class=btn>Sign in</button></form>")
    output = None
    if "username" in request.args:
        sql = f"SELECT username, role FROM users WHERE username = '{u}' AND password = '{p}'"
        try:
            row = db().execute(sql).fetchone()
            output = (f"<div class='out ok'>✔ Authenticated as <b>{escape(row['username'])}</b> "
                      f"(role={escape(row['role'])})</div>" if row
                      else out(f"✘ Invalid credentials.  [debug SQL: {sql}]"))
        except Exception as e:
            output = out(f"DB error: {e}\nSQL: {sql}")  # A05 verbose error
    return render_template("chapter.html", c=chap("login"), active="login", form=form,
                           output=output, hint="")


# -------- Ch2 · Reflected XSS (EASY) --------
@app.route("/greet")
def greet():
    name = request.args.get("name")
    form = (f"<form class=vf method=get><div><label>Your name</label>"
            f"<input name=name value='{escape(name or '')}' placeholder='type your name'></div>"
            f"<button class=btn>Greet me</button></form>")
    output = f"<div class=out><p>Hello, {name}!</p></div>" if name is not None else None
    return render_template("chapter.html", c=chap("greet"), active="greet", form=form,
                           output=output, hint="")


# -------- Ch3 · IDOR (MEDIUM) --------
@app.route("/note")
def note():
    nid = request.args.get("id", "1")
    form = (f"<form class=vf method=get><div><label>Note #</label>"
            f"<input name=id value='{escape(nid)}'></div><button class=btn>Open note</button></form>")
    row = db().execute("SELECT * FROM notes WHERE id = ?", (nid,)).fetchone()
    output = out(f"Note #{row['id']} (owner {row['owner_id']}): {row['body']}") if row else out("No note.")
    return render_template("chapter.html", c=chap("note"), active="note", form=form,
                           output=output, hint="")


# -------- Ch4 · SSTI (MEDIUM) --------
@app.route("/render")
def render():
    tpl = request.args.get("tpl")
    form = (f"<form class=vf method=get style='max-width:620px'><div><label>Note template</label>"
            f"<input name=tpl value='{escape(tpl or '')}' placeholder='Hello {{{{ user }}}}'></div>"
            f"<button class=btn>Render</button></form>")
    output = None
    if tpl is not None:
        rendered = render_template_string("Rendered: " + tpl)
        output = f"<div class=out>{rendered}</div>"
    return render_template("chapter.html", c=chap("render"), active="render", form=form,
                           output=output, hint="")


# -------- Ch5 · OS Command Injection (MEDIUM) --------
@app.route("/dns")
def dns():
    host = request.args.get("host")
    form = (f"<form class=vf method=get><div><label>Hostname</label>"
            f"<input name=host value='{escape(host or '')}' placeholder='127.0.0.1'></div>"
            f"<button class=btn>Look up</button></form>")
    output = None
    if host:
        res = subprocess.run("getent hosts " + host, shell=True, capture_output=True, text=True)
        output = out((res.stdout + res.stderr) or "(no output)")
    return render_template("chapter.html", c=chap("dns"), active="dns", form=form,
                           output=output, hint="")


# -------- Ch6 · SSRF (HARD) --------
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    form = (f"<form class=vf method=get style='max-width:620px'><div><label>Note URL</label>"
            f"<input name=url value='{escape(url or '')}' placeholder='https://example.com'></div>"
            f"<button class=btn>Import</button></form>")
    output = None
    if url:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                output = out(r.read(2048).decode("utf-8", "replace"))
        except Exception as e:
            output = out(f"fetch error: {e}")
    return render_template("chapter.html", c=chap("fetch"), active="fetch", form=form,
                           output=output, hint="")


# -------- Ch7 · Insecure Deserialization (INSANE) --------
@app.route("/restore")
def restore():
    form = ("<form class=vf method=get><p style='color:var(--muted)'>This page unpickles the "
            "<code>session</code> cookie on load. Set that cookie to a base64 pickle and refresh.</p>"
            "<a class='btn ghost' href='/'>Back</a></form>")
    cookie = request.cookies.get("session")
    if not cookie:
        output = out("No session cookie set.")
    else:
        data = pickle.loads(base64.b64decode(cookie))
        output = out(f"Session restored: {data!r}")
    return render_template("chapter.html", c=chap("restore"), active="restore", form=form,
                           output=output,
                           hint="")


if __name__ == "__main__":
    init_db()
    # A05: debug=True exposes the Werkzeug interactive console (RCE) on errors.
    app.run(host="0.0.0.0", port=5000, debug=True)
