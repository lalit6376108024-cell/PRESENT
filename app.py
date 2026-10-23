import os
import json
import sqlite3
import re
import secrets
import hashlib
import smtplib
from email.message import EmailMessage
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta
from io import BytesIO
import base64
from flask import send_file, abort
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("WILD_WITHIN_DB", os.path.join(APP_DIR, "wild_within.db"))
DEFAULT_TZ = os.environ.get("APP_TIMEZONE", "Asia/Kolkata")
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "")
if not app.secret_key:
    # Local development fallback only. Render must set SECRET_KEY in its environment.
    app.secret_key = secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1" if os.environ.get("RENDER") else "0") == "1",
                  PERMANENT_SESSION_LIFETIME=timedelta(days=14))

PUBLIC_ENDPOINTS = {"login", "signup", "forgot_password", "reset_password", "static", "health", "admin_snapshot"}

def current_user_id():
    value = session.get("user_id")
    return int(value) if value else None

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user_id():
            if request.method == "POST":
                return jsonify({"error": "Please sign in first."}), 401
            return redirect(url_for("login", next=request.full_path))
        return fn(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_auth_context():
    profile = None
    uid = current_user_id()
    if uid:
        try:
            with connect() as db:
                profile = db.execute("SELECT id, display_name, email, primary_goal, interests, coach_style FROM users WHERE id=?", (uid,)).fetchone()
        except Exception:
            profile = None
    return {"current_profile": profile, "csrf_token": session.get("csrf_token", ""), "timezone_name": DEFAULT_TZ}

@app.before_request
def protect_account_and_csrf():
    endpoint = request.endpoint or ""
    if endpoint not in PUBLIC_ENDPOINTS and not current_user_id():
        if request.method == "POST":
            return jsonify({"error": "Please sign in first."}), 401
        return redirect(url_for("login", next=request.full_path))
    if request.method == "POST" and endpoint not in {"login", "signup", "forgot_password", "reset_password"}:
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        import hmac
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return "Your session security token expired. Refresh the page and try again.", 400

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

class HybridRow(dict):
    """PostgreSQL row supporting both row['column'] and row[0] access."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)

class PGCursor:
    def __init__(self, cursor): self.cursor = cursor
    @property
    def rowcount(self): return self.cursor.rowcount
    def fetchone(self):
        row = self.cursor.fetchone()
        return HybridRow(row) if row is not None else None
    def fetchall(self): return [HybridRow(r) for r in self.cursor.fetchall()]

class PGConnection:
    def __init__(self, url):
        self.conn = psycopg.connect(url, row_factory=dict_row)
    def execute(self, sql, params=()):
        # Existing app uses SQLite-style placeholders; translate for psycopg.
        return PGCursor(self.conn.execute(sql.replace("?", "%s"), params))
    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip(): self.conn.execute(statement)
    def executemany(self, sql, params):
        return PGCursor(self.conn.executemany(sql.replace("?", "%s"), params))
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None: self.conn.commit()
            else: self.conn.rollback()
        finally: self.conn.close()

def connect():
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("DATABASE_URL is set but psycopg is missing. Install requirements.txt.")
        return PGConnection(DATABASE_URL)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db

def timezone():
    try:
        return ZoneInfo(DEFAULT_TZ)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")

def now_local():
    return datetime.now(timezone())

def init_db():
    with connect() as db:
        if DATABASE_URL:
            schema = """
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            display_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            primary_goal TEXT NOT NULL DEFAULT 'Build consistent habits',
            interests TEXT NOT NULL DEFAULT '',
            coach_style TEXT NOT NULL DEFAULT 'encouraging',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS habits (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Growth',
            description TEXT NOT NULL DEFAULT '',
            target_minutes INTEGER NOT NULL DEFAULT 15,
            reminder_time TEXT NOT NULL DEFAULT '',
            reminder_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
            icon TEXT NOT NULL DEFAULT '✳',
            schedule_json TEXT NOT NULL DEFAULT '{}',
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS logs (
            id BIGSERIAL PRIMARY KEY,
            habit_id INTEGER NOT NULL REFERENCES habits(id) ON DELETE CASCADE,
            log_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'done',
            minutes INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            UNIQUE(habit_id, log_date)
        );
        CREATE TABLE IF NOT EXISTS experiments (
            id BIGSERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            hypothesis TEXT NOT NULL DEFAULT '',
            duration_days INTEGER NOT NULL DEFAULT 30,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS experiment_logs (
            id BIGSERIAL PRIMARY KEY,
            experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
            log_date TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT '',
            rating INTEGER NOT NULL DEFAULT 3,
            note TEXT NOT NULL DEFAULT '',
            UNIQUE(experiment_id, log_date)
        );
        CREATE TABLE IF NOT EXISTS free_time_plans (
            id BIGSERIAL PRIMARY KEY,
            plan_date TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            intention TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(plan_date, start_time, end_time)
        );
        """
            db.executescript(schema)
        else:
            db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, display_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, primary_goal TEXT NOT NULL DEFAULT 'Build consistent habits',
            interests TEXT NOT NULL DEFAULT '', coach_style TEXT NOT NULL DEFAULT 'encouraging', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS habits (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Growth', description TEXT NOT NULL DEFAULT '',
            target_minutes INTEGER NOT NULL DEFAULT 15, reminder_time TEXT NOT NULL DEFAULT '',
            reminder_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6', icon TEXT NOT NULL DEFAULT '✳',
            schedule_json TEXT NOT NULL DEFAULT '{}', start_date TEXT NOT NULL,
            end_date TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, habit_id INTEGER NOT NULL REFERENCES habits(id) ON DELETE CASCADE,
            log_date TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'done', minutes INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL, UNIQUE(habit_id, log_date));
        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, hypothesis TEXT NOT NULL DEFAULT '',
            duration_days INTEGER NOT NULL DEFAULT 30, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS experiment_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
            log_date TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT '', rating INTEGER NOT NULL DEFAULT 3,
            note TEXT NOT NULL DEFAULT '', UNIQUE(experiment_id, log_date));
        CREATE TABLE IF NOT EXISTS free_time_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, plan_date TEXT NOT NULL, start_time TEXT NOT NULL,
            end_time TEXT NOT NULL, intention TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(plan_date, start_time, end_time));
        """)
        # Safe multi-account migration: add nullable ownership columns without deleting old data.
        owned_tables = ("habits", "logs", "experiments", "experiment_logs", "free_time_plans")
        for table in owned_tables:
            if DATABASE_URL:
                cols_now = {r['column_name'] for r in db.execute("SELECT column_name FROM information_schema.columns WHERE table_name=?", (table,)).fetchall()}
            else:
                cols_now = {r['name'] for r in db.execute(f'PRAGMA table_info({table})').fetchall()}
            if 'user_id' not in cols_now:
                if DATABASE_URL:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN user_id BIGINT REFERENCES users(id)")
                else:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id)")
        # Live-created memories: media bytes are stored as base64 in the database so they persist on Render with PostgreSQL.
        if DATABASE_URL:
            db.execute("""CREATE TABLE IF NOT EXISTS posts (
                id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK (kind IN ('post','reel')), title TEXT NOT NULL DEFAULT '',
                caption TEXT NOT NULL DEFAULT '', hashtags TEXT NOT NULL DEFAULT '', visibility TEXT NOT NULL DEFAULT 'private',
                media_type TEXT NOT NULL, media_data TEXT NOT NULL, media_size INTEGER NOT NULL DEFAULT 0,
                duration_seconds INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        else:
            db.execute("""CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK (kind IN ('post','reel')), title TEXT NOT NULL DEFAULT '',
                caption TEXT NOT NULL DEFAULT '', hashtags TEXT NOT NULL DEFAULT '', visibility TEXT NOT NULL DEFAULT 'private',
                media_type TEXT NOT NULL, media_data TEXT NOT NULL, media_size INTEGER NOT NULL DEFAULT 0,
                duration_seconds INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS posts_user_created_idx ON posts(user_id, created_at)")
        # Safe migrations for existing customer databases. Never drop existing tables or records.
        if DATABASE_URL:
            columns = {r['column_name'] for r in db.execute("SELECT column_name FROM information_schema.columns WHERE table_name='habits'").fetchall()}
        else:
            columns = {r['name'] for r in db.execute('PRAGMA table_info(habits)').fetchall()}
        if 'icon' not in columns:
            db.execute("ALTER TABLE habits ADD COLUMN icon TEXT NOT NULL DEFAULT '✳'")
        if 'schedule_json' not in columns:
            db.execute("ALTER TABLE habits ADD COLUMN schedule_json TEXT NOT NULL DEFAULT '{}'")
        # Allow different accounts to plan the same time slot without overwriting one another.
        if DATABASE_URL:
            db.execute("ALTER TABLE free_time_plans DROP CONSTRAINT IF EXISTS free_time_plans_plan_date_start_time_end_time_key")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS free_time_user_slot_uq ON free_time_plans(user_id, plan_date, start_time, end_time)")
        else:
            table_sql = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='free_time_plans'").fetchone()[0] or ""
            if 'UNIQUE(plan_date, start_time, end_time)' in table_sql.replace('\n',' '):
                db.execute("CREATE TABLE free_time_plans_new (id INTEGER PRIMARY KEY AUTOINCREMENT, plan_date TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL, intention TEXT NOT NULL, created_at TEXT NOT NULL, user_id INTEGER REFERENCES users(id), UNIQUE(user_id, plan_date, start_time, end_time))")
                db.execute("INSERT INTO free_time_plans_new(id,plan_date,start_time,end_time,intention,created_at,user_id) SELECT id,plan_date,start_time,end_time,intention,created_at,user_id FROM free_time_plans")
                db.execute("DROP TABLE free_time_plans")
                db.execute("ALTER TABLE free_time_plans_new RENAME TO free_time_plans")
            else:
                db.execute("CREATE UNIQUE INDEX IF NOT EXISTS free_time_user_slot_uq ON free_time_plans(user_id, plan_date, start_time, end_time)")
        count = db.execute("SELECT COUNT(*) FROM habits").fetchone()[0]
        if count == 0 and not DATABASE_URL:
            today = now_local().date().isoformat()
            created = now_local().isoformat(timespec="seconds")
            samples = [
                ("Morning hydration", "Health", "Drink water after waking up.", 5, "07:00"),
                ("Move your body", "Fitness", "Walk, stretch or train.", 30, "18:00"),
                ("Read and reflect", "Mind", "Read a few pages and note one idea.", 20, "21:00"),
            ]
            db.executemany("""INSERT INTO habits
                (name,category,description,target_minutes,reminder_time,reminder_days,start_date,created_at)
                VALUES (?,?,?,?,?,'0,1,2,3,4,5,6',?,?)""",
                [(n,c,d,m,t,today,created) for n,c,d,m,t in samples])


init_db()

# Add-on tables are created without deleting or replacing existing user data.
with connect() as db:
    if DATABASE_URL:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS nutrition_logs (
            id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            log_date TEXT NOT NULL, kind TEXT NOT NULL, item_name TEXT NOT NULL DEFAULT '',
            quantity REAL NOT NULL DEFAULT 0, water_ml INTEGER NOT NULL DEFAULT 0,
            calories REAL NOT NULL DEFAULT 0, protein_g REAL NOT NULL DEFAULT 0,
            carbs_g REAL NOT NULL DEFAULT 0, fat_g REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nutrition_goals (
            user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            water_target_ml INTEGER NOT NULL DEFAULT 2500, calories_target REAL NOT NULL DEFAULT 2000,
            protein_target_g REAL NOT NULL DEFAULT 50, carbs_target_g REAL NOT NULL DEFAULT 275,
            fat_target_g REAL NOT NULL DEFAULT 78, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS saved_outfits (
            id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL, occasion TEXT NOT NULL DEFAULT '', style TEXT NOT NULL DEFAULT '',
            top_item TEXT NOT NULL DEFAULT '', bottom_item TEXT NOT NULL DEFAULT '',
            footwear TEXT NOT NULL DEFAULT '', accessories TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        """)
    else:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS nutrition_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            log_date TEXT NOT NULL, kind TEXT NOT NULL, item_name TEXT NOT NULL DEFAULT '',
            quantity REAL NOT NULL DEFAULT 0, water_ml INTEGER NOT NULL DEFAULT 0,
            calories REAL NOT NULL DEFAULT 0, protein_g REAL NOT NULL DEFAULT 0,
            carbs_g REAL NOT NULL DEFAULT 0, fat_g REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nutrition_goals (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            water_target_ml INTEGER NOT NULL DEFAULT 2500, calories_target REAL NOT NULL DEFAULT 2000,
            protein_target_g REAL NOT NULL DEFAULT 50, carbs_target_g REAL NOT NULL DEFAULT 275,
            fat_target_g REAL NOT NULL DEFAULT 78, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS saved_outfits (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL, occasion TEXT NOT NULL DEFAULT '', style TEXT NOT NULL DEFAULT '',
            top_item TEXT NOT NULL DEFAULT '', bottom_item TEXT NOT NULL DEFAULT '',
            footwear TEXT NOT NULL DEFAULT '', accessories TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        """)


def get_day():
    value = request.args.get("date") or request.form.get("log_date") or now_local().date().isoformat()
    try:
        return date.fromisoformat(value)
    except ValueError:
        return now_local().date()

def habit_is_scheduled(habit, day):
    start = date.fromisoformat(habit["start_date"])
    end = date.fromisoformat(habit["end_date"]) if habit["end_date"] else None
    return start <= day and (end is None or day <= end)

WEEKDAYS = [(0, "Monday", "Mon"), (1, "Tuesday", "Tue"), (2, "Wednesday", "Wed"), (3, "Thursday", "Thu"), (4, "Friday", "Fri"), (5, "Saturday", "Sat"), (6, "Sunday", "Sun")]
ACTIVITY_ICONS = ["🏃", "💪", "🧘", "📚", "💻", "🥗", "💧", "🎨", "🎵", "🧠", "🧹", "👥", "🌿", "✍️", "✳"]

def read_schedule_form(form):
    schedule = {}
    for idx, _full, _short in WEEKDAYS:
        start = (form.get(f"schedule_{idx}_start") or "").strip()
        end = (form.get(f"schedule_{idx}_end") or "").strip()
        if start and end and start < end:
            schedule[str(idx)] = {"start": start, "end": end}
    return json.dumps(schedule, ensure_ascii=False)

def build_free_time(day):
    day_key = str(day.weekday())
    start_of_day, end_of_day = "06:00", "23:00"
    with connect() as db:
        habits = db.execute("SELECT * FROM habits WHERE active=1 AND user_id=?", (current_user_id(),)).fetchall()
        plans = db.execute("SELECT * FROM free_time_plans WHERE plan_date=? AND user_id=? ORDER BY start_time", (day.isoformat(), current_user_id())).fetchall()
    busy = []
    for h in habits:
        if not habit_is_scheduled(h, day):
            continue
        try:
            slot = json.loads(h["schedule_json"] or "{}").get(day_key)
        except (ValueError, TypeError):
            slot = None
        if slot and slot.get("start") and slot.get("end") and slot["start"] < slot["end"]:
            busy.append((slot["start"], slot["end"], h["name"]))
    busy.sort()
    if not busy:
        return [], 0, []
    merged = []
    for start, end, name in busy:
        if merged and start < merged[-1][1]:
            prev = merged[-1]
            merged[-1] = (prev[0], max(prev[1], end), prev[2] + ", " + name)
        else:
            merged.append((start, end, name))
    gaps, cursor = [], start_of_day
    def minutes_between(a, b):
        ah, am = map(int, a.split(":")); bh, bm = map(int, b.split(":"))
        return (bh * 60 + bm) - (ah * 60 + am)
    def add_gap(a, b):
        if minutes_between(a, b) >= 15:
            gaps.append({"start": a, "end": b, "minutes": minutes_between(a, b), "hours": round(minutes_between(a,b)/60, 1)})
    for start, end, _name in merged:
        if start > cursor:
            add_gap(cursor, start)
        if end > cursor:
            cursor = end
    if cursor < end_of_day:
        add_gap(cursor, end_of_day)
    plan_map = {(p["start_time"], p["end_time"]): p["intention"] for p in plans}
    for gap in gaps:
        gap["intention"] = plan_map.get((gap["start"], gap["end"]), "")
    return gaps, sum(g["minutes"] for g in gaps), busy

def dashboard_data(day):
    with connect() as db:
        habits = db.execute("SELECT * FROM habits WHERE active=1 AND user_id=? ORDER BY id DESC", (current_user_id(),)).fetchall()
        logs = db.execute("SELECT * FROM logs WHERE log_date=? AND user_id=?", (day.isoformat(), current_user_id())).fetchall()
        log_map = {r["habit_id"]: r for r in logs}
        scheduled = []
        for h in habits:
            if not habit_is_scheduled(h, day):
                continue
            try:
                weekly = json.loads(h["schedule_json"] or "{}")
            except (ValueError, TypeError):
                weekly = {}
            # Once a customer defines any weekday slots, show this activity only on days with a slot.
            if weekly and str(day.weekday()) not in weekly:
                continue
            scheduled.append(h)
        completed = sum(1 for h in scheduled if h["id"] in log_map and log_map[h["id"]]["status"] == "done")
        planned = len(scheduled)
        score = round(100 * completed / planned) if planned else 0
        week_start = day - timedelta(days=6)
        week_logs = db.execute("""
          SELECT log_date, COUNT(*) AS done_count FROM logs
          WHERE log_date BETWEEN ? AND ? AND status='done' AND user_id=? GROUP BY log_date
        """, (week_start.isoformat(), day.isoformat(), current_user_id())).fetchall()
        week_map = {r["log_date"]: r["done_count"] for r in week_logs}
        week = []
        for offset in range(6, -1, -1):
            d = day - timedelta(days=offset)
            week.append({"label": d.strftime("%a"), "date": d.isoformat(), "count": week_map.get(d.isoformat(), 0)})
        active_experiments = db.execute("SELECT * FROM experiments WHERE status='active' AND user_id=? ORDER BY start_date DESC", (current_user_id(),)).fetchall()
        recent = db.execute("""SELECT logs.*, habits.name AS habit_name FROM logs
          JOIN habits ON habits.id=logs.habit_id WHERE logs.user_id=? ORDER BY updated_at DESC LIMIT 6""", (current_user_id(),)).fetchall()
    rows = []
    for h in scheduled:
        log = log_map.get(h["id"])
        try:
            saved_schedule = json.loads(h["schedule_json"] or "{}")
        except (ValueError, TypeError):
            saved_schedule = {}
        rows.append({
            "habit": h,
            "schedule": saved_schedule,
            "schedule_today": saved_schedule.get(str(day.weekday())),
            "status": log["status"] if log else "pending",
            "minutes": log["minutes"] if log else 0,
            "note": log["note"] if log else "",
        })
    return rows, completed, planned, score, week, active_experiments, recent

def establish_session(user):
    session.clear()
    session["user_id"] = int(user["id"])
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user_id():
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            establish_session(user)
            target = request.args.get("next", "")
            if not target.startswith("/") or target.startswith("//"):
                target = url_for("index")
            return redirect(target)
        flash("Email or password was not correct.", "error")
    return render_template("login.html", mode="login")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user_id():
        return redirect(url_for("index"))
    if request.method == "POST":
        name = request.form.get("display_name", "").strip()[:80]
        email = request.form.get("email", "").strip().lower()[:254]
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        goal = request.form.get("primary_goal", "Build consistent habits").strip()[:160]
        interests = ", ".join(request.form.getlist("interests"))[:500]
        coach_style = request.form.get("coach_style", "encouraging")
        if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            flash("Enter your name and a valid email address.", "error")
        elif len(password) < 12:
            flash("Choose a password with at least 12 characters.", "error")
        elif password != confirm:
            flash("The passwords do not match.", "error")
        elif coach_style not in {"encouraging", "direct", "calm"}:
            flash("Choose a valid coach style.", "error")
        else:
            try:
                with connect() as db:
                    prior_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                    cur = db.execute("INSERT INTO users(display_name,email,password_hash,primary_goal,interests,coach_style,created_at) VALUES(?,?,?,?,?,?,?)",
                        (name, email, generate_password_hash(password), goal or "Build consistent habits", interests, coach_style, now_local().isoformat(timespec="seconds")))
                    # First account adopts legacy unowned records, preserving the pre-account prototype data.
                    if prior_users == 0:
                        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                        uid = user["id"]
                        for table in ("habits", "logs", "experiments", "experiment_logs", "free_time_plans"):
                            db.execute(f"UPDATE {table} SET user_id=? WHERE user_id IS NULL", (uid,))
                with connect() as db:
                    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                establish_session(user)
                flash("Your private growth space is ready. Your data belongs to your account.", "success")
                return redirect(url_for("index"))
            except Exception as exc:
                if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                    flash("An account with that email already exists. Please sign in.", "error")
                else:
                    app.logger.exception("Signup failed")
                    flash("We couldn't create the account. Please try again.", "error")
    return render_template("login.html", mode="signup")

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    uid = current_user_id()
    if request.method == "POST":
        name = request.form.get("display_name", "").strip()[:80]
        goal = request.form.get("primary_goal", "").strip()[:160]
        interests = ", ".join(request.form.getlist("interests"))[:500]
        coach_style = request.form.get("coach_style", "encouraging")
        if not name or coach_style not in {"encouraging", "direct", "calm"}:
            flash("Please enter a name and choose a valid coaching style.", "error")
        else:
            with connect() as db:
                db.execute("UPDATE users SET display_name=?, primary_goal=?, interests=?, coach_style=? WHERE id=?",
                           (name, goal or "Build consistent habits", interests, coach_style, uid))
            flash("Your personal growth preferences have been saved.", "success")
            return redirect(url_for("profile"))
    with connect() as db:
        user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return render_template("profile.html", user=user, selected_interests=[x.strip() for x in (user["interests"] or "").split(",") if x.strip()])

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def index():
    day = get_day()
    rows, completed, planned, score, week, experiments, recent = dashboard_data(day)
    free_gaps, free_minutes, busy_slots = build_free_time(day)
    with connect() as db:
        profile = db.execute("SELECT display_name, primary_goal, interests, coach_style FROM users WHERE id=?", (current_user_id(),)).fetchone()
    return render_template("index.html", profile=profile, selected_date=day.isoformat(), display_date=day.strftime("%A, %d %B %Y"),
        rows=rows, completed=completed, planned=planned, score=score, week=week,
        experiments=experiments, recent=recent, timezone_name=DEFAULT_TZ,
        today=now_local().date().isoformat(), weekdays=WEEKDAYS, activity_icons=ACTIVITY_ICONS,
        free_gaps=free_gaps, free_minutes=free_minutes, busy_slots=busy_slots)

@app.post("/habits/add")
def add_habit():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Give your activity a name first.", "error")
        return redirect(url_for("index"))
    try:
        minutes = max(1, min(1440, int(request.form.get("target_minutes", "15"))))
    except ValueError:
        minutes = 15
    reminder = request.form.get("reminder_time", "").strip()
    days = request.form.getlist("reminder_days")
    days_str = ",".join(str(int(d)) for d in days if d.isdigit() and 0 <= int(d) <= 6) or "0,1,2,3,4,5,6"
    start = request.form.get("start_date") or now_local().date().isoformat()
    end = request.form.get("end_date", "").strip()
    try:
        date.fromisoformat(start)
        if end:
            date.fromisoformat(end)
            if end < start:
                raise ValueError()
    except ValueError:
        flash("Please check the activity start/end dates.", "error")
        return redirect(url_for("index"))
    with connect() as db:
        db.execute("""INSERT INTO habits(name,category,description,target_minutes,reminder_time,reminder_days,icon,schedule_json,start_date,end_date,created_at,user_id)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (name, request.form.get("category","Growth"), request.form.get("description","").strip(),
           minutes, reminder, days_str, request.form.get("icon", "✳"), read_schedule_form(request.form), start, end, now_local().isoformat(timespec="seconds"), current_user_id()))
    flash("Activity added. You can log it each day.", "success")
    return redirect(url_for("index", date=start))

@app.post("/habits/<int:habit_id>/log")
def log_habit(habit_id):
    day = request.form.get("log_date") or now_local().date().isoformat()
    try:
        date.fromisoformat(day)
    except ValueError:
        day = now_local().date().isoformat()
    status = request.form.get("status", "done")
    if status not in ("done", "missed", "skipped"):
        status = "done"
    try:
        minutes = max(0, min(1440, int(request.form.get("minutes", "0"))))
    except ValueError:
        minutes = 0
    note = request.form.get("note", "").strip()[:500]
    with connect() as db:
        exists = db.execute("SELECT id FROM habits WHERE id=? AND user_id=?", (habit_id, current_user_id())).fetchone()
        if not exists:
            flash("That activity no longer exists.", "error")
            return redirect(url_for("index", date=day))
        db.execute("""INSERT INTO logs(habit_id,log_date,status,minutes,note,updated_at,user_id)
          VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(habit_id,log_date) DO UPDATE SET status=excluded.status, minutes=excluded.minutes,
          note=excluded.note, updated_at=excluded.updated_at""",
          (habit_id, day, status, minutes, note, now_local().isoformat(timespec="seconds"), current_user_id()))
    flash("Daily record saved.", "success")
    return redirect(url_for("index", date=day))

@app.post("/habits/<int:habit_id>/edit")
def edit_habit(habit_id):
    name = request.form.get("name", "").strip()
    if not name:
        flash("Activity name cannot be blank.", "error")
        return redirect(url_for("index"))
    try:
        minutes = max(1, min(1440, int(request.form.get("target_minutes", "15"))))
    except ValueError:
        minutes = 15
    with connect() as db:
        db.execute("""UPDATE habits SET name=?, category=?, description=?, target_minutes=?, reminder_time=?,
          reminder_days=?, icon=?, schedule_json=?, start_date=?, end_date=? WHERE id=? AND user_id=?""",
          (name, request.form.get("category","Growth"), request.form.get("description","").strip(),
           minutes, request.form.get("reminder_time",""), ",".join(request.form.getlist("reminder_days")) or "0,1,2,3,4,5,6",
           request.form.get("icon", "✳"), read_schedule_form(request.form),
           request.form.get("start_date") or now_local().date().isoformat(), request.form.get("end_date",""), habit_id, current_user_id()))
    flash("Activity updated.", "success")
    return redirect(url_for("index"))

@app.post("/habits/<int:habit_id>/archive")
def archive_habit(habit_id):
    with connect() as db:
        db.execute("UPDATE habits SET active=0 WHERE id=? AND user_id=?", (habit_id, current_user_id()))
    flash("Activity archived. Past records are preserved.", "success")
    return redirect(url_for("index"))

@app.route("/lab")
def lab():
    today = now_local().date()
    with connect() as db:
        experiments = db.execute("SELECT * FROM experiments WHERE user_id=? ORDER BY created_at DESC", (current_user_id(),)).fetchall()
        exp_rows = []
        for e in experiments:
            logs = db.execute("SELECT * FROM experiment_logs WHERE experiment_id=? AND user_id=? ORDER BY log_date", (e["id"], current_user_id())).fetchall()
            elapsed = max(0, min(e["duration_days"], (today - date.fromisoformat(e["start_date"])).days + 1))
            exp_rows.append({"experiment": e, "logs": logs, "elapsed": elapsed,
                             "progress": round(elapsed / e["duration_days"] * 100) if e["duration_days"] else 0})
    return render_template("lab.html", experiments=exp_rows, today=today.isoformat())

@app.post("/experiments/add")
def add_experiment():
    title = request.form.get("title", "").strip()
    if not title:
        flash("Name your experiment first.", "error")
        return redirect(url_for("lab"))
    try:
        raw_duration = request.form.get("custom_duration", "").strip() or request.form.get("duration_days", "30")
        duration = max(1, min(365, int(raw_duration)))
    except ValueError:
        duration = 30
    try:
        start = date.fromisoformat(request.form.get("start_date") or now_local().date().isoformat())
    except ValueError:
        start = now_local().date()
    end = start + timedelta(days=duration - 1)
    with connect() as db:
        db.execute("""INSERT INTO experiments(title,hypothesis,duration_days,start_date,end_date,created_at,user_id)
          VALUES(?,?,?,?,?,?,?)""", (title, request.form.get("hypothesis","").strip(), duration,
          start.isoformat(), end.isoformat(), now_local().isoformat(timespec="seconds"), current_user_id()))
    flash("Your commitment period has started.", "success")
    return redirect(url_for("lab"))

@app.post("/experiments/<int:exp_id>/log")
def log_experiment(exp_id):
    day = request.form.get("log_date") or now_local().date().isoformat()
    try:
        date.fromisoformat(day)
    except ValueError:
        day = now_local().date().isoformat()
    try:
        rating = max(1, min(5, int(request.form.get("rating","3"))))
    except ValueError:
        rating = 3
    with connect() as db:
        exp = db.execute("SELECT * FROM experiments WHERE id=? AND user_id=?", (exp_id, current_user_id())).fetchone()
        if not exp:
            flash("Experiment not found.", "error")
            return redirect(url_for("lab"))
        # Only allow records inside the commitment dates, preserving an honest timeline.
        if day < exp["start_date"] or day > exp["end_date"]:
            flash("That date is outside this experiment's commitment period.", "error")
            return redirect(url_for("lab"))
        db.execute("""INSERT INTO experiment_logs(experiment_id,log_date,outcome,rating,note,user_id) VALUES(?,?,?,?,?,?)
          ON CONFLICT(experiment_id,log_date) DO UPDATE SET outcome=excluded.outcome,rating=excluded.rating,note=excluded.note""",
          (exp_id, day, request.form.get("outcome","completed"), rating, request.form.get("note","").strip()[:500], current_user_id()))
    flash("Experiment evidence saved.", "success")
    return redirect(url_for("lab"))

@app.post("/experiments/<int:exp_id>/finish")
def finish_experiment(exp_id):
    with connect() as db:
        db.execute("UPDATE experiments SET status='completed' WHERE id=? AND user_id=?", (exp_id, current_user_id()))
    flash("Experiment marked complete. Its history remains available.", "success")
    return redirect(url_for("lab"))

@app.post("/free-time/plan")
def save_free_time_plan():
    day = request.form.get("plan_date") or now_local().date().isoformat()
    start, end = request.form.get("start_time", ""), request.form.get("end_time", "")
    intention = request.form.get("intention", "").strip()[:300]
    try:
        date.fromisoformat(day)
        if not (start and end and start < end and intention):
            raise ValueError()
    except ValueError:
        flash("Choose a valid free-time slot and say how you want to use it.", "error")
        return redirect(url_for("index", date=day))
    with connect() as db:
        db.execute("""INSERT INTO free_time_plans(plan_date,start_time,end_time,intention,created_at,user_id) VALUES(?,?,?,?,?,?)
          ON CONFLICT(user_id,plan_date,start_time,end_time) DO UPDATE SET intention=excluded.intention,created_at=excluded.created_at""",
          (day, start, end, intention, now_local().isoformat(timespec="seconds"), current_user_id()))
    flash("Your free-time intention has been saved.", "success")
    return redirect(url_for("index", date=day))

@app.get("/api/reminders")
def reminders():
    day = now_local().date()
    weekday = str(day.weekday())
    with connect() as db:
        habits = db.execute("""SELECT id,name,reminder_time,reminder_days,start_date,end_date FROM habits
          WHERE active=1 AND reminder_time != '' AND user_id=?""", (current_user_id(),)).fetchall()
        logs = db.execute("SELECT habit_id,status FROM logs WHERE log_date=? AND user_id=?", (day.isoformat(), current_user_id())).fetchall()
    log_map = {r["habit_id"]: r["status"] for r in logs}
    result = []
    for h in habits:
        if weekday not in h["reminder_days"].split(",") or day.isoformat() < h["start_date"] or (h["end_date"] and day.isoformat() > h["end_date"]):
            continue
        if log_map.get(h["id"]) == "done":
            continue
        result.append({"id": h["id"], "name": h["name"], "time": h["reminder_time"]})
    return jsonify({"date": day.isoformat(), "timezone": DEFAULT_TZ, "reminders": result})

@app.get("/feed")
def feed():
    with connect() as db:
        posts = db.execute("SELECT posts.id, posts.user_id, posts.kind, posts.title, posts.caption, posts.hashtags, posts.visibility, posts.media_type, posts.media_size, posts.duration_seconds, posts.created_at, posts.updated_at, users.display_name FROM posts JOIN users ON users.id=posts.user_id WHERE posts.user_id=? OR posts.visibility='public' ORDER BY posts.created_at DESC LIMIT 60", (current_user_id(),)).fetchall()
    return render_template("feed.html", posts=posts)

@app.post("/post/create")
def create_post():
    upload = request.files.get("media_file")
    kind = request.form.get("kind", "post")
    title = request.form.get("title", "").strip()[:100]
    caption = request.form.get("caption", "").strip()[:2200]
    hashtags_raw = request.form.get("hashtags", "").strip()[:300]
    visibility = request.form.get("visibility", "private")
    duration = request.form.get("duration_seconds", "0")
    try: duration = max(0, min(90, int(duration or 0)))
    except ValueError: duration = 0
    if kind not in {"post", "reel"} or visibility not in {"private", "followers", "public"}:
        flash("Choose a valid post type and audience.", "error"); return redirect(url_for("feed"))
    if not upload or not upload.filename:
        flash("Capture a photo or record a reel before publishing.", "error"); return redirect(url_for("feed"))
    media_type = (upload.mimetype or "").lower()
    if kind == "post" and media_type not in {"image/jpeg", "image/png", "image/webp"}:
        flash("A post needs a captured photo (JPEG, PNG or WebP).", "error"); return redirect(url_for("feed"))
    if kind == "reel" and not media_type.startswith("video/"):
        flash("A reel needs a recorded video.", "error"); return redirect(url_for("feed"))
    max_bytes = 8 * 1024 * 1024 if kind == "post" else 18 * 1024 * 1024
    raw = upload.read(max_bytes + 1)
    if not raw or len(raw) > max_bytes:
        flash("Photo limit is 8 MB; reel limit is 18 MB. Record a shorter clip or use a smaller capture.", "error"); return redirect(url_for("feed"))
    if kind == "reel" and not 1 <= duration <= 90:
        flash("Reels must be between 1 and 90 seconds.", "error"); return redirect(url_for("feed"))
    media_data = base64.b64encode(raw).decode("ascii")
    now = now_local().isoformat(timespec="seconds")
    # Normalize hashtags to simple, readable tags rather than accepting arbitrary formatting.
    tags = " ".join(dict.fromkeys("#" + re.sub(r"[^\w]", "", tag.lstrip("#")) for tag in re.findall(r"#?[^\s#]+", hashtags_raw) if re.sub(r"[^\w]", "", tag.lstrip("#"))))[:300]
    with connect() as db:
        db.execute("INSERT INTO posts(user_id,kind,title,caption,hashtags,visibility,media_type,media_data,media_size,duration_seconds,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (current_user_id(), kind, title, caption, tags, visibility, media_type, media_data, len(raw), duration, now, now))
    flash("Your memory is published to your personal feed.", "success")
    return redirect(url_for("feed"))

@app.get("/post/<int:post_id>/media")
def post_media(post_id):
    with connect() as db:
        post = db.execute("SELECT user_id, visibility, media_type, media_data FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post or (post["user_id"] != current_user_id() and post["visibility"] != "public"): abort(404)
    try: raw = base64.b64decode(post["media_data"], validate=True)
    except Exception: abort(404)
    if not (post["media_type"].startswith("image/") or post["media_type"].startswith("video/")): abort(404)
    return send_file(BytesIO(raw), mimetype=post["media_type"], as_attachment=False, download_name=f"wild-within-{post_id}", max_age=0)

@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
def edit_post(post_id):
    with connect() as db:
        post = db.execute("SELECT * FROM posts WHERE id=? AND user_id=?", (post_id, current_user_id())).fetchone()
        if not post: abort(404)
        if request.method == "POST":
            title = request.form.get("title", "").strip()[:100]
            caption = request.form.get("caption", "").strip()[:2200]
            hashtags_raw = request.form.get("hashtags", "").strip()[:300]
            visibility = request.form.get("visibility", "private")
            if visibility not in {"private", "followers", "public"}:
                flash("Choose a valid audience.", "error")
            else:
                tags = " ".join(dict.fromkeys("#" + re.sub(r"[^\w]", "", tag.lstrip("#")) for tag in re.findall(r"#?[^\s#]+", hashtags_raw) if re.sub(r"[^\w]", "", tag.lstrip("#"))))[:300]
                db.execute("UPDATE posts SET title=?,caption=?,hashtags=?,visibility=?,updated_at=? WHERE id=? AND user_id=?",
                    (title, caption, tags, visibility, now_local().isoformat(timespec="seconds"), post_id, current_user_id()))
                flash("Memory details updated. Your original capture is unchanged.", "success")
                return redirect(url_for("feed"))
    return render_template("edit_post.html", post=post)

@app.post("/post/<int:post_id>/delete")
def delete_post(post_id):
    with connect() as db:
        cur = db.execute("DELETE FROM posts WHERE id=? AND user_id=?", (post_id, current_user_id()))
        if cur.rowcount:
            flash("Memory deleted from your feed.", "success")
        else:
            abort(404)
    return redirect(url_for("feed"))

@app.get("/api/admin/snapshot")
def admin_snapshot():
    """Authenticated cloud-to-PC snapshot endpoint used by the local mirror agent."""
    import hmac
    token = os.environ.get("SYNC_TOKEN", "")
    supplied = request.headers.get("Authorization", "")
    if not token or not hmac.compare_digest(supplied, "Bearer " + token):
        return jsonify({"error": "unauthorized"}), 401
    email = os.environ.get("SYNC_USER_EMAIL", "").strip().lower()
    if not email:
        return jsonify({"error": "SYNC_USER_EMAIL must identify the one account allowed to sync to this PC."}), 503
    tables = ("habits", "logs", "experiments", "experiment_logs", "free_time_plans", "posts")
    payload = {"generated_at": now_local().isoformat(), "tables": {}}
    with connect() as db:
        user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            return jsonify({"error": "Configured sync account was not found."}), 404
        for table in tables:
            payload["tables"][table] = [dict(row) for row in db.execute(f"SELECT * FROM {table} WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()]
    return jsonify(payload)


FOOD_LIBRARY = [
    {"name":"Oats, dry","region":"Global","calories":389,"protein":16.9,"carbs":66.3,"fat":6.9},
    {"name":"Rice, cooked","region":"Global","calories":130,"protein":2.7,"carbs":28.2,"fat":0.3},
    {"name":"Whole-wheat roti","region":"South Asia","calories":297,"protein":9.8,"carbs":55.0,"fat":7.5},
    {"name":"Dal, cooked","region":"South Asia","calories":116,"protein":9.0,"carbs":20.1,"fat":0.4},
    {"name":"Paneer","region":"South Asia","calories":265,"protein":18.3,"carbs":1.2,"fat":20.8},
    {"name":"Plain yogurt","region":"Global","calories":61,"protein":3.5,"carbs":4.7,"fat":3.3},
    {"name":"Egg, boiled","region":"Global","calories":155,"protein":12.6,"carbs":1.1,"fat":10.6},
    {"name":"Chicken breast, cooked","region":"Global","calories":165,"protein":31.0,"carbs":0,"fat":3.6},
    {"name":"Salmon, cooked","region":"Global","calories":206,"protein":22.1,"carbs":0,"fat":12.4},
    {"name":"Tofu","region":"East Asia","calories":76,"protein":8.1,"carbs":1.9,"fat":4.8},
    {"name":"Lentils, cooked","region":"Global","calories":116,"protein":9.0,"carbs":20.1,"fat":0.4},
    {"name":"Chickpeas, cooked","region":"Middle East / South Asia","calories":164,"protein":8.9,"carbs":27.4,"fat":2.6},
    {"name":"Apple","region":"Global","calories":52,"protein":0.3,"carbs":13.8,"fat":0.2},
    {"name":"Banana","region":"Global","calories":89,"protein":1.1,"carbs":22.8,"fat":0.3},
    {"name":"Mango","region":"South Asia","calories":60,"protein":0.8,"carbs":15.0,"fat":0.4},
    {"name":"Avocado","region":"Americas","calories":160,"protein":2.0,"carbs":8.5,"fat":14.7},
    {"name":"Almonds","region":"Global","calories":579,"protein":21.2,"carbs":21.6,"fat":49.9},
    {"name":"Peanuts","region":"Global","calories":567,"protein":25.8,"carbs":16.1,"fat":49.2},
    {"name":"Spinach, cooked","region":"Global","calories":23,"protein":3.0,"carbs":3.8,"fat":0.3},
    {"name":"Potato, boiled","region":"Global","calories":87,"protein":1.9,"carbs":20.1,"fat":0.1},
    {"name":"Olive oil","region":"Mediterranean","calories":884,"protein":0,"carbs":0,"fat":100},
    {"name":"Corn tortilla","region":"Latin America","calories":218,"protein":5.7,"carbs":44.6,"fat":2.9},
    {"name":"Quinoa, cooked","region":"South America","calories":120,"protein":4.4,"carbs":21.3,"fat":1.9},
    {"name":"Kimchi","region":"Korea","calories":15,"protein":1.1,"carbs":2.4,"fat":0.5},
    {"name":"Sourdough bread","region":"Europe","calories":289,"protein":11.0,"carbs":56.0,"fat":2.0},
    {"name":"Falafel","region":"Middle East","calories":333,"protein":13.3,"carbs":31.8,"fat":17.8},
    {"name":"Couscous, cooked","region":"North Africa","calories":112,"protein":3.8,"carbs":23.2,"fat":0.2},
    {"name":"Edamame, cooked","region":"East Asia","calories":121,"protein":11.9,"carbs":8.9,"fat":5.2},
    {"name":"Sweet potato, baked","region":"Global","calories":90,"protein":2.0,"carbs":20.7,"fat":0.2},
    {"name":"Kidney beans, cooked","region":"Global","calories":127,"protein":8.7,"carbs":22.8,"fat":0.5},
    {"name":"Black beans, cooked","region":"Americas","calories":132,"protein":8.9,"carbs":23.7,"fat":0.5},
    {"name":"Black-eyed peas, cooked","region":"Africa / Americas","calories":116,"protein":7.7,"carbs":20.8,"fat":0.5},
    {"name":"Millet, cooked","region":"Africa / South Asia","calories":119,"protein":3.5,"carbs":23.7,"fat":1.0},
    {"name":"Bajra pearl millet, cooked","region":"South Asia","calories":119,"protein":3.5,"carbs":23.7,"fat":1.0},
    {"name":"Ragi finger millet, flour","region":"South Asia","calories":336,"protein":7.3,"carbs":72.0,"fat":1.5},
    {"name":"Barley, cooked","region":"Global","calories":123,"protein":2.3,"carbs":28.2,"fat":0.4},
    {"name":"Broccoli, cooked","region":"Global","calories":35,"protein":2.4,"carbs":7.2,"fat":0.4},
    {"name":"Carrot, raw","region":"Global","calories":41,"protein":0.9,"carbs":9.6,"fat":0.2},
    {"name":"Orange","region":"Global","calories":47,"protein":0.9,"carbs":11.8,"fat":0.1},
    {"name":"Strawberries","region":"Global","calories":32,"protein":0.7,"carbs":7.7,"fat":0.3},
    {"name":"Dates, dried","region":"Middle East / North Africa","calories":282,"protein":2.5,"carbs":75.0,"fat":0.4},
    {"name":"Whole milk","region":"Global","calories":61,"protein":3.2,"carbs":4.8,"fat":3.3},
    {"name":"Cheddar cheese","region":"Europe","calories":403,"protein":25.0,"carbs":1.3,"fat":33.1},
    {"name":"Beef, cooked lean","region":"Global","calories":217,"protein":26.1,"carbs":0,"fat":11.8},
    {"name":"Pork, cooked lean","region":"Global","calories":196,"protein":29.0,"carbs":0,"fat":8.0},
    {"name":"Shrimp, cooked","region":"Global","calories":99,"protein":24.0,"carbs":0.2,"fat":0.3},
    {"name":"Tempeh","region":"Indonesia","calories":193,"protein":20.3,"carbs":7.6,"fat":10.8},
    {"name":"Hummus","region":"Middle East","calories":166,"protein":7.9,"carbs":14.3,"fat":9.6},
    {"name":"Pita bread","region":"Middle East / Mediterranean","calories":275,"protein":9.1,"carbs":55.7,"fat":1.2},
    {"name":"Bulgur, cooked","region":"Middle East","calories":83,"protein":3.1,"carbs":18.6,"fat":0.2},
    {"name":"Plantain, boiled","region":"Africa / Caribbean","calories":116,"protein":1.3,"carbs":31.2,"fat":0.2},
    {"name":"Cassava, boiled","region":"Africa / South America","calories":112,"protein":1.4,"carbs":27.8,"fat":0.3},
    {"name":"Miso paste","region":"Japan","calories":199,"protein":12.8,"carbs":26.5,"fat":6.0},
    {"name":"Soba noodles, cooked","region":"Japan","calories":99,"protein":5.1,"carbs":21.4,"fat":0.1},
    {"name":"Injera","region":"Ethiopia / Eritrea","calories":130,"protein":4.0,"carbs":27.0,"fat":0.5}
]

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:254]
        generic = "If an account matches that email and email delivery is configured, a reset link will arrive shortly."
        with connect() as db:
            user = db.execute("SELECT id,email FROM users WHERE email=?", (email,)).fetchone()
            if user and os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM"):
                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                expiry = (now_local() + timedelta(minutes=30)).isoformat(timespec="seconds")
                db.execute("UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at=''", (now_local().isoformat(timespec="seconds"), user["id"]))
                db.execute("INSERT INTO password_reset_tokens(user_id,token_hash,expires_at,used_at) VALUES(?,?,?,'')", (user["id"], token_hash, expiry))
                try:
                    msg = EmailMessage()
                    msg["Subject"] = "Reset your WILD WITHIN password"
                    msg["From"] = os.environ["SMTP_FROM"]
                    msg["To"] = user["email"]
                    reset_url = url_for("reset_password", token=raw_token, _external=True, _scheme="https" if os.environ.get("RENDER") else "http")
                    msg.set_content("Use this one-time link within 30 minutes to reset your password:\n\n" + reset_url + "\n\nIf you did not request this, ignore this email.")
                    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587")), timeout=15) as server:
                        server.starttls()
                        smtp_user = os.environ.get("SMTP_USER", "")
                        if smtp_user:
                            server.login(smtp_user, os.environ.get("SMTP_PASSWORD", ""))
                        server.send_message(msg)
                except Exception:
                    app.logger.exception("Password-reset email delivery failed")
        flash(generic, "success")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        record = db.execute("SELECT id,user_id,expires_at,used_at FROM password_reset_tokens WHERE token_hash=?", (token_hash,)).fetchone()
    valid = bool(record and not record["used_at"] and record["expires_at"] > now_local().isoformat(timespec="seconds"))
    if not valid:
        flash("That reset link is invalid or expired. Request a new one.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 12:
            flash("Choose a password with at least 12 characters.", "error")
        elif password != confirm:
            flash("The passwords do not match.", "error")
        else:
            with connect() as db:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), record["user_id"]))
                db.execute("UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at=''", (now_local().isoformat(timespec="seconds"), record["user_id"]))
            flash("Your password has been reset. Sign in with your new password.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)

@app.route("/wellness", methods=["GET", "POST"])
def wellness():
    uid = current_user_id()
    today = now_local().date().isoformat()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "goals":
            try:
                goals = (
                    max(0, min(10000, int(request.form.get("water_target_ml", "2500")))),
                    max(0, min(10000, float(request.form.get("calories_target", "2000")))),
                    max(0, min(1000, float(request.form.get("protein_target_g", "50")))),
                    max(0, min(2000, float(request.form.get("carbs_target_g", "275")))),
                    max(0, min(1000, float(request.form.get("fat_target_g", "78"))))
                )
                with connect() as db:
                    db.execute("INSERT INTO nutrition_goals(user_id,water_target_ml,calories_target,protein_target_g,carbs_target_g,fat_target_g,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET water_target_ml=excluded.water_target_ml,calories_target=excluded.calories_target,protein_target_g=excluded.protein_target_g,carbs_target_g=excluded.carbs_target_g,fat_target_g=excluded.fat_target_g,updated_at=excluded.updated_at",
                        (uid,*goals,now_local().isoformat(timespec="seconds")))
                flash("Your daily nutrition targets were saved.", "success")
            except (ValueError, TypeError):
                flash("Please enter valid nutrition targets.", "error")
        elif action == "water":
            try:
                amount = max(1, min(5000, int(request.form.get("water_ml", "250"))))
            except ValueError:
                amount = 250
            with connect() as db:
                db.execute("INSERT INTO nutrition_logs(user_id,log_date,kind,item_name,quantity,water_ml,created_at) VALUES(?,?,?,?,?,?,?)",
                    (uid,today,"water","Water",amount,amount,now_local().isoformat(timespec="seconds")))
            flash("Water intake saved.", "success")
        elif action == "food":
            name = request.form.get("food_name", "").strip()
            try:
                grams = max(1, min(3000, float(request.form.get("quantity", "100"))))
            except ValueError:
                grams = 100
            food = next((f for f in FOOD_LIBRARY if f["name"] == name), None)
            if food:
                factor = grams / 100.0
                with connect() as db:
                    db.execute("INSERT INTO nutrition_logs(user_id,log_date,kind,item_name,quantity,calories,protein_g,carbs_g,fat_g,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (uid,today,"food",name,grams,round(food["calories"]*factor,1),round(food["protein"]*factor,1),round(food["carbs"]*factor,1),round(food["fat"]*factor,1),now_local().isoformat(timespec="seconds")))
                flash("Food entry saved to today's log.", "success")
            else:
                flash("Choose a food from the library.", "error")
        return redirect(url_for("wellness"))
    q = request.args.get("q", "").strip().lower()
    foods = [f for f in FOOD_LIBRARY if not q or q in f["name"].lower() or q in f["region"].lower()]
    with connect() as db:
        db.execute("INSERT INTO nutrition_goals(user_id,updated_at) VALUES(?,?) ON CONFLICT(user_id) DO NOTHING", (uid,now_local().isoformat(timespec="seconds")))
        goals = db.execute("SELECT * FROM nutrition_goals WHERE user_id=?", (uid,)).fetchone()
        rows = db.execute("SELECT * FROM nutrition_logs WHERE user_id=? AND log_date=? ORDER BY id DESC", (uid,today)).fetchall()
        totals = db.execute("SELECT COALESCE(SUM(water_ml),0) water_ml, COALESCE(SUM(calories),0) calories, COALESCE(SUM(protein_g),0) protein_g, COALESCE(SUM(carbs_g),0) carbs_g, COALESCE(SUM(fat_g),0) fat_g FROM nutrition_logs WHERE user_id=? AND log_date=?", (uid,today)).fetchone()
    return render_template("wellness.html", foods=foods, rows=rows, totals=totals, goals=goals, search=q, today=today)

@app.route("/fashion", methods=["GET", "POST"])
def fashion():
    uid = current_user_id()
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:100]
        if not title:
            flash("Give your outfit a name.", "error")
        else:
            fields = [request.form.get(k, "").strip()[:500] for k in ("occasion","style","top_item","bottom_item","footwear","accessories","notes")]
            with connect() as db:
                db.execute("INSERT INTO saved_outfits(user_id,title,occasion,style,top_item,bottom_item,footwear,accessories,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (uid,title,*fields,now_local().isoformat(timespec="seconds")))
            flash("Outfit saved to your private fashion studio.", "success")
        return redirect(url_for("fashion"))
    with connect() as db:
        outfits = db.execute("SELECT * FROM saved_outfits WHERE user_id=? ORDER BY id DESC LIMIT 50", (uid,)).fetchall()
    return render_template("fashion.html", outfits=outfits)

@app.get("/health")
def health():
    return jsonify({"ok": True, "app": "WILD WITHIN"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
