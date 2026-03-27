import os
import hashlib
import secrets
import string
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger("signage_rev.db")

DATABASE_URL = os.environ.get("DATABASE_URL")
USE_PG = bool(DATABASE_URL)

if USE_PG:
    import psycopg2
    import psycopg2.extras
else:
    import sqlite3


def hash_password(password: str, salt: str = None):
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
    return hashed, salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    check, _ = hash_password(password, salt)
    return secrets.compare_digest(check, hashed)


class Database:
    def __init__(self, sqlite_path: str = "signage_rev.db"):
        self.sqlite_path = sqlite_path

    def _conn(self):
        if USE_PG:
            url = DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
            conn.autocommit = False
            return conn
        else:
            conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn

    def _execute(self, conn, sql: str, params=()) -> list:
        if USE_PG:
            sql = sql.replace("?", "%s")
            cur = conn.cursor()
            cur.execute(sql, params)
            try:
                return [dict(r) for r in cur.fetchall()]
            except Exception:
                return []
        else:
            cur = conn.execute(sql, params)
            try:
                return [dict(r) for r in cur.fetchall()]
            except Exception:
                return []

    def init(self):
        conn = self._conn()
        try:
            self._create_tables(conn)
            self._migrate(conn)
            self._seed(conn)
            conn.commit()
            logger.info("Database initialized successfully.")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
        finally:
            conn.close()

    def _create_tables(self, conn):
        serial = "SERIAL" if USE_PG else "INTEGER"
        pk_auto = "PRIMARY KEY" if USE_PG else "PRIMARY KEY AUTOINCREMENT"
        now_fn = "now()::text" if USE_PG else "datetime('now')"
        stmts = [
            f"""CREATE TABLE IF NOT EXISTS admins (
                id              {serial} {pk_auto},
                username        TEXT    NOT NULL UNIQUE,
                password_hash   TEXT    NOT NULL,
                salt            TEXT    NOT NULL,
                role            TEXT    NOT NULL DEFAULT 'subadmin',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT    DEFAULT NULL,
                created_at      TEXT    DEFAULT ({now_fn})
            )""",
            f"""CREATE TABLE IF NOT EXISTS sessions (
                token        TEXT    PRIMARY KEY,
                admin_id     INTEGER NOT NULL,
                csrf_token   TEXT    NOT NULL,
                ip_address   TEXT    NOT NULL,
                user_agent   TEXT    NOT NULL,
                expires_at   TEXT    NOT NULL,
                last_active  TEXT    NOT NULL,
                created_at   TEXT    DEFAULT ({now_fn})
            )""",
            f"""CREATE TABLE IF NOT EXISTS audit_logs (
                id           {serial} {pk_auto},
                admin_id     INTEGER,
                action       TEXT    NOT NULL,
                target       TEXT    NOT NULL,
                ip_address   TEXT    NOT NULL,
                created_at   TEXT    DEFAULT ({now_fn})
            )""",
            f"""CREATE TABLE IF NOT EXISTS admin_screens (
                admin_id     INTEGER NOT NULL,
                screen_id    TEXT    NOT NULL,
                PRIMARY KEY (admin_id, screen_id)
            )""",
            f"""CREATE TABLE IF NOT EXISTS screen_groups (
                id         {serial} {pk_auto},
                name       TEXT    NOT NULL,
                created_at TEXT    DEFAULT ({now_fn})
            )""",
            f"""CREATE TABLE IF NOT EXISTS playlists (
                id                {serial} {pk_auto},
                name              TEXT    NOT NULL,
                fallback_url      TEXT    DEFAULT NULL,
                loop_duration     INTEGER NOT NULL DEFAULT 1800,
                fallback_duration INTEGER NOT NULL DEFAULT 300,
                created_at        TEXT    DEFAULT ({now_fn})
            )""",
            f"""CREATE TABLE IF NOT EXISTS slides (
                id               {serial} {pk_auto},
                playlist_id      INTEGER NOT NULL,
                type             TEXT    NOT NULL,
                url              TEXT    NOT NULL,
                title            TEXT    NOT NULL DEFAULT '',
                duration         INTEGER NOT NULL DEFAULT 15,
                position         INTEGER NOT NULL DEFAULT 0,
                active           INTEGER NOT NULL DEFAULT 1,
                sched_start      TEXT    DEFAULT NULL,
                sched_end        TEXT    DEFAULT NULL,
                days_of_week     TEXT    DEFAULT NULL,
                time_start       TEXT    DEFAULT NULL,
                time_end         TEXT    DEFAULT NULL,
                interrupt_every  INTEGER NOT NULL DEFAULT 0,
                interrupt_for    INTEGER NOT NULL DEFAULT 300,
                created_at       TEXT    DEFAULT ({now_fn})
            )""",
            f"""CREATE TABLE IF NOT EXISTS screens (
                id              TEXT    PRIMARY KEY,
                name            TEXT    NOT NULL DEFAULT 'Unnamed Screen',
                group_id        INTEGER DEFAULT NULL,
                playlist_id     INTEGER DEFAULT NULL,
                screen_token    TEXT    DEFAULT NULL,
                last_seen       TEXT    DEFAULT NULL,
                status          TEXT    NOT NULL DEFAULT 'offline',
                ip_address      TEXT    DEFAULT NULL,
                user_agent      TEXT    DEFAULT NULL,
                orientation     TEXT    NOT NULL DEFAULT 'landscape',
                rotation_dir    INTEGER NOT NULL DEFAULT 90,
                created_at      TEXT    DEFAULT ({now_fn})
            )""",
        ]
        for stmt in stmts: self._execute(conn, stmt)

    def _migrate(self, conn):
        if USE_PG:
            def col_exists(table, col):
                return len(self._execute(conn,
                                         "SELECT column_name FROM information_schema.columns WHERE table_name=? AND column_name=?",
                                         (table, col))) > 0

            def table_exists(table):
                return len(self._execute(conn, "SELECT table_name FROM information_schema.tables WHERE table_name=?",
                                         (table,))) > 0
        else:
            def col_exists(table, col):
                return any(r["name"] == col for r in self._execute(conn, f"PRAGMA table_info({table})"))

            def table_exists(table):
                return len(
                    self._execute(conn, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))) > 0

        migrations = [
            ("sessions", "ip_address", "TEXT DEFAULT ''"),
            ("sessions", "user_agent", "TEXT DEFAULT ''"),
            ("sessions", "csrf_token", "TEXT DEFAULT ''"),
            ("sessions", "last_active", "TEXT DEFAULT ''"),
            ("admins", "failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("admins", "locked_until", "TEXT DEFAULT NULL"),
            ("screens", "screen_token", "TEXT DEFAULT NULL"),
            ("playlists", "fallback_url", "TEXT DEFAULT NULL"),
            ("playlists", "loop_duration", "INTEGER NOT NULL DEFAULT 1800"),
            ("playlists", "fallback_duration", "INTEGER NOT NULL DEFAULT 300"),
            ("slides", "interrupt_every", "INTEGER NOT NULL DEFAULT 0"),
            ("slides", "interrupt_for", "INTEGER NOT NULL DEFAULT 300"),
            ("screens", "orientation", "TEXT NOT NULL DEFAULT 'landscape'"),
            ("screens", "rotation_dir", "INTEGER NOT NULL DEFAULT 90"),
        ]
        for table, col, defn in migrations:
            if table_exists(table) and not col_exists(table, col):
                self._execute(conn, f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
                logger.info(f"Migrated: Added {col} to {table}")

    def _seed(self, conn):
        rows = self._execute(conn, "SELECT COUNT(*) as c FROM admins")
        if rows[0]["c"] == 0:
            username = os.environ.get("ADMIN_USERNAME", "").strip() or "admin"
            password = os.environ.get("ADMIN_PASSWORD", "").strip()
            if not password:
                chars = string.ascii_letters + string.digits + "!@#$%^&*"
                password = "".join(secrets.choice(chars) for _ in range(16)) + "A1b!"
                print(f"\n================================================================")
                print("FIRST-RUN SETUP — Temporary Superadmin Account:")
                print(f"  Username : {username}\n  Password : {password}")
                print("================================================================\n", flush=True)

            hashed, salt = hash_password(password)
            self._execute(conn, "INSERT INTO admins (username, password_hash, salt, role) VALUES (?,?,?,?)",
                          (username, hashed, salt, "superadmin"))

        if self._execute(conn, "SELECT COUNT(*) as c FROM playlists")[0]["c"] == 0:
            self._execute(conn, "INSERT INTO screen_groups (name) VALUES (?)", ("Main Lobby",))
            p1 = self._execute(conn, "INSERT INTO playlists (name) VALUES (?) RETURNING id", ("Main",))[0]["id"]
            self._execute(conn,
                          "INSERT INTO slides (playlist_id,type,url,title,duration,position) VALUES (?,?,?,?,?,?)",
                          (p1, "image", "https://images.unsplash.com/photo-1557804506-669a67965ba0?w=1920", "Welcome",
                           10, 0))

    # ── Audit Logging ──────────────────────────────────────────────────────────
    def log_audit(self, admin_id: Optional[int], action: str, target: str, ip: str):
        conn = self._conn()
        try:
            self._execute(conn, "INSERT INTO audit_logs (admin_id, action, target, ip_address) VALUES (?,?,?,?)",
                          (admin_id, action, target, ip))
            conn.commit()
        finally:
            conn.close()

    # ── Admin Auth & Lockout ───────────────────────────────────────────────────
    def get_admin_by_username(self, username: str) -> Optional[Dict]:
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT * FROM admins WHERE username=?", (username,))
            return rows[0] if rows else None
        finally:
            conn.close()

    def get_admin_by_id(self, admin_id: int) -> Optional[Dict]:
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT * FROM admins WHERE id=?", (admin_id,))
            return rows[0] if rows else None
        finally:
            conn.close()

    def get_all_admins(self) -> List[Dict]:
        conn = self._conn()
        try:
            return self._execute(conn, "SELECT id, username, role, created_at, locked_until FROM admins ORDER BY id")
        finally:
            conn.close()

    def create_admin(self, username: str, password: str, role: str = "subadmin") -> Dict:
        hashed, salt = hash_password(password)
        conn = self._conn()
        try:
            rows = self._execute(conn,
                                 "INSERT INTO admins (username, password_hash, salt, role) VALUES (?,?,?,?) RETURNING id, username, role",
                                 (username, hashed, salt, role))
            conn.commit()
            return rows[0]
        finally:
            conn.close()

    def update_admin_password(self, admin_id: int, password: str):
        hashed, salt = hash_password(password)
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE admins SET password_hash=?, salt=? WHERE id=?", (hashed, salt, admin_id))
            conn.commit()
        finally:
            conn.close()

    def delete_admin(self, admin_id: int):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM admin_screens WHERE admin_id=?", (admin_id,))
            self._execute(conn, "DELETE FROM sessions WHERE admin_id=?", (admin_id,))
            self._execute(conn, "DELETE FROM admins WHERE id=?", (admin_id,))
            conn.commit()
        finally:
            conn.close()

    def increment_failed_attempts(self, admin_id: int):
        conn = self._conn()
        try:
            admin = self._execute(conn, "SELECT failed_attempts FROM admins WHERE id=?", (admin_id,))[0]
            fails = admin["failed_attempts"] + 1
            if fails >= 5:
                locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                self._execute(conn, "UPDATE admins SET failed_attempts=?, locked_until=? WHERE id=?",
                              (fails, locked_until, admin_id))
            else:
                self._execute(conn, "UPDATE admins SET failed_attempts=? WHERE id=?", (fails, admin_id))
            conn.commit()
        finally:
            conn.close()

    def reset_failed_attempts(self, admin_id: int):
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE admins SET failed_attempts=0, locked_until=NULL WHERE id=?", (admin_id,))
            conn.commit()
        finally:
            conn.close()

    # ── Sessions (Device & IP Bound) ───────────────────────────────────────────
    def create_session(self, admin_id: int, ip: str, ua: str) -> Dict:
        token = secrets.token_hex(32)
        csrf = secrets.token_urlsafe(32)
        now_iso = datetime.now().isoformat()
        expires = (datetime.now() + timedelta(hours=12)).isoformat()  # 12h absolute timeout

        conn = self._conn()
        try:
            # Prevent session fixation by clearing old sessions for this admin+IP pair
            self._execute(conn, "DELETE FROM sessions WHERE admin_id=? AND ip_address=?", (admin_id, ip))
            self._execute(conn,
                          "INSERT INTO sessions (token, admin_id, csrf_token, ip_address, user_agent, expires_at, last_active) VALUES (?,?,?,?,?,?,?)",
                          (token, admin_id, csrf, ip, ua, expires, now_iso))
            conn.commit()
            return {"token": token, "csrf_token": csrf}
        finally:
            conn.close()

    def verify_session(self, token: str, current_ip: str, current_ua: str) -> Optional[Dict]:
        conn = self._conn()
        try:
            rows = self._execute(conn,
                                 "SELECT s.*, a.username, a.role FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token=?",
                                 (token,))
            if not rows: return None

            s = rows[0]
            now = datetime.now()

            # Absolute timeout check
            if datetime.fromisoformat(s["expires_at"]) < now:
                self._execute(conn, "DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                return None

            # Idle timeout check (1 hour)
            if now - datetime.fromisoformat(s["last_active"]) > timedelta(hours=1):
                self._execute(conn, "DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                return None

            # Device/IP Binding check
            if s["ip_address"] != current_ip or s["user_agent"] != current_ua:
                logger.warning(f"Session hijack attempt blocked. Bound IP/UA mismatch for user {s['username']}")
                self._execute(conn, "DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                return None

            # Update last active for rolling idle timeout
            self._execute(conn, "UPDATE sessions SET last_active=? WHERE token=?", (now.isoformat(), token))
            conn.commit()
            return s
        finally:
            conn.close()

    def delete_session(self, token: str):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM sessions WHERE token=?", (token,))
            conn.commit()
        finally:
            conn.close()

    def cleanup_sessions(self):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM sessions WHERE expires_at < ?", (datetime.now().isoformat(),))
            conn.commit()
        finally:
            conn.close()

    # ── Admin-Screen assignments ────────────────────────────────────────────────
    def get_admin_screen_ids(self, admin_id: int) -> List[str]:
        conn = self._conn()
        try:
            return [r["screen_id"] for r in
                    self._execute(conn, "SELECT screen_id FROM admin_screens WHERE admin_id=?", (admin_id,))]
        finally:
            conn.close()

    def assign_screen_to_admin(self, admin_id: int, screen_id: str):
        conn = self._conn()
        try:
            if USE_PG:
                self._execute(conn,
                              "INSERT INTO admin_screens (admin_id, screen_id) VALUES (?,?) ON CONFLICT DO NOTHING",
                              (admin_id, screen_id))
            else:
                self._execute(conn, "INSERT OR IGNORE INTO admin_screens (admin_id, screen_id) VALUES (?,?)",
                              (admin_id, screen_id))
            conn.commit()
        finally:
            conn.close()

    def unassign_screen_from_admin(self, admin_id: int, screen_id: str):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM admin_screens WHERE admin_id=? AND screen_id=?", (admin_id, screen_id))
            conn.commit()
        finally:
            conn.close()

    def get_screens_for_admin(self, admin_id: int, role: str) -> List[Dict]:
        conn = self._conn()
        try:
            if role == "superadmin":
                return self._execute(conn,
                                     """SELECT s.*, g.name AS group_name, p.name AS playlist_name FROM screens s LEFT JOIN screen_groups g ON g.id=s.group_id LEFT JOIN playlists p ON p.id=s.playlist_id ORDER BY s.created_at DESC""")
            else:
                return self._execute(conn,
                                     """SELECT s.*, g.name AS group_name, p.name AS playlist_name FROM screens s LEFT JOIN screen_groups g ON g.id=s.group_id LEFT JOIN playlists p ON p.id=s.playlist_id JOIN admin_screens ass ON ass.screen_id=s.id AND ass.admin_id=? ORDER BY s.created_at DESC""",
                                     (admin_id,))
        finally:
            conn.close()

    def update_screen_orientation(self, screen_id: str, orientation: str, rotation_dir: int):
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE screens SET orientation=?, rotation_dir=? WHERE id=?",
                          (orientation, rotation_dir, screen_id))
            conn.commit()
        finally:
            conn.close()

    # ── Playlists ──────────────────────────────────────────────────────────────
    def get_playlists(self):
        conn = self._conn()
        try:
            return self._execute(conn,
                                 """SELECT p.*, COUNT(s.id) AS slide_count FROM playlists p LEFT JOIN slides s ON s.playlist_id=p.id GROUP BY p.id, p.name, p.fallback_url, p.loop_duration, p.fallback_duration, p.created_at ORDER BY p.id""")
        finally:
            conn.close()

    def add_playlist(self, name: str):
        conn = self._conn()
        try:
            rows = self._execute(conn, "INSERT INTO playlists (name) VALUES (?) RETURNING *", (name,))
            conn.commit()
            return rows[0]
        finally:
            conn.close()

    def delete_playlist(self, pid: int):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM slides WHERE playlist_id=?", (pid,))
            self._execute(conn, "DELETE FROM playlists WHERE id=?", (pid,))
            conn.commit()
        finally:
            conn.close()

    def rename_playlist(self, pid: int, name: str):
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE playlists SET name=? WHERE id=?", (name, pid))
            conn.commit()
        finally:
            conn.close()

    # ── Slides ─────────────────────────────────────────────────────────────────
    def get_slides(self, playlist_id: int):
        conn = self._conn()
        try:
            return self._execute(conn, "SELECT * FROM slides WHERE playlist_id=? ORDER BY position", (playlist_id,))
        finally:
            conn.close()

    def get_active_slides(self, playlist_id: int):
        now, day_name, time_now = datetime.now(), datetime.now().strftime("%a"), datetime.now().strftime("%H:%M")
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT * FROM slides WHERE playlist_id=? AND active=1 ORDER BY position",
                                 (playlist_id,))
        finally:
            conn.close()
        result = []
        for s in rows:
            if s["sched_start"] and now.date().isoformat() < s["sched_start"]: continue
            if s["sched_end"] and now.date().isoformat() > s["sched_end"]:   continue
            if s["days_of_week"] and day_name not in [d.strip() for d in s["days_of_week"].split(",")]: continue
            if s["time_start"] and time_now < s["time_start"]: continue
            if s["time_end"] and time_now > s["time_end"]:   continue
            result.append(s)
        return result

    def add_slide(self, playlist_id, type_, url, title, duration, sched_start=None, sched_end=None, days_of_week=None,
                  time_start=None, time_end=None):
        conn = self._conn()
        try:
            max_pos = self._execute(conn, "SELECT COALESCE(MAX(position),0) as m FROM slides WHERE playlist_id=?",
                                    (playlist_id,))[0]["m"]
            result = self._execute(conn,
                                   """INSERT INTO slides (playlist_id,type,url,title,duration,position,sched_start,sched_end,days_of_week,time_start,time_end) VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING *""",
                                   (playlist_id, type_, url, title, duration, max_pos + 1, sched_start, sched_end,
                                    days_of_week, time_start, time_end))
            conn.commit()
            return result[0]
        finally:
            conn.close()

    def delete_slide(self, sid: int):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM slides WHERE id=?", (sid,))
            conn.commit()
        finally:
            conn.close()

    def reorder_slides(self, ids: List[int]):
        conn = self._conn()
        try:
            for pos, sid in enumerate(ids): self._execute(conn, "UPDATE slides SET position=? WHERE id=?", (pos, sid))
            conn.commit()
        finally:
            conn.close()

    def toggle_slide(self, sid: int):
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE slides SET active=1-active WHERE id=?", (sid,))
            conn.commit()
        finally:
            conn.close()

    def get_slide_playlist(self, sid: int) -> Optional[int]:
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT playlist_id FROM slides WHERE id=?", (sid,))
            return rows[0]["playlist_id"] if rows else None
        finally:
            conn.close()

    # ── Screens & Per-Device Tokens ─────────────────────────────────────────────
    def get_screens(self):
        conn = self._conn()
        try:
            return self._execute(conn,
                                 "SELECT s.*, g.name AS group_name, p.name AS playlist_name FROM screens s LEFT JOIN screen_groups g ON g.id=s.group_id LEFT JOIN playlists p ON p.id=s.playlist_id ORDER BY s.created_at DESC")
        finally:
            conn.close()

    def get_screen_token(self, screen_id: str) -> Optional[str]:
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT screen_token FROM screens WHERE id=?", (screen_id,))
            return rows[0]["screen_token"] if rows else None
        finally:
            conn.close()

    def enroll_screen(self, screen_id: str, ip: str, ua: str) -> str:
        # Generates a persistent token for the screen upon initial pairing
        token = secrets.token_hex(32)
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT id FROM screens WHERE id=?", (screen_id,))
            if rows:
                self._execute(conn,
                              "UPDATE screens SET screen_token=?, last_seen=?, status='online', ip_address=?, user_agent=? WHERE id=?",
                              (token, datetime.now().isoformat(), ip, ua, screen_id))
            else:
                count = self._execute(conn, "SELECT COUNT(*) as c FROM screens")[0]["c"]
                orient_rows = self._execute(conn, "SELECT orientation, rotation_dir FROM screens LIMIT 1")
                orientation = orient_rows[0]["orientation"] if orient_rows else "landscape"
                rotation_dir = orient_rows[0]["rotation_dir"] if orient_rows else 90
                self._execute(conn,
                              """INSERT INTO screens (id,name,screen_token,last_seen,status,ip_address,user_agent,orientation,rotation_dir) VALUES (?,?,?,?,?,?,?,?,?)""",
                              (screen_id, f"Screen {count + 1}", token, datetime.now().isoformat(), "online", ip, ua,
                               orientation, rotation_dir))
            conn.commit()
            return token
        finally:
            conn.close()

    def update_screen(self, screen_id: str, name=None, group_id=None, playlist_id=None):
        conn = self._conn()
        try:
            if name is not None: self._execute(conn, "UPDATE screens SET name=? WHERE id=?", (name, screen_id))
            if group_id is not None: self._execute(conn, "UPDATE screens SET group_id=? WHERE id=?",
                                                   (group_id or None, screen_id))
            if playlist_id is not None: self._execute(conn, "UPDATE screens SET playlist_id=? WHERE id=?",
                                                      (playlist_id or None, screen_id))
            conn.commit()
        finally:
            conn.close()

    def heartbeat_screen(self, screen_id: str):
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE screens SET last_seen=?,status='online' WHERE id=?",
                          (datetime.now().isoformat(), screen_id))
            conn.commit()
        finally:
            conn.close()

    def mark_screens_offline(self, timeout=30):
        conn = self._conn()
        try:
            if USE_PG:
                self._execute(conn,
                              "UPDATE screens SET status='offline' WHERE last_seen < (NOW() - INTERVAL '? seconds') OR last_seen IS NULL",
                              (timeout,))
            else:
                self._execute(conn,
                              f"UPDATE screens SET status='offline' WHERE last_seen < datetime('now','-{timeout} seconds') OR last_seen IS NULL")
            conn.commit()
        finally:
            conn.close()

    def delete_screen(self, screen_id: str):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM admin_screens WHERE screen_id=?", (screen_id,))
            self._execute(conn, "DELETE FROM screens WHERE id=?", (screen_id,))
            conn.commit()
        finally:
            conn.close()

    # ── Groups ─────────────────────────────────────────────────────────────────
    def get_groups(self):
        conn = self._conn()
        try:
            return self._execute(conn,
                                 "SELECT g.*, COUNT(s.id) AS screen_count FROM screen_groups g LEFT JOIN screens s ON s.group_id=g.id GROUP BY g.id, g.name, g.created_at ORDER BY g.id")
        finally:
            conn.close()

    def add_group(self, name: str):
        conn = self._conn()
        try:
            rows = self._execute(conn, "INSERT INTO screen_groups (name) VALUES (?) RETURNING *", (name,))
            conn.commit()
            return rows[0]
        finally:
            conn.close()

    def delete_group(self, gid: int):
        conn = self._conn()
        try:
            self._execute(conn, "DELETE FROM screen_groups WHERE id=?", (gid,))
            conn.commit()
        finally:
            conn.close()

    def rename_group(self, gid: int, name: str):
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE screen_groups SET name=? WHERE id=?", (name, gid))
            conn.commit()
        finally:
            conn.close()

    def assign_playlist_to_group(self, gid: int, playlist_id: int):
        conn = self._conn()
        try:
            self._execute(conn, "UPDATE screens SET playlist_id=? WHERE group_id=?", (playlist_id, gid))
            conn.commit()
        finally:
            conn.close()

    def resolve_playlist(self, screen_id: str) -> Optional[int]:
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT playlist_id FROM screens WHERE id=?", (screen_id,))
            if rows and rows[0]["playlist_id"]: return rows[0]["playlist_id"]
            rows = self._execute(conn, "SELECT id FROM playlists ORDER BY id LIMIT 1")
            return rows[0]["id"] if rows else None
        finally:
            conn.close()