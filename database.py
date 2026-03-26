import os
import hashlib
import secrets
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

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
    def __init__(self, sqlite_path: str = "signage.db"):
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
                rows = cur.fetchall()
                return [dict(r) for r in rows]
            except Exception:
                return []
        else:
            cur = conn.execute(sql, params)
            try:
                rows = cur.fetchall()
                return [dict(r) for r in rows]
            except Exception:
                return []

    # ── Init ───────────────────────────────────────────────────────────────────
    def init(self):
        conn = self._conn()
        try:
            self._create_tables(conn)
            self._migrate(conn)
            self._seed(conn)
            conn.commit()
        finally:
            conn.close()

    def _create_tables(self, conn):
        serial = "SERIAL" if USE_PG else "INTEGER"
        pk_auto = "PRIMARY KEY" if USE_PG else "PRIMARY KEY AUTOINCREMENT"
        now_fn = "now()::text" if USE_PG else "datetime('now')"
        stmts = [
            f"""CREATE TABLE IF NOT EXISTS admins (
                id           {serial} {pk_auto},
                username     TEXT    NOT NULL UNIQUE,
                password_hash TEXT   NOT NULL,
                salt         TEXT    NOT NULL,
                role         TEXT    NOT NULL DEFAULT 'subadmin',
                created_at   TEXT    DEFAULT ({now_fn})
            )""",
            f"""CREATE TABLE IF NOT EXISTS sessions (
                token        TEXT    PRIMARY KEY,
                admin_id     INTEGER NOT NULL,
                expires_at   TEXT    NOT NULL,
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
                last_seen       TEXT    DEFAULT NULL,
                status          TEXT    NOT NULL DEFAULT 'offline',
                ip_address      TEXT    DEFAULT NULL,
                user_agent      TEXT    DEFAULT NULL,
                orientation     TEXT    NOT NULL DEFAULT 'landscape',
                rotation_dir    INTEGER NOT NULL DEFAULT 90,
                created_at      TEXT    DEFAULT ({now_fn})
            )""",
        ]
        for stmt in stmts:
            self._execute(conn, stmt)


    def _migrate(self, conn):
        if USE_PG:
            def col_exists(table, col):
                rows = self._execute(conn,
                    "SELECT column_name FROM information_schema.columns WHERE table_name=? AND column_name=?",
                    (table, col))
                return len(rows) > 0
        else:
            def col_exists(table, col):
                rows = self._execute(conn, f"PRAGMA table_info({table})")
                return any(r["name"] == col for r in rows)

        def table_exists(table):
            if USE_PG:
                rows = self._execute(conn,
                    "SELECT table_name FROM information_schema.tables WHERE table_name=?", (table,))
                return len(rows) > 0
            else:
                rows = self._execute(conn,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
                return len(rows) > 0

        migrations = [
            ("playlists", "fallback_url",      "TEXT DEFAULT NULL"),
            ("playlists", "loop_duration",     "INTEGER NOT NULL DEFAULT 1800"),
            ("playlists", "fallback_duration", "INTEGER NOT NULL DEFAULT 300"),
            ("slides",    "interrupt_every",   "INTEGER NOT NULL DEFAULT 0"),
            ("slides",    "interrupt_for",     "INTEGER NOT NULL DEFAULT 300"),
            ("screens",   "orientation",       "TEXT NOT NULL DEFAULT 'landscape'"),
            ("screens",   "rotation_dir",      "INTEGER NOT NULL DEFAULT 90"),
        ]
        for table, col, defn in migrations:
            if table_exists(table) and not col_exists(table, col):
                self._execute(conn, f"ALTER TABLE {table} ADD COLUMN {col} {defn}")

    def _seed(self, conn):
        # Seed default super admin if no admins exist
        rows = self._execute(conn, "SELECT COUNT(*) as c FROM admins")
        if rows[0]["c"] == 0:
            hashed, salt = hash_password("admin123")
            self._execute(conn,
                "INSERT INTO admins (username, password_hash, salt, role) VALUES (?,?,?,?)",
                ("admin", hashed, salt, "superadmin"))

        # Seed playlists if empty
        rows = self._execute(conn, "SELECT COUNT(*) as c FROM playlists")
        if rows[0]["c"] > 0:
            return
        self._execute(conn, "INSERT INTO screen_groups (name) VALUES (?)", ("Main Lobby",))
        self._execute(conn, "INSERT INTO screen_groups (name) VALUES (?)", ("Reception",))
        p1 = self._execute(conn, "INSERT INTO playlists (name) VALUES (?) RETURNING id", ("Main Playlist",))[0]["id"]
        p2 = self._execute(conn, "INSERT INTO playlists (name) VALUES (?) RETURNING id", ("Reception Loop",))[0]["id"]
        for row in [
            (p1,"youtube","https://www.youtube.com/watch?v=jNQXAC9IVRw","Welcome Reel",20,0),
            (p1,"image","https://images.unsplash.com/photo-1557804506-669a67965ba0?w=1920","Brand Poster",10,1),
            (p1,"image","https://images.unsplash.com/photo-1498050108023-c5249f4df085?w=1920","Product Highlight",8,2),
            (p2,"image","https://images.unsplash.com/photo-1497366216548-37526070297c?w=1920","Welcome",12,0),
        ]:
            self._execute(conn,
                "INSERT INTO slides (playlist_id,type,url,title,duration,position) VALUES (?,?,?,?,?,?)", row)

    # ── Auth ───────────────────────────────────────────────────────────────────
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
            return self._execute(conn, "SELECT id, username, role, created_at FROM admins ORDER BY id")
        finally:
            conn.close()

    def create_admin(self, username: str, password: str, role: str = "subadmin") -> Dict:
        hashed, salt = hash_password(password)
        conn = self._conn()
        try:
            rows = self._execute(conn,
                "INSERT INTO admins (username, password_hash, salt, role) VALUES (?,?,?,?) RETURNING id, username, role, created_at",
                (username, hashed, salt, role))
            conn.commit()
            return rows[0]
        finally:
            conn.close()

    def update_admin_password(self, admin_id: int, password: str):
        hashed, salt = hash_password(password)
        conn = self._conn()
        try:
            self._execute(conn,
                "UPDATE admins SET password_hash=?, salt=? WHERE id=?",
                (hashed, salt, admin_id))
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

    def create_session(self, admin_id: int, days: int = 7) -> str:
        token = secrets.token_hex(32)
        expires = (datetime.now() + timedelta(days=days)).isoformat()
        conn = self._conn()
        try:
            self._execute(conn,
                "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?,?,?)",
                (token, admin_id, expires))
            conn.commit()
            return token
        finally:
            conn.close()

    def verify_session(self, token: str) -> Optional[Dict]:
        conn = self._conn()
        try:
            rows = self._execute(conn,
                "SELECT s.*, a.username, a.role FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token=?",
                (token,))
            if not rows:
                return None
            session = rows[0]
            if datetime.fromisoformat(session["expires_at"]) < datetime.now():
                self._execute(conn, "DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                return None
            return session
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
            rows = self._execute(conn,
                "SELECT screen_id FROM admin_screens WHERE admin_id=?", (admin_id,))
            return [r["screen_id"] for r in rows]
        finally:
            conn.close()

    def assign_screen_to_admin(self, admin_id: int, screen_id: str):
        conn = self._conn()
        try:
            # Use INSERT OR IGNORE for SQLite, ON CONFLICT DO NOTHING for PG
            if USE_PG:
                self._execute(conn,
                    "INSERT INTO admin_screens (admin_id, screen_id) VALUES (?,?) ON CONFLICT DO NOTHING",
                    (admin_id, screen_id))
            else:
                self._execute(conn,
                    "INSERT OR IGNORE INTO admin_screens (admin_id, screen_id) VALUES (?,?)",
                    (admin_id, screen_id))
            conn.commit()
        finally:
            conn.close()

    def unassign_screen_from_admin(self, admin_id: int, screen_id: str):
        conn = self._conn()
        try:
            self._execute(conn,
                "DELETE FROM admin_screens WHERE admin_id=? AND screen_id=?",
                (admin_id, screen_id))
            conn.commit()
        finally:
            conn.close()

    def get_screens_for_admin(self, admin_id: int, role: str) -> List[Dict]:
        conn = self._conn()
        try:
            if role == "superadmin":
                rows = self._execute(conn, """
                    SELECT s.*, g.name AS group_name, p.name AS playlist_name
                    FROM screens s
                    LEFT JOIN screen_groups g ON g.id=s.group_id
                    LEFT JOIN playlists p ON p.id=s.playlist_id
                    ORDER BY s.created_at DESC
                """)
            else:
                rows = self._execute(conn, """
                    SELECT s.*, g.name AS group_name, p.name AS playlist_name
                    FROM screens s
                    LEFT JOIN screen_groups g ON g.id=s.group_id
                    LEFT JOIN playlists p ON p.id=s.playlist_id
                    JOIN admin_screens ass ON ass.screen_id=s.id AND ass.admin_id=?
                    ORDER BY s.created_at DESC
                """, (admin_id,))
            return rows
        finally:
            conn.close()

    # ── Screen orientation ──────────────────────────────────────────────────────
    def update_screen_orientation(self, screen_id: str, orientation: str, rotation_dir: int):
        conn = self._conn()
        try:
            self._execute(conn,
                "UPDATE screens SET orientation=?, rotation_dir=? WHERE id=?",
                (orientation, rotation_dir, screen_id))
            conn.commit()
        finally:
            conn.close()

    # ── Playlists ──────────────────────────────────────────────────────────────
    def get_playlists(self):
        conn = self._conn()
        try:
            rows = self._execute(conn, """
                SELECT p.id, p.name, p.fallback_url, p.loop_duration, p.fallback_duration,
                       p.created_at, COUNT(s.id) AS slide_count
                FROM playlists p LEFT JOIN slides s ON s.playlist_id=p.id
                GROUP BY p.id, p.name, p.fallback_url, p.loop_duration, p.fallback_duration, p.created_at
                ORDER BY p.id
            """)
            return rows
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

    def update_playlist_fallback(self, pid: int, fallback_url, loop_duration: int, fallback_duration: int):
        conn = self._conn()
        try:
            self._execute(conn,
                "UPDATE playlists SET fallback_url=?,loop_duration=?,fallback_duration=? WHERE id=?",
                (fallback_url or None, loop_duration, fallback_duration, pid))
            conn.commit()
        finally:
            conn.close()

    # ── Slides ─────────────────────────────────────────────────────────────────
    def get_slides(self, playlist_id: int):
        conn = self._conn()
        try:
            return self._execute(conn,
                "SELECT * FROM slides WHERE playlist_id=? ORDER BY position", (playlist_id,))
        finally:
            conn.close()

    def get_active_slides(self, playlist_id: int):
        now = datetime.now()
        day_name = now.strftime("%a")
        time_now = now.strftime("%H:%M")
        conn = self._conn()
        try:
            rows = self._execute(conn,
                "SELECT * FROM slides WHERE playlist_id=? AND active=1 ORDER BY position", (playlist_id,))
        finally:
            conn.close()
        result = []
        for s in rows:
            if s["sched_start"] and now.date().isoformat() < s["sched_start"]: continue
            if s["sched_end"]   and now.date().isoformat() > s["sched_end"]:   continue
            if s["days_of_week"]:
                if day_name not in [d.strip() for d in s["days_of_week"].split(",")]: continue
            if s["time_start"] and time_now < s["time_start"]: continue
            if s["time_end"]   and time_now > s["time_end"]:   continue
            result.append(s)
        return result

    def add_slide(self, playlist_id, type_, url, title, duration,
                  sched_start=None, sched_end=None, days_of_week=None,
                  time_start=None, time_end=None, interrupt_every=0, interrupt_for=300):
        conn = self._conn()
        try:
            rows = self._execute(conn,
                "SELECT COALESCE(MAX(position),0) as m FROM slides WHERE playlist_id=?", (playlist_id,))
            max_pos = rows[0]["m"]
            result = self._execute(conn, """
                INSERT INTO slides
                  (playlist_id,type,url,title,duration,position,sched_start,sched_end,
                   days_of_week,time_start,time_end,interrupt_every,interrupt_for)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *
            """, (playlist_id,type_,url,title,duration,max_pos+1,
                  sched_start,sched_end,days_of_week,time_start,time_end,interrupt_every,interrupt_for))
            conn.commit()
            return result[0]
        finally:
            conn.close()

    def update_slide(self, sid, type_, url, title, duration, active=1,
                     sched_start=None, sched_end=None, days_of_week=None,
                     time_start=None, time_end=None, interrupt_every=0, interrupt_for=300):
        conn = self._conn()
        try:
            self._execute(conn, """
                UPDATE slides SET type=?,url=?,title=?,duration=?,active=?,
                  sched_start=?,sched_end=?,days_of_week=?,time_start=?,time_end=?,
                  interrupt_every=?,interrupt_for=? WHERE id=?
            """, (type_,url,title,duration,active,sched_start,sched_end,
                  days_of_week,time_start,time_end,interrupt_every,interrupt_for,sid))
            conn.commit()
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
            for pos, sid in enumerate(ids):
                self._execute(conn, "UPDATE slides SET position=? WHERE id=?", (pos, sid))
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

    # ── Screens ────────────────────────────────────────────────────────────────
    def get_screens(self):
        conn = self._conn()
        try:
            return self._execute(conn, """
                SELECT s.*, g.name AS group_name, p.name AS playlist_name
                FROM screens s
                LEFT JOIN screen_groups g ON g.id=s.group_id
                LEFT JOIN playlists p ON p.id=s.playlist_id
                ORDER BY s.created_at DESC
            """)
        finally:
            conn.close()

    def upsert_screen(self, screen_id: str, ip: str=None, ua: str=None):
        conn = self._conn()
        try:
            rows = self._execute(conn, "SELECT id FROM screens WHERE id=?", (screen_id,))
            if rows:
                self._execute(conn, """
                    UPDATE screens SET last_seen=?,status='online',
                      ip_address=COALESCE(?,ip_address),user_agent=COALESCE(?,user_agent)
                    WHERE id=?
                """, (datetime.now().isoformat(), ip, ua, screen_id))
            else:
                count = self._execute(conn, "SELECT COUNT(*) as c FROM screens")[0]["c"]
                # Inherit orientation from existing screens so new screens match current setup
                orient_rows = self._execute(conn, "SELECT orientation, rotation_dir FROM screens LIMIT 1")
                orientation = orient_rows[0]["orientation"] if orient_rows else "landscape"
                rotation_dir = orient_rows[0]["rotation_dir"] if orient_rows else 90
                self._execute(conn, """
                    INSERT INTO screens (id,name,last_seen,status,ip_address,user_agent,orientation,rotation_dir)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (screen_id, f"Screen {count+1}", datetime.now().isoformat(), "online", ip, ua, orientation, rotation_dir))
            conn.commit()
            return self._execute(conn, "SELECT * FROM screens WHERE id=?", (screen_id,))[0]
        finally:
            conn.close()

    def update_screen(self, screen_id: str, name=None, group_id=None, playlist_id=None):
        conn = self._conn()
        try:
            if name        is not None: self._execute(conn, "UPDATE screens SET name=? WHERE id=?", (name, screen_id))
            if group_id    is not None: self._execute(conn, "UPDATE screens SET group_id=? WHERE id=?", (group_id or None, screen_id))
            if playlist_id is not None: self._execute(conn, "UPDATE screens SET playlist_id=? WHERE id=?", (playlist_id or None, screen_id))
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
            return self._execute(conn, """
                SELECT g.*, COUNT(s.id) AS screen_count
                FROM screen_groups g LEFT JOIN screens s ON s.group_id=g.id
                GROUP BY g.id, g.name, g.created_at ORDER BY g.id
            """)
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
            if rows and rows[0]["playlist_id"]:
                return rows[0]["playlist_id"]
            rows = self._execute(conn, "SELECT id FROM playlists ORDER BY id LIMIT 1")
            return rows[0]["id"] if rows else None
        finally:
            conn.close()