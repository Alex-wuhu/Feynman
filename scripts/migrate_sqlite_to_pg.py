#!/usr/bin/env python3
"""One-time migration: copy data from SQLite (data/chatbook.db) to Supabase PostgreSQL.

Usage:
    DATABASE_URL=postgresql://... python scripts/migrate_sqlite_to_pg.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras

SQLITE_PATH = Path(__file__).resolve().parents[1] / "data" / "chatbook.db"
DATABASE_URL = os.getenv("DATABASE_URL", "")


def main():
    if not DATABASE_URL:
        print("ERROR: Set DATABASE_URL env var first.", file=sys.stderr)
        sys.exit(1)

    if not SQLITE_PATH.exists():
        print(f"SQLite DB not found at {SQLITE_PATH}", file=sys.stderr)
        sys.exit(1)

    sq = sqlite3.connect(SQLITE_PATH)
    sq.row_factory = sqlite3.Row
    pg = psycopg2.connect(DATABASE_URL)
    pg.autocommit = False

    try:
        cur = pg.cursor()

        # Agents
        rows = sq.execute("SELECT * FROM agents").fetchall()
        print(f"Migrating {len(rows)} agents...")
        for r in rows:
            cur.execute("""
                INSERT INTO agents (id, name, type, source, status, meta_json, user_id, is_deleted, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (r["id"], r["name"], r["type"], r["source"], r["status"], r["meta_json"],
                  r["user_id"] if "user_id" in r.keys() else None,
                  bool(r["is_deleted"]) if "is_deleted" in r.keys() else False,
                  r["created_at"]))

        # Chunks
        rows = sq.execute("SELECT * FROM chunks").fetchall()
        print(f"Migrating {len(rows)} chunks...")
        for r in rows:
            cur.execute("""
                INSERT INTO chunks (id, agent_id, chunk_index, text, vector, dim, norm)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (r["id"], r["agent_id"], r["chunk_index"], r["text"],
                  psycopg2.Binary(r["vector"]), r["dim"], r["norm"]))

        # Messages (legacy table — also kept for reference)
        rows = sq.execute("SELECT * FROM messages").fetchall()
        print(f"Migrating {len(rows)} messages (legacy table)...")
        for r in rows:
            user_id = r["user_id"] if "user_id" in r.keys() else None
            cur.execute("""
                INSERT INTO messages (id, agent_id, user_id, role, content, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (r["id"], r["agent_id"], user_id, r["role"], r["content"], r["created_at"]))

        # Questions
        try:
            rows = sq.execute("SELECT * FROM questions").fetchall()
            print(f"Migrating {len(rows)} questions...")
            for r in rows:
                cur.execute("""
                    INSERT INTO questions (id, agent_id, text, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (r["id"], r["agent_id"], r["text"], r["created_at"]))
        except sqlite3.OperationalError:
            print("No questions table in SQLite, skipping.")

        # Votes
        try:
            rows = sq.execute("SELECT * FROM votes").fetchall()
            print(f"Migrating {len(rows)} votes...")
            for r in rows:
                cur.execute("""
                    INSERT INTO votes (id, title, count, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (r["id"], r["title"], r["count"], r["created_at"]))
        except sqlite3.OperationalError:
            print("No votes table in SQLite, skipping.")

        # Minds
        try:
            rows = sq.execute("SELECT * FROM minds").fetchall()
            print(f"Migrating {len(rows)} minds...")
            for r in rows:
                cur.execute("""
                    INSERT INTO minds (id, name, era, domain, bio_summary, persona,
                        thinking_style, typical_phrases, works, avatar_seed, version, chat_count, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (r["id"], r["name"], r["era"], r["domain"], r["bio_summary"],
                      r["persona"], r["thinking_style"], r["typical_phrases"],
                      r["works"], r["avatar_seed"], r["version"], r["chat_count"], r["created_at"]))
        except sqlite3.OperationalError:
            print("No minds table in SQLite, skipping.")

        # Mind works
        try:
            rows = sq.execute("SELECT * FROM mind_works").fetchall()
            print(f"Migrating {len(rows)} mind_works...")
            for r in rows:
                cur.execute("""
                    INSERT INTO mind_works (mind_id, agent_id) VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                """, (r["mind_id"], r["agent_id"]))
        except sqlite3.OperationalError:
            print("No mind_works table in SQLite, skipping.")

        # Mind memories
        try:
            rows = sq.execute("SELECT * FROM mind_memories").fetchall()
            print(f"Migrating {len(rows)} mind_memories...")
            for r in rows:
                cur.execute("""
                    INSERT INTO mind_memories (id, mind_id, user_id, summary, topic, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (r["id"], r["mind_id"], r["user_id"], r["summary"], r["topic"], r["created_at"]))
        except sqlite3.OperationalError:
            print("No mind_memories table in SQLite, skipping.")

        # Chat sessions
        try:
            rows = sq.execute("SELECT * FROM chat_sessions").fetchall()
            print(f"Migrating {len(rows)} chat_sessions...")
            for r in rows:
                user_id = r["user_id"] if "user_id" in r.keys() else None
                cur.execute("""
                    INSERT INTO chat_sessions (id, user_id, title, session_type, mind_id, meta_json, updated_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (r["id"], user_id, r["title"], r["session_type"], r["mind_id"],
                      r["meta_json"], r["updated_at"], r["created_at"]))
        except sqlite3.OperationalError:
            print("No chat_sessions table in SQLite, skipping.")

        # Session messages
        try:
            rows = sq.execute("SELECT * FROM session_messages").fetchall()
            print(f"Migrating {len(rows)} session_messages...")
            for r in rows:
                cur.execute("""
                    INSERT INTO session_messages (id, session_id, role, content, meta_json, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (r["id"], r["session_id"], r["role"], r["content"],
                      r["meta_json"], r["created_at"]))
        except sqlite3.OperationalError:
            print("No session_messages table in SQLite, skipping.")

        pg.commit()
        print("Migration complete!")

    except Exception as e:
        pg.rollback()
        print(f"Migration failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sq.close()
        pg.close()


if __name__ == "__main__":
    main()
