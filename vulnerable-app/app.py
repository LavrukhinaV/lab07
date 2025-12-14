import html
import logging
import os
import sqlite3
from pathlib import Path

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# Не хардкодим DEBUG — Semgrep просит управлять через env
# FLASK_DEBUG=1/0
app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "0") == "1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "app.db")

# Разрешаем читать файлы только из этой директории
SAFE_READ_DIR = Path(os.getenv("SAFE_READ_DIR", "/tmp")).resolve()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    # Не возвращаем HTML/версию в строке — просто JSON
    return jsonify({"status": "ok"}), 200


@app.route("/user")
def get_user():
    username = request.args.get("name", "")
    conn = get_db()
    cur = conn.cursor()

    # Параметризованный запрос (без f-string)
    rows = cur.execute(
        "SELECT id, name, email FROM users WHERE name = ?",
        (username,),
    ).fetchall()
    conn.close()

    return jsonify({"result": [dict(r) for r in rows]}), 200


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Semgrep ругался на ручной HTML. Возвращаем JSON.
    return jsonify({"query": q, "count": 0, "results": []}), 200


@app.route("/read")
def read_file():
    # Вместо "<pre>...</pre>" вернём text/plain + ограничим директорию
    raw_path = request.args.get("path", "")
    if not raw_path:
        return jsonify({"error": "path is required"}), 400

    target = Path(raw_path).expanduser().resolve()

    # Запрещаем выход за пределы SAFE_READ_DIR
    if SAFE_READ_DIR not in target.parents and target != SAFE_READ_DIR:
        return jsonify({"error": "forbidden path"}), 403

    if not target.exists() or not target.is_file():
        return jsonify({"error": "not found"}), 404

    data = target.read_text(encoding="utf-8", errors="replace")
    # Возвращаем plain text, не HTML
    return Response(data, mimetype="text/plain; charset=utf-8", status=200)


if __name__ == "__main__":
    # Semgrep ругался на 0.0.0.0 — по умолчанию локальный хост
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8080"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
