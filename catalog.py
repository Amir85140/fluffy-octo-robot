"""CyberRange Server — API + консоль оператора.
Запуск:  uvicorn server:app --host 0.0.0.0 --port 8000
Первый зарегистрированный аккаунт становится оператором. фейковых людей нет."""
import json, os, sqlite3, secrets, hashlib, threading, time, uuid, csv, io
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.responses import JSONResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

import catalog

ROOT = Path(__file__).parent.resolve()
DB_PATH = ROOT / "cyberrange.db"
LOCK = threading.RLock()
DB = sqlite3.connect(str(DB_PATH), check_same_thread=False)
DB.row_factory = sqlite3.Row

METRICS: Dict[str, deque] = {}
LOGS: Dict[str, deque] = {}
ONLINE_WINDOW = 12.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, login TEXT UNIQUE, name TEXT, dept TEXT,
  role TEXT, salt TEXT, hash TEXT, created REAL, deleted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT, created REAL);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, key TEXT, user_id TEXT, host TEXT, os TEXT,
  ver TEXT, last_seen REAL, created REAL, killed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS enroll(token TEXT PRIMARY KEY, user_id TEXT, created REAL, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, agent_id TEXT, user_id TEXT, attack_id TEXT,
  params TEXT, status TEXT, outcome TEXT, score INTEGER DEFAULT 0, created REAL, started REAL, finished REAL,
  evidence TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, ts REAL, user_id TEXT, agent_id TEXT, task_id TEXT,
  kind TEXT, level TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS presets(id TEXT PRIMARY KEY, name TEXT, queue TEXT, cfg TEXT, created REAL);
CREATE TABLE IF NOT EXISTS campaign(id INTEGER PRIMARY KEY CHECK(id=1), cfg TEXT, queue TEXT, targets TEXT,
  status TEXT, cur INTEGER DEFAULT 0, tc INTEGER DEFAULT 0, last REAL DEFAULT 0, started REAL DEFAULT 0, delivered INTEGER DEFAULT 0);
"""
with LOCK:
    DB.executescript(SCHEMA)
    if not DB.execute("SELECT 1 FROM campaign WHERE id=1").fetchone():
        DB.execute("INSERT INTO campaign(id,cfg,queue,targets,status) VALUES(1,?,?,?,?)",
                   (json.dumps(dict(interval=45, ceiling=5, duration=0, order="seq", loop=True, escalate=False)),
                    json.dumps(["phish_obvious", "sms_prize", "scan_basic", "brute_basic", "flood_basic", "ransom_basic"]),
                    json.dumps([]), "idle"))
    DB.commit()


def q(sql, args=()):
    with LOCK:
        return DB.execute(sql, args).fetchall()


def ex(sql, args=()):
    with LOCK:
        DB.execute(sql, args)
        DB.commit()


def now(): return time.time()
def nid(): return uuid.uuid4().hex[:12]


def hash_pw(pw: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
    return salt, h


def event(kind, message, level="info", user_id=None, agent_id=None, task_id=None):
    ex("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)",
       (nid(), now(), user_id, agent_id, task_id, kind, level, message))


def score_of(outcome, lvl):
    return {"report": 100, "avoid": 60, "win": 120, "ignore": -10,
            "click": -20, "submit": -40, "fail": -40, "lose": -30}.get(outcome, 0) * lvl


def session_user(req: Request):
    tok = req.cookies.get("cr_session") or req.headers.get("x-cr-session")
    if not tok: return None
    r = q("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND u.deleted=0", (tok,))
    return dict(r[0]) if r else None


def require(req: Request, admin=False):
    u = session_user(req)
    if not u: raise HTTPException(401, "Требуется вход")
    if admin and u["role"] != "admin": raise HTTPException(403, "Только для оператора")
    return u


def agent_online(a): return (now() - (a["last_seen"] or 0)) < ONLINE_WINDOW


def rating_rows():
    users = [dict(r) for r in q("SELECT * FROM users WHERE deleted=0 AND role='user' ORDER BY created")]
    out = []
    for u in users:
        ts = [dict(r) for r in q("SELECT * FROM tasks WHERE user_id=? AND status='done'", (u["id"],))]
        ok = sum(1 for t in ts if t["outcome"] in ("report", "avoid", "win"))
        bad = sum(1 for t in ts if t["outcome"] in ("submit", "fail", "lose", "click"))
        rep = sum(1 for t in ts if t["outcome"] == "report")
        xp = max(0, sum(t["score"] or 0 for t in ts))
        lvl = 1
        for i, th in enumerate([0, 150, 400, 750, 1200, 1800, 2600, 3600, 4800, 6200]):
            if xp >= th: lvl = i + 1
        streak = 0
        for t in sorted(ts, key=lambda x: x["finished"] or 0, reverse=True):
            if t["outcome"] in ("report", "avoid", "win"): streak += 1
            else: break
        ag = [dict(r) for r in q("SELECT * FROM agents WHERE user_id=?", (u["id"],))]
        hist, acc = [], 0
        for t in sorted(ts, key=lambda x: x["finished"] or 0)[-12:]:
            acc = max(0, acc + (t["score"] or 0)); hist.append(acc)
        out.append(dict(id=u["id"], name=u["name"], login=u["login"], dept=u["dept"], created=u["created"],
                        xp=xp, level=lvl, streak=streak, total=len(ts), ok=ok, bad=bad,
                        report_rate=round(rep / len(ts) * 100) if ts else 0,
                        accuracy=round(ok / (ok + bad) * 100) if ok + bad else 0,
                        agents=[dict(id=a["id"], host=a["host"], os=a["os"], online=agent_online(a),
                                     last_seen=a["last_seen"]) for a in ag],
                        history=hist))
    return sorted(out, key=lambda x: -x["xp"])


app = FastAPI(title="CyberRange")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


@app.get("/")
def index():
    return FileResponse(str(ROOT / "static" / "console.html"))


# ---------------- auth ----------------
@app.post("/api/register")
def register(req: Request, payload: Dict[str, Any] = Body(...)):
    login = (payload.get("login") or "").strip().lower()
    name = (payload.get("name") or "").strip()
    dept = (payload.get("dept") or "").strip() or "Общий"
    pw = payload.get("password") or ""
    if len(login) < 3: raise HTTPException(400, "Логин: минимум 3 символа")
    if not all(c.isalnum() or c in "._-" for c in login): raise HTTPException(400, "Логин: латиница, цифры, . _ -")
    if len(name) < 2: raise HTTPException(400, "Укажите имя")
    if len(pw) < 6: raise HTTPException(400, "Пароль: минимум 6 символов")
    if q("SELECT 1 FROM users WHERE login=?", (login,)): raise HTTPException(409, "Такой логин уже занят")
    first = not q("SELECT 1 FROM users WHERE deleted=0")
    role = "admin" if first else "user"
    salt, h = hash_pw(pw)
    uid = nid()
    ex("INSERT INTO users(id,login,name,dept,role,salt,hash,created,deleted) VALUES(?,?,?,?,?,?,?,?,0)",
       (uid, login, name, dept, role, salt, h, now()))
    tok = secrets.token_urlsafe(32)
    ex("INSERT INTO sessions VALUES(?,?,?)", (tok, uid, now()))
    event("auth", f"Регистрация: {name} ({role})", "ok", user_id=uid)
    r = JSONResponse(dict(ok=True, role=role, first=first))
    r.set_cookie("cr_session", tok, httponly=True, samesite="lax", max_age=86400 * 14)
    return r


@app.post("/api/login")
def login(payload: Dict[str, Any] = Body(...)):
    lg = (payload.get("login") or "").strip().lower()
    pw = payload.get("password") or ""
    r = q("SELECT * FROM users WHERE login=? AND deleted=0", (lg,))
    if not r: raise HTTPException(401, "Пользователь не найден")
    u = dict(r[0])
    _, h = hash_pw(pw, u["salt"])
    if not secrets.compare_digest(h, u["hash"]): raise HTTPException(401, "Неверный пароль")
    tok = secrets.token_urlsafe(32)
    ex("INSERT INTO sessions VALUES(?,?,?)", (tok, u["id"], now()))
    event("auth", f"Вход: {u['name']}", "ok", user_id=u["id"])
    resp = JSONResponse(dict(ok=True, role=u["role"]))
    resp.set_cookie("cr_session", tok, httponly=True, samesite="lax", max_age=86400 * 14)
    return resp


@app.post("/api/logout")
def logout(req: Request):
    tok = req.cookies.get("cr_session")
    if tok: ex("DELETE FROM sessions WHERE token=?", (tok,))
    r = JSONResponse(dict(ok=True)); r.delete_cookie("cr_session"); return r


# ---------------- state ----------------
@app.get("/api/state")
def state(req: Request):
    u = session_user(req)
    if not u: return dict(me=None)
    me = dict(id=u["id"], name=u["name"], login=u["login"], role=u["role"], dept=u["dept"])
    camp = dict(q("SELECT * FROM campaign WHERE id=1")[0])
    camp["cfg"] = json.loads(camp["cfg"]); camp["queue"] = json.loads(camp["queue"]); camp["targets"] = json.loads(camp["targets"])
    base = dict(me=me, catalog=catalog.ATTACKS, campaign=camp, server_time=now())
    if u["role"] != "admin":
        my = [r for r in rating_rows() if r["id"] == u["id"]]
        tokens = [dict(token=t["token"], used=t["used"]) for t in q("SELECT * FROM enroll WHERE user_id=?", (u["id"],))]
        base.update(me_rating=my[0] if my else None, my_tokens=tokens)
        return base
    tasks = [dict(r) for r in q("SELECT * FROM tasks ORDER BY created DESC LIMIT 60")]
    for t in tasks:
        t["params"] = json.loads(t["params"] or "{}")
        t["attack"] = catalog.BY_ID.get(t["attack_id"], {})
        t["metrics"] = list(METRICS.get(t["id"], []))
        t["logs"] = list(LOGS.get(t["id"], []))[-40:]
    agents = [dict(r) for r in q("SELECT * FROM agents ORDER BY created DESC")]
    for a in agents:
        a["online"] = agent_online(a); a.pop("key", None)
        uu = q("SELECT name,dept FROM users WHERE id=?", (a["user_id"],))
        a["user_name"] = uu[0]["name"] if uu else "—"
        a["dept"] = uu[0]["dept"] if uu else "—"
    base.update(rating=rating_rows(), agents=agents, tasks=tasks,
                events=[dict(r) for r in q("SELECT * FROM events ORDER BY ts DESC LIMIT 80")],
                presets=[dict(id=r["id"], name=r["name"], queue=json.loads(r["queue"]), cfg=json.loads(r["cfg"]))
                         for r in q("SELECT * FROM presets ORDER BY created DESC")],
                enroll=[dict(token=r["token"], user_id=r["user_id"], used=r["used"],
                             user_name=(q("SELECT name FROM users WHERE id=?", (r["user_id"],)) or [{"name": "—"}])[0]["name"])
                        for r in q("SELECT * FROM enroll ORDER BY created DESC LIMIT 20")],
                users=[dict(id=r["id"], name=r["name"], dept=r["dept"]) for r in q("SELECT * FROM users WHERE deleted=0 AND role='user'")])
    return base


# ---------------- admin ----------------
@app.post("/api/enroll")
def make_enroll(req: Request, payload: Dict[str, Any] = Body(...)):
    require(req, admin=True)
    uid = payload.get("user_id")
    if not q("SELECT 1 FROM users WHERE id=? AND deleted=0", (uid,)): raise HTTPException(404, "Сотрудник не найден")
    tok = secrets.token_urlsafe(18)
    ex("INSERT INTO enroll VALUES(?,?,?,0)", (tok, uid, now()))
    event("agent", f"Создан токен установки для {uid}", "ok", user_id=uid)
    return dict(token=tok)


@app.delete("/api/enroll/{token}")
def del_enroll(token: str, req: Request):
    require(req, admin=True); ex("DELETE FROM enroll WHERE token=?", (token,)); return dict(ok=True)


@app.post("/api/launch")
def launch(req: Request, payload: Dict[str, Any] = Body(...)):
    u = require(req, admin=True)
    aid, attack_id = payload.get("agent_id"), payload.get("attack_id")
    a = q("SELECT * FROM agents WHERE id=?", (aid,))
    if not a: raise HTTPException(404, "Агент не найден")
    a = dict(a[0])
    if not agent_online(a): raise HTTPException(409, "Агент офлайн — установите и запустите его на машине сотрудника")
    if attack_id not in catalog.BY_ID: raise HTTPException(400, "Неизвестная атака")
    params = catalog.clamp_params({**catalog.defaults(attack_id), **(payload.get("params") or {})})
    tid = nid()
    ex("INSERT INTO tasks(id,agent_id,user_id,attack_id,params,status,created) VALUES(?,?,?,?,?,'pending',?)",
       (tid, aid, a["user_id"], attack_id, json.dumps(params), now()))
    METRICS[tid] = deque(maxlen=90); LOGS[tid] = deque(maxlen=200)
    event("task", f"Запуск: {catalog.BY_ID[attack_id]['name']}", "warn", user_id=a["user_id"], agent_id=aid, task_id=tid)
    return dict(task_id=tid)


@app.post("/api/task/{tid}/control")
def control(tid: str, req: Request, payload: Dict[str, Any] = Body(...)):
    require(req, admin=True)
    r = q("SELECT * FROM tasks WHERE id=?", (tid,))
    if not r: raise HTTPException(404, "Задача не найдена")
    p = json.loads(dict(r[0])["params"] or "{}"); p.update(payload or {})
    p = catalog.clamp_params(p)
    ex("UPDATE tasks SET params=? WHERE id=?", (json.dumps(p), tid))
    return dict(ok=True, params=p)


@app.post("/api/task/{tid}/stop")
def stop_task(tid: str, req: Request):
    require(req, admin=True)
    ex("UPDATE tasks SET status='stopping' WHERE id=? AND status IN ('pending','running')", (tid,))
    event("task", "Останов задачи оператором", "warn", task_id=tid)
    return dict(ok=True)


@app.post("/api/task/{tid}/command")
def command(tid: str, req: Request, payload: Dict[str, Any] = Body(...)):
    require(req, admin=True)
    r = q("SELECT params FROM tasks WHERE id=?", (tid,))
    if not r: raise HTTPException(404, "Задача не найдена")
    p = json.loads(r[0]["params"] or "{}")
    p["_command"] = payload.get("command")
    ex("UPDATE tasks SET params=? WHERE id=?", (json.dumps(p), tid))
    return dict(ok=True)


@app.post("/api/agent/{aid}/kill")
def kill_agent(aid: str, req: Request):
    require(req, admin=True)
    ex("UPDATE agents SET killed=1 WHERE id=?", (aid,))
    ex("UPDATE tasks SET status='stopping' WHERE agent_id=? AND status IN ('pending','running')", (aid,))
    event("agent", "Kill-switch: все задачи агента остановлены", "bad", agent_id=aid)
    return dict(ok=True)


@app.post("/api/agent/{aid}/unkill")
def unkill(aid: str, req: Request):
    require(req, admin=True); ex("UPDATE agents SET killed=0 WHERE id=?", (aid,)); return dict(ok=True)


@app.delete("/api/user/{uid}")
def del_user(uid: str, req: Request):
    require(req, admin=True)
    ex("UPDATE users SET deleted=1 WHERE id=? AND role='user'", (uid,))
    event("user", "Сотрудник удалён", "warn", user_id=uid); return dict(ok=True)


@app.post("/api/user/{uid}/restore")
def restore_user(uid: str, req: Request):
    require(req, admin=True); ex("UPDATE users SET deleted=0 WHERE id=?", (uid,)); return dict(ok=True)


@app.post("/api/campaign")
def save_campaign(req: Request, payload: Dict[str, Any] = Body(...)):
    require(req, admin=True)
    c = dict(q("SELECT * FROM campaign WHERE id=1")[0])
    cfg = {**json.loads(c["cfg"]), **(payload.get("cfg") or {})}
    cfg["interval"] = max(10, min(1800, int(cfg.get("interval", 45))))
    cfg["ceiling"] = max(1, min(5, int(cfg.get("ceiling", 5))))
    queue = payload.get("queue", json.loads(c["queue"]))
    targets = payload.get("targets", json.loads(c["targets"]))
    ex("UPDATE campaign SET cfg=?,queue=?,targets=? WHERE id=1", (json.dumps(cfg), json.dumps(queue), json.dumps(targets)))
    return dict(ok=True)


@app.post("/api/campaign/{action}")
def campaign_action(action: str, req: Request):
    require(req, admin=True)
    c = dict(q("SELECT * FROM campaign WHERE id=1")[0])
    if action == "start":
        if not json.loads(c["queue"]): raise HTTPException(400, "Очередь атак пуста")
        ex("UPDATE campaign SET status='active', started=?, last=?, cur=0, tc=0 WHERE id=1",
           (now(), now() - json.loads(c["cfg"])["interval"] + 6))
        event("campaign", "Кампания запущена", "ok")
    elif action == "pause":
        ex("UPDATE campaign SET status='paused' WHERE id=1"); event("campaign", "Кампания на паузе", "warn")
    elif action == "stop":
        ex("UPDATE campaign SET status='idle', delivered=0 WHERE id=1"); event("campaign", "Кампания остановлена", "warn")
    else: raise HTTPException(400, "Неизвестное действие")
    return dict(ok=True)


@app.post("/api/presets")
def add_preset(req: Request, payload: Dict[str, Any] = Body(...)):
    require(req, admin=True)
    pid = nid()
    ex("INSERT INTO presets VALUES(?,?,?,?,?)", (pid, payload.get("name") or "Набор",
       json.dumps(payload.get("queue") or []), json.dumps(payload.get("cfg") or {}), now()))
    return dict(id=pid)


@app.delete("/api/presets/{pid}")
def del_preset(pid: str, req: Request):
    require(req, admin=True)
    r = q("SELECT * FROM presets WHERE id=?", (pid,))
    if r: ex("DELETE FROM presets WHERE id=?", (pid,))
    return dict(ok=True, removed=dict(r[0]) if r else None)


@app.post("/api/presets/restore")
def restore_preset(req: Request, payload: Dict[str, Any] = Body(...)):
    require(req, admin=True)
    r = payload.get("removed") or {}
    if r.get("id"):
        ex("INSERT OR REPLACE INTO presets VALUES(?,?,?,?,?)", (r["id"], r["name"], r["queue"], r["cfg"], now()))
    return dict(ok=True)


@app.get("/api/export")
def export(req: Request, type: str = "rating"):
    require(req, admin=True)
    if type == "rating":
        buf = io.StringIO(); w = csv.writer(buf, delimiter=";")
        w.writerow(["место", "имя", "логин", "отдел", "иммунитет", "XP", "серия", "точность", "report_rate", "отражено", "провалов", "агентов"])
        for i, r in enumerate(rating_rows(), 1):
            w.writerow([i, r["name"], r["login"], r["dept"], r["level"], r["xp"], r["streak"],
                        r["accuracy"], r["report_rate"], r["ok"], r["bad"], len(r["agents"])])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                                 headers={"Content-Disposition": 'attachment; filename="cyberrange_rating.csv"'})
    data = [dict(r) for r in q("SELECT * FROM events ORDER BY ts")]
    return PlainTextResponse(json.dumps(data, ensure_ascii=False, indent=2), media_type="application/json",
                             headers={"Content-Disposition": 'attachment; filename="cyberrange_events.json"'})


# ---------------- agent protocol ----------------
@app.post("/api/agent/enroll")
def agent_enroll(req: Request, payload: Dict[str, Any] = Body(...)):
    tok = payload.get("token")
    r = q("SELECT * FROM enroll WHERE token=? AND used=0", (tok,))
    if not r: raise HTTPException(403, "Токен установки недействителен или уже использован")
    e = dict(r[0])
    aid, key = nid(), secrets.token_urlsafe(24)
    ex("INSERT INTO agents(id,key,user_id,host,os,ver,last_seen,created,killed) VALUES(?,?,?,?,?,?,?,?,0)",
       (aid, key, e["user_id"], payload.get("host", "?"), payload.get("os", "?"), payload.get("ver", "1"), now(), now()))
    ex("UPDATE enroll SET used=1 WHERE token=?", (tok,))
    event("agent", f"Агент подключён: {payload.get('host')}", "ok", user_id=e["user_id"], agent_id=aid)
    return dict(agent_id=aid, key=key, user_id=e["user_id"])


def auth_agent(payload):
    r = q("SELECT * FROM agents WHERE id=? AND key=?", (payload.get("agent_id"), payload.get("key")))
    if not r: raise HTTPException(403, "Агент не авторизован")
    return dict(r[0])


@app.post("/api/agent/poll")
def agent_poll(payload: Dict[str, Any] = Body(...)):
    a = auth_agent(payload)
    ex("UPDATE agents SET last_seen=?, host=?, os=? WHERE id=?", (now(), payload.get("host", a["host"]), payload.get("os", a["os"]), a["id"]))
    if a["killed"]:
        return dict(tasks=[], controls={}, stops=[t["id"] for t in q("SELECT id FROM tasks WHERE agent_id=? AND status IN ('pending','running','stopping')", (a["id"],))], kill=True)
    tasks = [dict(r) for r in q("SELECT * FROM tasks WHERE agent_id=? AND status='pending'", (a["id"],))]
    for t in tasks:
        t["params"] = json.loads(t["params"] or "{}")
        ex("UPDATE tasks SET status='running', started=? WHERE id=?", (now(), t["id"]))
        METRICS.setdefault(t["id"], deque(maxlen=90)); LOGS.setdefault(t["id"], deque(maxlen=200))
    controls = {t["id"]: json.loads(t["params"] or "{}") for t in
                q("SELECT * FROM tasks WHERE agent_id=? AND status='running'", (a["id"],))}
    stops = [t["id"] for t in q("SELECT id FROM tasks WHERE agent_id=? AND status='stopping'", (a["id"],))]
    return dict(tasks=[dict(id=t["id"], attack_id=t["attack_id"], params=t["params"]) for t in tasks],
                controls=controls, stops=stops, kill=False)


@app.post("/api/agent/report")
def agent_report(payload: Dict[str, Any] = Body(...)):
    a = auth_agent(payload)
    tid = payload.get("task_id")
    r = q("SELECT * FROM tasks WHERE id=?", (tid,))
    if not r: raise HTTPException(404, "Задача не найдена")
    t = dict(r[0])
    m = payload.get("metrics")
    if isinstance(m, dict):
        m["t"] = now(); METRICS.setdefault(tid, deque(maxlen=90)).append(m)
    for line in payload.get("logs") or []:
        LOGS.setdefault(tid, deque(maxlen=200)).append(line)
        event("exec", line.get("m", ""), line.get("l", "info"), user_id=t["user_id"], agent_id=a["id"], task_id=tid)
    if payload.get("evidence"):
        ex("UPDATE tasks SET evidence=? WHERE id=?", (payload["evidence"], tid))
    status = payload.get("status")
    if status in ("done", "stopped"):
        outcome = payload.get("outcome") or "ignore"
        lvl = catalog.BY_ID.get(t["attack_id"], {}).get("lvl", 1)
        sc = score_of(outcome, lvl)
        ex("UPDATE tasks SET status='done', outcome=?, score=?, finished=? WHERE id=?", (outcome, sc, now(), tid))
        event("outcome", f"{catalog.BY_ID.get(t['attack_id'],{}).get('name','атака')} → {outcome} ({sc:+d} XP)",
              "ok" if sc > 0 else "bad", user_id=t["user_id"], agent_id=a["id"], task_id=tid)
    return dict(ok=True)


# ---------------- campaign scheduler ----------------
import asyncio

async def scheduler():
    while True:
        try:
            c = dict(q("SELECT * FROM campaign WHERE id=1")[0])
            if c["status"] == "active":
                cfg = json.loads(c["cfg"]); queue = json.loads(c["queue"]); targets = json.loads(c["targets"])
                if cfg.get("duration") and now() - c["started"] > cfg["duration"] * 60:
                    ex("UPDATE campaign SET status='idle' WHERE id=1"); event("campaign", "Кампания завершена по таймеру", "warn")
                elif now() - c["last"] >= cfg["interval"]:
                    pool = [catalog.BY_ID[i] for i in queue if i in catalog.BY_ID and catalog.BY_ID[i]["lvl"] <= cfg["ceiling"]]
                    agents = [dict(r) for r in q("SELECT * FROM agents WHERE killed=0")]
                    agents = [a for a in agents if agent_online(a) and (not targets or a["user_id"] in targets)]
                    if pool and agents:
                        if cfg.get("order") == "asc": pool.sort(key=lambda x: x["lvl"])
                        atk = pool[ri(len(pool))] if cfg.get("order") == "random" else pool[c["cur"] % len(pool)]
                        ag = agents[c["tc"] % len(agents)]
                        tid = nid()
                        ex("INSERT INTO tasks(id,agent_id,user_id,attack_id,params,status,created) VALUES(?,?,?,?,?,'pending',?)",
                           (tid, ag["id"], ag["user_id"], atk["id"], json.dumps(catalog.defaults(atk["id"])), now()))
                        METRICS[tid] = deque(maxlen=90); LOGS[tid] = deque(maxlen=200)
                        cur = c["cur"] + 1
                        if cur >= len(pool) and not cfg.get("loop"):
                            ex("UPDATE campaign SET status='idle' WHERE id=1"); event("campaign", "Очередь пройдена", "ok")
                        ex("UPDATE campaign SET last=?, cur=?, tc=?, delivered=delivered+1 WHERE id=1",
                           (now(), cur, c["tc"] + 1))
                        event("task", f"Кампания: {atk['name']} → агент {ag['host']}", "warn",
                              user_id=ag["user_id"], agent_id=ag["id"], task_id=tid)
        except Exception as e:
            print("scheduler:", e)
        await asyncio.sleep(1)


def ri(n):
    import random
    return random.randrange(n)


@app.on_event("startup")
async def startup():
    asyncio.create_task(scheduler())
    print("\n  CyberRange server готов. Откройте http://127.0.0.1:8000")
    print("  Первый зарегистрированный аккаунт становится оператором.\n")
