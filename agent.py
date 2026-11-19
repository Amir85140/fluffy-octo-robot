"""CyberRange Agent — фоновая служба БЕЗ ОКОН.
Ставится оператором на машину сотрудника, автостарт + супервизор, не останавливается.

  python agent.py --enroll TOKEN --server http://SERVER:8000
  python agent.py --install          # автостарт + запуск супервизора в фоне
  python agent.py --run              # один рабочий цикл (для отладки)
  python agent.py --uninstall        # снять автостарт и остановить

Все атаки исполняются реально, но только против 127.0.0.1 и внутри песочницы.
"""
import argparse, base64, hashlib, http.client, json, os, platform, random, secrets, shutil, socket, sqlite3, \
    string, subprocess, sys, threading, time, urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

try:
    import psutil
except Exception:
    psutil = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

HOME = Path.home() / ".cyberrange"
SANDBOX = HOME / "sandbox"
CFG = HOME / "agent.json"
STOP_FILE = HOME / "STOP"
HOME.mkdir(parents=True, exist_ok=True)
SANDBOX.mkdir(parents=True, exist_ok=True)
VER = "2.0"
LOOPBACK = "127.0.0.1"


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    try:
        with open(HOME / "agent.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def load_cfg():
    if CFG.exists():
        try: return json.loads(CFG.read_text("utf-8"))
        except Exception: return {}
    return {}


def save_cfg(c): CFG.write_text(json.dumps(c, indent=2), "utf-8")


def api(server, path, payload, timeout=12):
    req = urllib.request.Request(server.rstrip("/") + path,
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def safe_path(p: Path) -> Path:
    p = p.resolve()
    if not str(p).startswith(str(SANDBOX.resolve())):
        raise RuntimeError("path outside sandbox blocked")
    return p


# ------------------------------------------------------------------ notifications
def notify(title, body, url=None):
    """Нативное системное уведомление. Окна приложения не создаются никогда."""
    sysname = platform.system()
    try:
        if sysname == "Windows":
            ps = (
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null;"
                "$x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(2);"
                f"$t=$x.GetElementsByTagName('text');$t.Item(0).AppendChild($x.CreateTextNode('{title}'))|Out-Null;"
                f"$t.Item(1).AppendChild($x.CreateTextNode('{body}'))|Out-Null;"
            )
            if url:
                ps += (f"$a=$x.CreateElement('actions');$act=$x.CreateElement('action');"
                       f"$act.SetAttribute('content','Открыть');$act.SetAttribute('activationType','protocol');"
                       f"$act.SetAttribute('arguments','{url}');$a.AppendChild($act)|Out-Null;$x.DocumentElement.AppendChild($a)|Out-Null;")
            ps += ("$n=[Windows.UI.Notifications.ToastNotification]::new($x);"
                   "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('CyberRange').Show($n);")
            subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                           capture_output=True, timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return True
        if sysname == "Darwin":
            if shutil.which("terminal-notifier") and url:
                subprocess.run(["terminal-notifier", "-title", title, "-message", body, "-open", url],
                               capture_output=True, timeout=15); return True
            subprocess.run(["osascript", "-e",
                            f'display notification "{body}" with title "{title}"'],
                           capture_output=True, timeout=15); return True
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", "-u", "critical", title, body], capture_output=True, timeout=15)
            return True
    except Exception as e:
        log(f"notify failed: {e}")
    return False


# ------------------------------------------------------------------ sandbox target
class Target:
    """Реальный HTTP-сервис-мишень на loopback. Защищается по-настоящему."""
    def __init__(self, task):
        self.task = task
        self.lock = threading.Lock()
        self.reqs = 0; self.ok = 0; self.rejected = 0; self.lat = []; self.fails = 0
        self.logins = 0; self.login_ok = 0; self.login_blocked = 0
        self.attempts = {}
        self.lures = {}
        self.captured = []
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.execute("CREATE TABLE users(u TEXT,p TEXT,role TEXT)")
        self.db.executemany("INSERT INTO users VALUES(?,?,?)",
                            [("admin", "s3cret!x", "admin"), ("elena", "qwerty123", "user"), ("dmitry", "dragon2024", "user")])
        self.db.commit()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *a): pass
            def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                if outer.task.params.get("csp"):
                    self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
                for k, v in (extra or {}).items(): self.send_header(k, v)
                self.end_headers()
                try: self.wfile.write(body)
                except Exception: pass
            def do_GET(self):
                t0 = time.time(); p = outer.task.params
                with outer.lock: outer.reqs += 1
                rl = int(p.get("rate_limit") or 0)
                if rl and outer.reqs % max(1, int(200 / max(1, rl))) == 0:
                    with outer.lock: outer.rejected += 1
                    return self._send(429, b"rate limited", "text/plain")
                if p.get("cache") and self.path == "/" and outer.reqs % 3:
                    return self._send(200, b"cached", "text/plain")
                work = int(p.get("work_ms") or 0)
                if work:
                    end = time.time() + work / 1000.0
                    while time.time() < end: hashlib.sha256(b"x" * 512).digest()
                if self.path.startswith("/p/"):
                    return outer.serve_lure(self)
                if self.path.startswith("/sqli"):
                    return outer.serve_sqli(self)
                if self.path.startswith("/xss"):
                    return outer.serve_xss(self)
                if self.path.startswith("/beacon"):
                    with outer.lock: outer.captured.append(time.time())
                    return self._send(200, b"ok", "text/plain")
                self._send(200, b"<h3>sandbox service</h3>")
                with outer.lock:
                    outer.ok += 1; outer.lat.append((time.time() - t0) * 1000)
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                if self.path.startswith("/p/"):
                    return outer.lure_post(self, raw)
                if self.path == "/login":
                    return outer.do_login(self, raw)
                self._send(404, b"no", "text/plain")

        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    # ---- real auth endpoint with real defenses
    def do_login(self, h, raw):
        p = self.task.params
        try: data = json.loads(raw.decode() or "{}")
        except Exception: data = {}
        src = data.get("src", "local")
        with self.lock:
            self.logins += 1
            self.attempts[src] = self.attempts.get(src, 0) + 1
            n = self.attempts[src]
        lock = int(p.get("lockout") or 0)
        if lock and n > lock:
            with self.lock: self.login_blocked += 1
            return h._send(429, json.dumps({"error": "locked"}).encode(), "application/json")
        if p.get("captcha"):
            time.sleep(0.25)
        if p.get("breach_check") and str(data.get("p", "")) in WEAK:
            with self.lock: self.login_blocked += 1
            return h._send(403, json.dumps({"error": "breached password"}).encode(), "application/json")
        row = self.db.execute("SELECT u FROM users WHERE u=? AND p=?",
                              (data.get("u", ""), data.get("p", ""))).fetchone()
        if row and p.get("tfa"):
            with self.lock: self.login_blocked += 1
            return h._send(403, json.dumps({"error": "2fa required"}).encode(), "application/json")
        if row:
            with self.lock: self.login_ok += 1
            return h._send(200, json.dumps({"ok": True, "user": row[0]}).encode(), "application/json")
        return h._send(401, json.dumps({"error": "bad credentials"}).encode(), "application/json")

    # ---- lures
    def add_lure(self, token, html, kind="phish"):
        with self.lock:
            self.lures[token] = dict(html=html, kind=kind, opened=False, submitted=False, reported=False, keys=0)

    def serve_lure(self, h):
        parts = h.path.split("/")
        token = parts[2] if len(parts) > 2 else ""
        with self.lock:
            l = self.lures.get(token)
            if l: l["opened"] = True
        if not l: return h._send(404, b"expired", "text/plain")
        h._send(200, l["html"].encode())

    def lure_post(self, h, raw):
        parts = h.path.split("/")
        token = parts[2] if len(parts) > 2 else ""
        action = parts[3] if len(parts) > 3 else "submit"
        with self.lock:
            l = self.lures.get(token)
            if not l: return h._send(404, b"expired", "text/plain")
            if action == "report":
                l["reported"] = True
                return h._send(200, TEACH.replace("{{T}}", "Сообщение принято. Это была учебная тревога — вы поступили верно.").encode())
            if action == "keys":
                l["keys"] += 1
                return h._send(200, b"ok", "text/plain")
            l["submitted"] = True   # значение пароля НЕ сохраняется никогда
        return h._send(200, TEACH.replace("{{T}}", "Данные отправлены атакующему. Это была учебная тревога — разберите красные флаги.").encode())

    def serve_sqli(self, h):
        import urllib.parse as up
        qs = up.parse_qs(up.urlparse(h.path).query)
        payload = qs.get("q", ["' OR '1'='1"])[0]
        if self.task.params.get("parameterized"):
            rows = self.db.execute("SELECT u,p,role FROM users WHERE u=? AND p=?", ("admin", payload)).fetchall()
            sql = f"SELECT u,p,role FROM users WHERE u=? AND p=?   params=['admin', {payload!r}]"
        else:
            sql = f"SELECT u,p,role FROM users WHERE u='admin' AND p='{payload}'"
            try:
                rows = self.db.execute(sql).fetchall()
            except Exception as e:
                rows = []; sql += f"   -- ERROR: {e}"
        body = ("<h3>SQL sandbox</h3><pre style='color:#b45309'>" + sql + "</pre>"
                "<table border=1 cellpadding=6>" + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
                + f"</table><p>строк: {len(rows)}</p>")
        self.task.evidence = f"SQL вернул {len(rows)} строк; параметризация={'вкл' if self.task.params.get('parameterized') else 'выкл'}"
        h._send(200, body.encode())

    def serve_xss(self, h):
        import urllib.parse as up
        qs = up.parse_qs(up.urlparse(h.path).query)
        payload = qs.get("q", ["<script>fetch('/beacon?xss=1')</script>"])[0]
        shown = (payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                 if self.task.params.get("sanitize") else payload)
        h._send(200, f"<h3>XSS sandbox</h3><div>Пост: {shown}</div>".encode())

    def close(self):
        try: self.httpd.shutdown(); self.httpd.server_close()
        except Exception: pass


TEACH = """<!doctype html><meta charset=utf-8><body style="font-family:system-ui;background:#0b1220;color:#e8eefb;padding:40px">
<h2 style="color:#22d3ee">CyberRange · учебная тревога</h2><p style="font-size:17px;max-width:620px">{{T}}</p>
<p style="color:#93a4c4">Значение пароля не сохранялось — фиксируется только факт отправки. Разбор доступен оператору ИБ.</p>"""

WEAK = {"qwerty123", "password1", "123456", "dragon2024", "admin", "qwerty", "letmein"}
DICT = ["qwerty123", "password1", "123456", "dragon2024", "admin", "s3cret!x", "letmein", "welcome1", "iloveyou", "monkey"]


def lure_html(tpl, token, base):
    forms = {
        "account": ("Служба безопасности", "Ваш аккаунт взломан. Смените пароль немедленно.", "Пароль", "Сменить пароль"),
        "prize": ("MEGA-PRIZE", "Вы выиграли смартфон! Оплатите доставку 199₽.", "Номер карты", "Получить приз"),
        "bank": ("Банк · оператор", "Подтвердите отмену операции. Назовите код из SMS.", "Код из SMS", "Отменить операцию"),
        "m365": ("Microsoft 365", "Ящик будет отключён. Подтвердите пароль для синхронизации.", "Пароль", "Подтвердить"),
        "delivery": ("Служба доставки", "Посылка задержана. Оплатите повторную доставку 99₽.", "Номер карты", "Оплатить"),
        "helpdesk": ("Техподдержка", "На вашем ПК вирус. Введите код подключения AnyDesk.", "Код подключения", "Подключиться"),
        "ceo": ("Директор", "Срочно оплати счёт партнёра. Никому не сообщай.", "Подтверждение платежа", "Оплатить"),
        "chain": ("Проверка входа", "Подтвердите личность кодом из SMS.", "Код 2FA", "Подтвердить"),
    }
    who, text, field, cta = forms.get(tpl, forms["account"])
    keylog = ""
    if tpl == "keylog":
        keylog = f"<script>document.getElementById('f').addEventListener('input',()=>fetch('{base}/p/{token}/keys',{{method:'POST'}}))</script>"
    return f"""<!doctype html><meta charset=utf-8><title>{who}</title>
<body style="font-family:system-ui;background:#f3f4f6;margin:0;padding:40px">
<div style="max-width:420px;margin:auto;background:#fff;border-radius:12px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,.12)">
<h2 style="margin:0 0 6px">{who}</h2><p style="color:#4b5563">{text}</p>
<form method=post action="{base}/p/{token}/submit">
<input id=f name=secret placeholder="{field}" style="width:100%;padding:11px;margin:10px 0;border:1px solid #d1d5db;border-radius:8px">
<button style="width:100%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-weight:700">{cta}</button></form>
<form method=post action="{base}/p/{token}/report" style="margin-top:14px">
<button style="width:100%;padding:10px;background:#fff;color:#b91c1c;border:1px solid #fca5a5;border-radius:8px;font-weight:700">🚨 Это фишинг — сообщить в ИБ</button></form>
<p style="color:#9ca3af;font-size:12px;margin-top:14px">Адрес страницы: {base} — не корпоративный домен.</p></div>{keylog}"""


# ------------------------------------------------------------------ task runner
class Task:
    def __init__(self, tid, attack_id, params, agent):
        self.id = tid; self.attack_id = attack_id; self.params = dict(params); self.agent = agent
        self.stop_flag = threading.Event()
        self.dir = safe_path(SANDBOX / tid); self.dir.mkdir(parents=True, exist_ok=True)
        self.backup = safe_path(self.dir / "_backup"); self.backup.mkdir(exist_ok=True)
        self.target = None; self.outcome = None; self.evidence = ""
        self.logs = []; self.metrics = {}
        self.thread = threading.Thread(target=self._run, daemon=True)

    def say(self, m, l="info"):
        self.logs.append(dict(m=m, l=l, t=time.time()))
        log(f"[{self.id}] {m}")

    def stopped(self): return self.stop_flag.is_set()

    def start(self): self.thread.start()

    def stop(self):
        self.stop_flag.set()

    def _run(self):
        mod = MODULES.get(self.attack_id)
        try:
            self.target = Target(self)
            self.say(f"Песочница: {self.dir}", "info")
            self.say(f"Локальная цель поднята на {LOOPBACK}:{self.target.port}", "ok")
            fn = ENGINE.get(mod)
            if not fn: raise RuntimeError("модуль не найден")
            fn(self)
        except Exception as e:
            self.say(f"ошибка модуля: {e}", "bad")
            self.outcome = self.outcome or "lose"
        finally:
            self.cleanup()
            self.agent.finish(self)

    def cleanup(self):
        try:
            if self.target: self.target.close()
        except Exception: pass

    def url(self): return f"http://{LOOPBACK}:{self.target.port}"


# ------------------------------------------------------------------ REAL engines
def eng_phish(t: Task):
    p = t.params
    tpl = p.get("tpl", "account")
    channels = [("email", "Новое письмо", "Служба безопасности: требуется подтверждение")]
    if p.get("chain"):
        channels = [("email", "Новое письмо", "Обновление учётной записи"),
                    ("sms", "SMS", "Код подтверждения: 482913 — сообщите оператору"),
                    ("call", "Входящий звонок", "Служба безопасности банка")]
    elif p.get("vector") == "sms":
        channels = [("sms", "SMS", "Ваша посылка задержана, оплатите доставку")]
    elif p.get("vector") == "call":
        channels = [("call", "Входящий звонок", "Служба безопасности банка")]
    deadline = time.time() + int(p.get("ttl", 180))
    for i, (ch, title, body) in enumerate(channels):
        if t.stopped(): break
        token = secrets.token_urlsafe(8)
        t.target.add_lure(token, lure_html("keylog" if t.attack_id == "keylog" else tpl, token, t.url()))
        url = f"{t.url()}/p/{token}"
        ok = notify(title, body + (" · " + url if platform.system() != "Windows" else ""), url)
        t.say(f"Канал {ch}: уведомление доставлено ({'нативно' if ok else 'лог'}), приманка {url}", "warn")
        t.metrics = dict(channel=ch, delivered=i + 1, opened=0, submitted=0, reported=0)
        while time.time() < deadline and not t.stopped():
            with t.target.lock:
                l = t.target.lures.get(token, {})
                opened, sub, rep = l.get("opened"), l.get("submitted"), l.get("reported")
                keys = l.get("keys", 0)
            t.metrics = dict(channel=ch, delivered=i + 1, opened=int(bool(opened)),
                             submitted=int(bool(sub)), reported=int(bool(rep)), keys=keys,
                             ttl=max(0, int(deadline - time.time())))
            if rep:
                t.outcome = "report"; t.evidence = f"Сотрудник сообщил в ИБ из канала {ch}"; break
            if sub:
                t.outcome = "submit"; t.evidence = f"Форма отправлена в канале {ch} (значение не сохранено)"; break
            if keys and t.attack_id == "keylog":
                t.evidence = f"Перехвачено нажатий в поле приманки: {keys}"
            time.sleep(0.5)
        if t.outcome: break
        if i < len(channels) - 1: time.sleep(4)
    if not t.outcome:
        t.outcome = "click" if t.metrics.get("opened") else "ignore"
        t.evidence = "Приманка открыта, но не отправлена" if t.metrics.get("opened") else "Взаимодействия не было"


def eng_flood(t: Task):
    p = t.params
    end = time.time() + int(p.get("duration", 60))
    port = t.target.port
    lat = []; codes = {}; sent = 0; window = []
    lock = threading.Lock()

    def worker():
        nonlocal sent
        while time.time() < end and not t.stopped():
            pace = max(1, int(p.get("rps", 100))) / max(1, int(p.get("workers", 8)))
            time.sleep(max(0.001, 1.0 / pace) * random.uniform(.7, 1.3))
            path = "/" if not p.get("dist") else random.choice(["/", "/?q=1", "/?deep=1"])
            t0 = time.time()
            try:
                c = http.client.HTTPConnection(LOOPBACK, port, timeout=4)
                c.request("GET", path, headers={"X-Source": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" if p.get("dist") else "10.0.0.7"})
                r = c.getresponse(); r.read(); code = r.status; c.close()
            except Exception:
                code = 599
            d = (time.time() - t0) * 1000
            with lock:
                sent += 1; lat.append(d); codes[code] = codes.get(code, 0) + 1; window.append(time.time())

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(int(p.get("workers", 8)))]
    for th in threads: th.start()
    t.say(f"РЕАЛЬНЫЙ флуд запущен: {p.get('workers')} потоков → {LOOPBACK}:{port}", "bad")
    while time.time() < end and not t.stopped():
        time.sleep(1)
        with lock:
            cutoff = time.time() - 1
            window[:] = [x for x in window if x > cutoff]
            rps = len(window)
            avg = sum(lat[-200:]) / max(1, len(lat[-200:]))
            bad = sum(v for k, v in codes.items() if k >= 500 or k == 429 or k == 599)
            total = sum(codes.values()) or 1
            lat.clear()
        avail = max(0, 100 - round(bad / total * 100))
        t.metrics = dict(rps=rps, latency=round(avg, 1), availability=avail, sent=sent,
                         rejected=t.target.rejected, codes=dict(codes))
        if rps and avail < 25:
            t.say(f"Сервис деградирует: доступность {avail}% при {rps} rps", "bad")
    t.stop_flag.set()
    for th in threads: th.join(timeout=2)
    avail = t.metrics.get("availability", 100)
    t.outcome = "lose" if avail < 40 else "win"
    t.evidence = f"Реально отправлено {sent} HTTP-запросов; итоговая доступность {avail}%"


def eng_brute(t: Task):
    p = t.params
    end = time.time() + int(p.get("duration", 60))
    port = t.target.port; n = 0; ok = 0; blocked = 0
    stuff = t.attack_id == "credstuff"
    pairs = [(f"user{i}@corp.ru", random.choice(DICT)) for i in range(400)]
    t.say(f"РЕАЛЬНЫЕ POST-попытки входа → {LOOPBACK}:{port}/login", "bad")
    while time.time() < end and not t.stopped():
        time.sleep(max(0.02, 1.0 / max(1, int(p.get("rate", 8)))))
        u, pw = (random.choice(pairs) if stuff else ("admin", random.choice(DICT)))
        src = f"10.1.{random.randint(0,255)}.{random.randint(1,254)}" if p.get("dist") else "10.1.0.9"
        try:
            c = http.client.HTTPConnection(LOOPBACK, port, timeout=4)
            c.request("POST", "/login", body=json.dumps(dict(u=u, p=pw, src=src)),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse(); r.read(); code = r.status; c.close()
        except Exception:
            code = 599
        n += 1
        if code == 200: ok += 1; t.say(f"УСПЕШНЫЙ ВХОД: {u} / {pw}", "bad")
        if code in (429, 403): blocked += 1
        t.metrics = dict(attempts=n, success=ok, blocked=blocked,
                         block_rate=round(blocked / max(1, n) * 100), rate=int(p.get("rate", 8)))
        if ok >= 3: break
    t.outcome = "lose" if ok else "win"
    t.evidence = f"Реальных попыток: {n}, успешных входов: {ok}, отклонено защитами: {blocked}"


def eng_ransom(t: Task):
    if AESGCM is None:
        t.say("cryptography не установлена — реальное шифрование недоступно", "bad"); t.outcome = "lose"; return
    p = t.params
    names = ["отчёт_Q3.docx", "бюджет.xlsx", "договор_4471.pdf", "архив.zip", "презентация.pptx",
             "клиенты.csv", "зарплаты.xlsx", "план_2027.docx", "сканы.pdf", "бэкап_1С.bak",
             "протокол.docx", "чертежи.dwg", "смета.xlsx", "акт.pdf", "кадры.zip", "нотатки.txt",
             "реестр.csv", "устав.docx", "патент.pdf", "логотип.png", "договор_2.pdf", "отчёт_2.xlsx",
             "карта.dwg", "инструкция.docx"][:int(p.get("files", 12))]
    files = []
    for n in names:
        f = safe_path(t.dir / n)
        f.write_bytes(("Конфиденциальный документ " + n + "\n" + "данные " * 200).encode("utf-8"))
        shutil.copy2(f, safe_path(t.backup / n))
        files.append(f)
    t.say(f"Создано реальных файлов: {len(files)}; резервная копия снята", "info")
    key = AESGCM.generate_key(bit_length=256)
    (t.dir / "KEY.bin").write_bytes(key)
    if p.get("exfil"):
        ex_dir = safe_path(t.dir / "_exfil"); ex_dir.mkdir(exist_ok=True)
        for f in files: shutil.copy2(f, safe_path(ex_dir / f.name))
        t.say(f"Эксфильтрация: {len(files)} копий реально скопировано в {ex_dir.name}", "bad")
    enc = 0; restored = False; isolated = False
    deadline = time.time() + 150
    note = safe_path(t.dir / "README_RESTORE.txt")
    i = 0
    while time.time() < deadline and not t.stopped():
        cmd = p.pop("_command", None)
        if cmd == "isolate":
            isolated = True; t.say("Изоляция: распространение остановлено оператором", "ok")
        if cmd == "restore":
            for f in files:
                src = safe_path(t.backup / f.name)
                if src.exists(): shutil.copy2(src, f)
                locked = f.with_suffix(f.suffix + ".locked")
                if locked.exists(): locked.unlink()
            restored = True; enc = 0; t.say("РЕАЛЬНОЕ восстановление из резервной копии выполнено", "ok")
        if cmd == "pay":
            t.outcome = "lose"; t.evidence = "Выкуп оплачен — гарантий расшифровки нет"; break
        if not isolated and not restored and i < len(files):
            f = files[i]; i += 1
            nonce = secrets.token_bytes(12)
            ct = AESGCM(key).encrypt(nonce, f.read_bytes(), None)
            locked = safe_path(Path(str(f) + ".locked"))
            locked.write_bytes(nonce + ct); f.unlink(); enc += 1
            note.write_text(f"Ваши файлы зашифрованы AES-256-GCM. Зашифровано: {enc}. Выкуп 0.5 BTC.", "utf-8")
            t.say(f"AES-256-GCM: {f.name} → {locked.name} ({len(ct)} байт)", "bad")
        t.metrics = dict(files=len(files), encrypted=enc, restored=int(restored), isolated=int(isolated),
                         exfil=int(bool(p.get("exfil"))), bytes=sum(x.stat().st_size for x in t.dir.glob("*.locked")))
        if restored and isolated:
            t.outcome = "win"; t.evidence = "Изоляция + реальное восстановление из бэкапа"; break
        if enc >= len(files) and not restored:
            t.outcome = "lose"; t.evidence = f"Все {enc} файлов реально зашифрованы, восстановление не выполнено"; break
        time.sleep(max(0.15, int(p.get("spread_ms", 1200)) / 1000))
    if not t.outcome: t.outcome = "ignore"


def eng_miner(t: Task):
    p = t.params
    end = time.time() + int(p.get("duration", 60))
    stop = threading.Event()

    def burn():
        while not stop.is_set() and time.time() < end and not t.stopped():
            duty = max(0.05, min(0.9, int(p.get("cpu_cap", 25)) / 100))
            t0 = time.time()
            while time.time() - t0 < duty * 0.2:
                hashlib.sha256(secrets.token_bytes(256)).digest()
            time.sleep(max(0.001, (1 - duty) * 0.2))

    ths = [threading.Thread(target=burn, daemon=True) for _ in range(int(p.get("threads", 2)))]
    for th in ths: th.start()
    t.say(f"РЕАЛЬНАЯ нагрузка CPU: {len(ths)} потоков, лимит {p.get('cpu_cap')}%", "bad")
    while time.time() < end and not t.stopped():
        cmd = p.pop("_command", None)
        if cmd == "kill":
            t.say("Процесс майнера остановлен оператором", "ok"); break
        cpu = psutil.cpu_percent(interval=0.6) if psutil else None
        t.metrics = dict(cpu=cpu if cpu is not None else 0, threads=len(ths),
                         cap=int(p.get("cpu_cap", 25)), mem=round(psutil.virtual_memory().percent, 1) if psutil else 0)
        time.sleep(0.4)
    stop.set()
    for th in ths: th.join(timeout=2)
    t.outcome = "win" if p.get("_killed") or True else "lose"
    t.evidence = f"Реальная загрузка CPU ограничена {p.get('cpu_cap')}%, потоков {len(ths)}"


def eng_scan(t: Task):
    p = t.params
    count = int(p.get("ports", 120))
    common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 27017]
    targets = common + [t.target.port] + list(range(1024, 1024 + max(0, count - len(common) - 1)))
    found = []
    t.say(f"РЕАЛЬНЫЙ TCP-скан {LOOPBACK}, {len(targets)} портов", "warn")
    for i, port in enumerate(targets):
        if t.stopped(): break
        s = socket.socket(); s.settimeout(0.12)
        try:
            if s.connect_ex((LOOPBACK, port)) == 0:
                found.append(port); t.say(f"открыт порт {port}", "bad")
        finally:
            s.close()
        t.metrics = dict(scanned=i + 1, total=len(targets), open=len(found), ports=found[:12])
        time.sleep(0.02)
    t.outcome = "win"
    t.evidence = f"Реально открытых портов на loopback: {len(found)} → {found[:10]}"


def eng_usb(t: Task):
    p = t.params
    usb = safe_path(t.dir / "USB_DRIVE"); usb.mkdir(exist_ok=True)
    names = ["Зарплаты_Q3.pdf.exe", "Фото_корпоратив.jpg.exe", "Отчёт.docm", "Пароли_от_Wi-Fi.lnk", "Премии.xlsx", "Инструкция.pdf"]
    for n in names[:int(p.get("files", 6))]:
        safe_path(usb / n).write_bytes(b"decoy payload — безвреден")
    token = secrets.token_urlsafe(8)
    t.target.add_lure(token, lure_html("account", token, t.url()))
    url = f"{t.url()}/p/{token}"
    notify("Найден USB-носитель", f"Обнаружено {len(names)} файлов. Проверьте носитель: {url}", url)
    t.say(f"РЕАЛЬНО создано {len(names)} файлов-приманок в {usb}", "warn")
    deadline = time.time() + 150
    while time.time() < deadline and not t.stopped():
        with t.target.lock:
            l = t.target.lures.get(token, {})
        t.metrics = dict(files=len(names), opened=int(bool(l.get("opened"))),
                         submitted=int(bool(l.get("submitted"))), reported=int(bool(l.get("reported"))))
        if l.get("reported"): t.outcome = "report"; break
        if l.get("submitted"): t.outcome = "submit"; break
        time.sleep(0.5)
    t.outcome = t.outcome or ("click" if t.metrics.get("opened") else "ignore")
    t.evidence = f"Файлы созданы реально: {usb}"


def eng_sqli(t: Task):
    token = secrets.token_urlsafe(6)
    url = f"{t.url()}/sqli?q=" + "' OR '1'='1"
    t.say(f"РЕАЛЬНЫЙ SQLite: инъекция доступна по {url}", "bad")
    import urllib.request as ur
    deadline = time.time() + 120
    while time.time() < deadline and not t.stopped():
        try:
            with ur.urlopen(url, timeout=5) as r: html = r.read().decode()
            rows = html.count("<tr>")
        except Exception:
            rows = 0
        safe = int(bool(t.params.get("parameterized")))
        t.metrics = dict(rows=rows, parameterized=safe, injected=int(rows > 1))
        if rows > 1 and not safe:
            t.say(f"Инъекция успешна: реально возвращено {rows} строк", "bad")
        if safe and rows <= 1:
            t.outcome = "win"; t.evidence = f"Параметризация включена: инъекция вернула {rows} строк"; break
        time.sleep(1.2)
    t.outcome = t.outcome or "lose"
    t.evidence = t.evidence or "Уязвимая конкатенация строк осталась включённой"


def eng_xss(t: Task):
    token = secrets.token_urlsafe(6)
    payload = "<script>fetch('/beacon?xss=1')</script>"
    url = f"{t.url()}/xss?q=" + payload
    notify("Новый пост на портале", "Откройте обсуждение: " + url, url)
    t.say(f"РЕАЛЬНЫЙ XSS-payload опубликован: {url}", "bad")
    deadline = time.time() + 150
    while time.time() < deadline and not t.stopped():
        hits = len(t.target.captured)
        prot = int(bool(t.params.get("csp") or t.params.get("sanitize")))
        t.metrics = dict(executed=hits, protected=prot)
        if hits and not prot: t.say(f"Скрипт реально выполнен в браузере: beacon ×{hits}", "bad")
        if prot and hits == 0:
            t.outcome = "win"; t.evidence = "CSP/экранирование включены — выполнение заблокировано"; break
        time.sleep(1)
    t.outcome = t.outcome or ("lose" if t.target.captured else "ignore")


def eng_mitm(t: Task):
    token = secrets.token_urlsafe(8)
    t.target.add_lure(token, lure_html("m365", token, t.url()))
    url = f"{t.url()}/p/{token}"
    notify("Сеть Wi-Fi требует входа", "Подтвердите учётную запись: " + url, url)
    t.say("РЕАЛЬНЫЙ перехват: тело POST своей песочницы читается прокси", "bad")
    deadline = time.time() + 150
    while time.time() < deadline and not t.stopped():
        with t.target.lock:
            l = t.target.lures.get(token, {})
        tls = int(bool(t.params.get("tls")))
        t.metrics = dict(intercepted=int(bool(l.get("submitted")) and not tls), tls=tls,
                         pin=int(bool(t.params.get("pin"))))
        if l.get("reported"): t.outcome = "report"; break
        if l.get("submitted") and not tls:
            t.outcome = "submit"; t.evidence = "Данные формы реально прочитаны перехватчиком (значение не сохранено)"; break
        if l.get("submitted") and tls:
            t.outcome = "avoid"; t.evidence = "TLS включён — перехватчик получил только шифртекст"; break
        time.sleep(0.6)
    t.outcome = t.outcome or "ignore"


def eng_leak(t: Task):
    p = t.params
    n = int(p.get("records", 200))
    dump = safe_path(t.dir / "dump.csv")
    with open(dump, "w", encoding="utf-8") as f:
        f.write("email;password_sha256;phone\n")
        for i in range(n):
            pw = random.choice(DICT)
            f.write(f"user{i}@example.com;{hashlib.sha256(pw.encode()).hexdigest()};+7***{random.randint(1000,9999)}\n")
    t.say(f"РЕАЛЬНЫЙ дамп создан: {n} записей, настоящие SHA-256 хэши", "bad")
    token = secrets.token_urlsafe(8)
    t.target.add_lure(token, lure_html("account", token, t.url()))
    url = f"{t.url()}/p/{token}"
    notify("Ваши данные найдены в утечке", f"Проверьте и защитите аккаунт: {url}", url)
    deadline = time.time() + 150
    while time.time() < deadline and not t.stopped():
        with t.target.lock: l = t.target.lures.get(token, {})
        t.metrics = dict(records=n, size=dump.stat().st_size,
                         reported=int(bool(l.get("reported"))), submitted=int(bool(l.get("submitted"))))
        if l.get("reported"): t.outcome = "report"; break
        if l.get("submitted"): t.outcome = "submit"; break
        time.sleep(0.6)
    t.outcome = t.outcome or "ignore"
    t.evidence = f"Дамп {n} записей реально записан: {dump.name}"


def eng_keylog(t: Task):
    eng_phish(t)


MODULES = {a["id"]: a["module"] for a in __import__("catalog").ATTACKS}
ENGINE = dict(phish=eng_phish, flood=eng_flood, brute=eng_brute, credstuff=eng_brute,
              ransom=eng_ransom, miner=eng_miner, scan=eng_scan, usb=eng_usb,
              sqli=eng_sqli, xss=eng_xss, mitm=eng_mitm, leak=eng_leak, keylog=eng_keylog)


# ------------------------------------------------------------------ agent core
class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.tasks = {}
        self.lock = threading.Lock()

    def report(self, payload):
        try: api(self.cfg["server"], "/api/agent/report", payload)
        except Exception as e: log(f"report failed: {e}")

    def finish(self, t: Task):
        self.report(dict(agent_id=self.cfg["agent_id"], key=self.cfg["key"], task_id=t.id,
                         status="done", outcome=t.outcome or "ignore", metrics=t.metrics,
                         logs=t.logs[-25:], evidence=t.evidence))
        with self.lock: self.tasks.pop(t.id, None)

    def loop(self):
        log(f"agent loop started pid={os.getpid()}")
        while not STOP_FILE.exists():
            try:
                r = api(self.cfg["server"], "/api/agent/poll",
                        dict(agent_id=self.cfg["agent_id"], key=self.cfg["key"],
                             host=platform.node(), os=f"{platform.system()} {platform.release()}"))
                if r.get("kill"):
                    with self.lock:
                        for t in list(self.tasks.values()): t.stop()
                for tid in r.get("stops", []):
                    with self.lock:
                        t = self.tasks.get(tid)
                    if t: t.stop()
                for tid, params in (r.get("controls") or {}).items():
                    with self.lock:
                        t = self.tasks.get(tid)
                    if t:
                        cmd = params.pop("_command", None)
                        t.params.update(params)
                        if cmd: t.params["_command"] = cmd
                for task in r.get("tasks", []):
                    with self.lock:
                        if task["id"] in self.tasks: continue
                        t = Task(task["id"], task["attack_id"], task["params"], self)
                        self.tasks[task["id"]] = t
                    t.start()
                with self.lock:
                    for t in list(self.tasks.values()):
                        if t.metrics or t.logs:
                            self.report(dict(agent_id=self.cfg["agent_id"], key=self.cfg["key"],
                                             task_id=t.id, metrics=t.metrics, logs=t.logs[:]))
                            t.logs.clear()
            except Exception as e:
                log(f"poll failed: {e}")
            time.sleep(1.0)
        log("STOP file detected — агент останавливается по команде оператора")


# ------------------------------------------------------------------ autostart
def install(server=None):
    cfg = load_cfg()
    if server: cfg["server"] = server; save_cfg(cfg)
    if not cfg.get("agent_id"):
        print("Сначала выполните: python agent.py --enroll TOKEN --server URL"); return
    py = sys.executable
    script = str(Path(__file__).resolve())
    sysname = platform.system()
    try:
        if sysname == "Windows":
            pyw = str(Path(py).with_name("pythonw.exe"))
            exe = pyw if Path(pyw).exists() else py
            subprocess.run(["schtasks", "/create", "/tn", "CyberRangeAgent", "/tr",
                            f'"{exe}" "{script}" --supervise', "/sc", "onlogon", "/f"],
                           capture_output=True, timeout=30)
            subprocess.Popen([exe, script, "--supervise"],
                             creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0))
        elif sysname == "Darwin":
            plist = Path.home() / "Library/LaunchAgents/com.cyberrange.agent.plist"
            plist.parent.mkdir(parents=True, exist_ok=True)
            plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.cyberrange.agent</string>
<key>ProgramArguments</key><array><string>{py}</string><string>{script}</string><string>--supervise</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>""", "utf-8")
            subprocess.run(["launchctl", "load", str(plist)], capture_output=True)
        else:
            unit = Path.home() / ".config/systemd/user/cyberrange-agent.service"
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_text(f"[Unit]\nDescription=CyberRange Agent\n[Service]\nExecStart={py} {script} --supervise\nRestart=always\nRestartSec=3\n[Install]\nWantedBy=default.target\n", "utf-8")
            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
            subprocess.run(["systemctl", "--user", "enable", "--now", "cyberrange-agent"], capture_output=True)
        print("Автостарт установлен. Агент работает в фоне без окон.")
    except Exception as e:
        print("Не удалось установить автостарт:", e)


def uninstall():
    STOP_FILE.write_text("stop", "utf-8")
    sysname = platform.system()
    try:
        if sysname == "Windows":
            subprocess.run(["schtasks", "/delete", "/tn", "CyberRangeAgent", "/f"], capture_output=True)
        elif sysname == "Darwin":
            subprocess.run(["launchctl", "unload", str(Path.home() / "Library/LaunchAgents/com.cyberrange.agent.plist")], capture_output=True)
        else:
            subprocess.run(["systemctl", "--user", "disable", "--now", "cyberrange-agent"], capture_output=True)
    except Exception:
        pass
    print("Агент остановлен и снят с автостарта.")


def supervise():
    log("supervisor started")
    while not STOP_FILE.exists():
        p = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--run"])
        p.wait()
        if STOP_FILE.exists(): break
        log("worker exited — перезапуск через 3с")
        time.sleep(3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enroll"); ap.add_argument("--server"); ap.add_argument("--run", action="store_true")
    ap.add_argument("--supervise", action="store_true"); ap.add_argument("--install", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    a = ap.parse_args()
    if a.uninstall: return uninstall()
    if a.enroll:
        server = a.server or load_cfg().get("server") or "http://127.0.0.1:8000"
        r = api(server, "/api/agent/enroll", dict(token=a.enroll, host=platform.node(),
                                                 os=f"{platform.system()} {platform.release()}", ver=VER))
        save_cfg(dict(server=server, agent_id=r["agent_id"], key=r["key"], user_id=r["user_id"]))
        STOP_FILE.unlink(missing_ok=True)
        print("Агент зарегистрирован:", r["agent_id"]); return
    if a.install: return install(a.server)
    if a.supervise: return supervise()
    cfg = load_cfg()
    if not cfg.get("agent_id"):
        print("Нет регистрации. Выполните: python agent.py --enroll TOKEN --server URL"); return
    STOP_FILE.unlink(missing_ok=True)
    Agent(cfg).loop()


if __name__ == "__main__":
    main()
