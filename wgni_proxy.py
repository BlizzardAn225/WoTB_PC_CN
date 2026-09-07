#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
wgni_proxy — WOTB 国服登录 WGNI 代理(:443)
=============================================
免责声明 / Disclaimer: 仅供个人学习与研究使用。使用本项目即表示你理解并接受:
连接第三方游戏服务器可能违反其服务条款,由此产生的账号风险与法律责任自负。
For personal study/research only. Connecting to third-party game servers in
unintended ways may violate their Terms of Service; use at your own risk.

工作方式(详见分析报告):
  - hosts 需已把 cn1.plt.ms1shanghai.cn 指向本机
  - external-steam oauth → 注入 capture/token_cache.json 中的真实国服令牌(scope 改写)
  - token1/basic oauth   → 透传真实 CN1(剥离国际服 scope),原生会话
  - 注册端点             → 用真实 token1 凭证伪造注册成功
  - 其余请求             → 透传
用法:
  python wgni_proxy.py [inject|passthrough]
路径:
  全部基于脚本所在目录(capture\、proxy_certs\、proxy_logs\),可整目录搬运。
"""
import socket, ssl, threading, sys, time, os
import json as _json
import urllib.request, urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(SCRIPT_DIR, "proxy_certs", "srv_chain.pem")
KEY = os.path.join(SCRIPT_DIR, "proxy_certs", "srv.key")
LOGDIR = os.path.join(SCRIPT_DIR, "proxy_logs")
TOKEN_DISK = os.path.join(SCRIPT_DIR, "capture", "token_cache.json")
OVERRIDES_FILE = os.path.join(SCRIPT_DIR, "capture", "idtoken_overrides.json")
SAUTH_PATH = os.path.join(SCRIPT_DIR, "capture", "sauth_live.json")
UPSTREAM_IP = os.environ.get("WOTB_CN1_IP", "42.186.11.184")   # cn1 真实 IP,可环境变量覆盖
UPSTREAM_HOST = "cn1.plt.ms1shanghai.cn"
CLIENT_ID = "yFgIPcLBlKVLBs6K9mtK3yDnDsLJXqsDNidGESQL"          # 游戏内置 regions clientId
MODE = sys.argv[1] if len(sys.argv) > 1 else "inject"
os.makedirs(LOGDIR, exist_ok=True)
os.makedirs(os.path.dirname(TOKEN_DISK), exist_ok=True)
lock = threading.Lock()
TOKEN_CACHE = {"body": None, "ts": 0.0}
INJECT_LOCK = threading.Lock()
CRLF = "\r\n"

def log(*a):
    with lock:
        line = "[%s] %s" % (time.strftime("%H:%M:%S"), " ".join(str(x) for x in a))
        print(line, flush=True)
        with open(os.path.join(LOGDIR, "proxy.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")

ctx_in = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx_in.load_cert_chain(CERT, KEY)
ctx_out = ssl.create_default_context()
ctx_out.check_hostname = False
ctx_out.verify_mode = ssl.CERT_NONE

def read_line(sock):
    buf = b""
    while not buf.endswith(b"\r\n"):
        c = sock.recv(1)
        if not c:
            return None
        buf += c
    return buf

def read_headers(sock):
    headers = {}
    while True:
        line = read_line(sock)
        if line is None or line == b"\r\n":
            break
        k, _, v = line.decode("latin1").partition(":")
        headers[k.strip().lower()] = v.strip()
    return headers

def read_body(sock, headers):
    n = int(headers.get("content-length", "0") or 0)
    body = b""
    while len(body) < n:
        c = sock.recv(n - len(body))
        if not c:
            break
        body += c
    return body

def http_response(status, ctype, payload):
    reason = {200: "OK", 400: "Bad Request", 500: "Internal Server Error"}.get(status, "OK")
    hdr = ("HTTP/1.1 %d %s" + CRLF + "Content-Type: %s" + CRLF +
           "Content-Length: %d" + CRLF + "Connection: close" + CRLF + CRLF) % (
        status, reason, ctype, len(payload))
    return hdr.encode("latin1") + payload

def raw_https_request(method, host_header, path, body=None, headers_extra=None, resp_timeout=25):
    """向真实 CN1 发 HTTP(SNI 正确,绕过 hosts)"""
    sock = ctx_out.wrap_socket(socket.create_connection((UPSTREAM_IP, 443), timeout=resp_timeout),
                               server_hostname=UPSTREAM_HOST)
    try:
        hdrs = {"Host": UPSTREAM_HOST, "User-Agent": "wotb-cn/11.20.0_china", "Accept": "*/*",
                "Cache-Control": "no-cache", "Accept-Language": "zh-Hans", "Connection": "close"}
        if headers_extra:
            hdrs.update(headers_extra)
        req = "%s %s HTTP/1.1\r\n" % (method, path)
        for k, v in hdrs.items():
            req += "%s: %s\r\n" % (k, v)
        data = body.encode() if isinstance(body, str) else (body or b"")
        req += "Content-Length: %d\r\n\r\n" % len(data)
        sock.sendall(req.encode("latin1") + data)
        resp = b""
        while True:
            c = sock.recv(65536)
            if not c:
                break
            resp += c
        head, _, payload = resp.partition(b"\r\n\r\n")
        status = int(head.split(b"\r\n")[0].split()[1])
        hmap = {}
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.decode("latin1").partition(":")
            hmap[k.strip().lower()] = v.strip()
        if hmap.get("transfer-encoding", "").lower() == "chunked":
            raw, out = payload, b""
            while True:
                i = raw.find(b"\r\n")
                if i < 0:
                    break
                sz = int(raw[:i].split(b";")[0], 16)
                if sz == 0:
                    break
                out += raw[i + 2:i + 2 + sz]
                raw = raw[i + 2 + sz + 2:]
            payload = out
        return status, hmap, payload
    finally:
        sock.close()

def passthrough(method, path, headers, body):
    out = ctx_out.wrap_socket(socket.create_connection((UPSTREAM_IP, 443), timeout=20), server_hostname=UPSTREAM_HOST)
    try:
        req = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, UPSTREAM_HOST)
        for k, v in headers.items():
            if k in ("host", "connection", "content-length", "expect"):
                continue
            req += "%s: %s\r\n" % (k, v)
        req += "Connection: close\r\nContent-Length: %d\r\n\r\n" % len(body)
        out.sendall(req.encode("latin1") + body)
        resp = b""
        while True:
            c = out.recv(65536)
            if not c:
                break
            resp += c
        first = resp.split(b"\r\n")[0].decode("latin1", "replace")
        log("<<", first)
        if b"\r\n\r\n" in resp:
            payload = resp.split(b"\r\n\r\n", 1)[1]
            if payload and not payload.startswith(b"<"):
                log("<< BODY:", payload[:1000].decode("utf-8", "replace"))
            # 收割:轮询 GET 响应含真实令牌(对象或数组形式均支持)
            if "/credentials/create/oauth/token/" in path and method == "GET":
                pl = payload.strip()
                if pl.startswith(b'{"access_token"'):
                    _cache_token(pl)
                elif pl.startswith(b'[{"access_token"'):
                    try:
                        arr = _json.loads(pl)
                        if arr:
                            _cache_token(_json.dumps(arr[0]).encode())
                    except Exception as e:
                        log("[harvest] unwrap failed:", e)
        resp = resp.replace(b"Connection: keep-alive", b"Connection: close")
        return resp
    finally:
        out.close()

def _cache_token(payload):
    TOKEN_CACHE["body"] = payload
    TOKEN_CACHE["ts"] = time.time()
    try:
        open(TOKEN_DISK, "wb").write(payload)
    except Exception as e:
        log("[harvest] disk write failed:", e)
    log("[harvest] access_token cached (%d bytes)" % len(payload))

def load_token():
    with INJECT_LOCK:
        if TOKEN_CACHE["body"] is None and os.path.exists(TOKEN_DISK):
            try:
                TOKEN_CACHE["body"] = open(TOKEN_DISK, "rb").read()
                TOKEN_CACHE["ts"] = os.path.getmtime(TOKEN_DISK)
                log("[token] loaded from disk")
            except Exception as e:
                log("[token] disk load failed:", e)
        if TOKEN_CACHE["body"] and time.time() - TOKEN_CACHE["ts"] < 35000:
            return _json.loads(TOKEN_CACHE["body"])
        return None

def forge_id_token(id_token, overrides):
    """按 overrides 重签 id_token payload(仅改 claims,签名不变)"""
    import base64 as b64
    h, p, s = id_token.split(".")
    claims = _json.loads(b64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    claims.update(overrides)
    np = b64.urlsafe_b64encode(_json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
    return h + "." + np + "." + s

def handle_inject(method, path, headers, body):
    tok = load_token()
    if tok is None:
        log("[inject] no valid token available")
        err = b'{"error": "no_cn_session", "error_description": "login on emulator first"}'
        return http_response(400, "application/json", err)
    out = dict(tok)
    out["client_id"] = CLIENT_ID
    # scope 改写:PC 引擎按 scope 判断凭证身份体系( netease→steam )
    if isinstance(out.get("scope"), str):
        new_scope = out["scope"].replace("account.credentials.netease", "account.credentials.steam")
        if new_scope != out["scope"]:
            log("[inject] scope rewritten: netease -> steam")
        out["scope"] = new_scope
    overrides = {}
    if os.path.exists(OVERRIDES_FILE):
        try:
            overrides = _json.load(open(OVERRIDES_FILE))
            if overrides:
                log("[inject] applying id_token overrides:", overrides)
        except Exception as e:
            log("[inject] override file bad:", e)
    if overrides and "id_token" in out:
        try:
            out["id_token"] = forge_id_token(out["id_token"], overrides)
        except Exception as e:
            log("[inject] forge failed:", e)
    payload = _json.dumps(out, separators=(",", ":")).encode()
    log("[inject] token served (account %s)" % out.get("user"))
    return http_response(200, "application/json", payload)

def fresh_token1(bearer):
    st, hm, _ = raw_https_request("POST", UPSTREAM_HOST,
        "/id/api/v2/account/credentials/create/token1/",
        urllib.parse.urlencode({"requested_for": "wotb"}),
        headers_extra={"Content-Type": "application/x-www-form-urlencoded",
                       "Authorization": "Bearer " + bearer})
    log("[reg] token1 POST ->", st)
    if st == 202 and hm.get("location"):
        loc = hm["location"].split(UPSTREAM_HOST, 1)[-1] or "/"
        for _ in range(15):
            st2, _, payload = raw_https_request("GET", UPSTREAM_HOST, loc)
            log("[reg] poll ->", st2)
            if st2 == 200:
                return _json.loads(payload)
            if st2 != 202:
                return None
            time.sleep(1.5)
    return None

def handle_registration(method, path, headers, body):
    """Steam 注册 → 伪造成功(真实 token1 凭证)。
       解析器期望 HTTP 200 JSON {account_id:int, token:str, name:str}"""
    tok = load_token()
    if tok is None:
        return http_response(400, "application/json", b'{"error": "no_cn_session"}')
    nick = "wotb"
    try:
        pl = tok["id_token"].split(".")[1]
        claims = _json.loads(__import__("base64").urlsafe_b64decode(pl + "=" * (-len(pl) % 4)))
        nick = claims.get("nickname", "wotb")
    except Exception as e:
        log("[reg] nickname parse:", e)
    creds = fresh_token1(tok["access_token"])
    if not creds:
        log("[reg] token1 fetch failed")
        return http_response(500, "application/json", b'{"error": "token1_failed"}')
    resp = _json.dumps({"account_id": int(creds["account_id"]),
                        "token": str(creds["token"]),
                        "name": nick,
                        "nickname": nick,
                        "game_realm": "sg",
                        "realm": "sg"}, separators=(",", ":")).encode()
    log("[reg] credentials served:", resp.decode())
    return http_response(200, "application/json", resp)

def handle_credentials(method, path, headers, body):
    """凭证状态查询 → 伪造 complete(防御性端点)"""
    nick = "wotb_cn"
    tok = load_token()
    if tok:
        try:
            pl = tok["id_token"].split(".")[1]
            claims = _json.loads(__import__("base64").urlsafe_b64decode(pl + "=" * (-len(pl) % 4)))
            nick = claims.get("nickname", nick)
        except Exception:
            pass
    resp = _json.dumps({"state": "complete", "login": nick}, separators=(",", ":")).encode()
    log("[creds] fake credentials-state served:", resp.decode())
    return http_response(200, "application/json", resp)

def capture_sauth(body):
    params = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
    sj = params.get("sauth_json", [None])[0]
    if not sj:
        return
    try:
        j = _json.loads(sj)
        cur = None
        if os.path.exists(SAUTH_PATH):
            cur = _json.load(open(SAUTH_PATH))
        if not cur or cur.get("sessionid") != j.get("sessionid"):
            _json.dump(j, open(SAUTH_PATH, "w"), indent=2)
            log("[capture] fresh sauth saved: sessionid=%s" % j.get("sessionid"))
    except Exception as e:
        log("[capture] err:", repr(e))

def handle(conn):
    try:
        conn = ctx_in.wrap_socket(conn, server_side=True)
        while True:
            line = read_line(conn)
            if not line:
                break
            method, path, _ver = line.decode("latin1").split(" ", 2)
            headers = read_headers(conn)
            body = read_body(conn, headers)
            log(">>", method, path)
            if body and len(body) < 1500:
                log(">> BODY:", body.decode("utf-8", "replace"))
            grant = ""
            if "grant_type=" in body.decode("latin1"):
                grant = urllib.parse.parse_qs(body.decode("utf-8", "replace")).get("grant_type", [""])[0]
            if path.startswith("/id/api/") and "credentials/create/oauth/token/" in path and method == "POST":
                if "external-netease" in grant:
                    capture_sauth(body)
                    resp = passthrough(method, path, headers, body)
                elif "external-steam" in grant:
                    resp = handle_inject(method, path, headers, body) if MODE == "inject" \
                        else passthrough(method, path, headers, body)
                else:
                    # token1/basic 等自带真实凭证 → 剥离国际服 scope 后透传(CN1 对其 scope 集合回 invalid_scope)
                    log("[passthrough] grant=%s → 真实 CN1" % grant.split(":")[-1] if grant else "[passthrough]")
                    stripped = "&".join(p for p in body.decode("latin1").split("&")
                                        if not p.startswith("scope=")).encode("latin1")
                    resp = passthrough(method, path, headers, stripped)
            elif path.startswith("/registration/api/v3/account/external/") and method == "POST":
                resp = handle_registration(method, path, headers, body)
            elif path.startswith("/personal/api/v3/account/credentials/") and MODE == "inject":
                resp = handle_credentials(method, path, headers, body)
            else:
                resp = passthrough(method, path, headers, body)
            conn.sendall(resp)
            break
    except Exception as e:
        log("ERR:", repr(e))
    finally:
        try:
            conn.close()
        except:
            pass

if __name__ == "__main__":
    log("proxy mode =", MODE)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 443))
    srv.listen(16)
    while True:
        c, addr = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
