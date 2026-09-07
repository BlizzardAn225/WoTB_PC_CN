#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
regions_http_server — WOTB regions 配置服务器(:80)
====================================================
免责声明 / Disclaimer: 仅供个人学习与研究使用,使用风险自负。
For personal study/research only. Use at your own risk.

工作方式:
  - hosts 需已把 cdn.static.wotb.app / dl-wotblitz-gc.wargaming.net 指向本机
  - GET /conf/regions_<版本>.yaml → 返回 regions yaml(优先 AppData 缓存里最新版,
    否则脚本旁的 regions.yaml 便携包)
  - 其余 GET 按 Host 转发真实 CDN(纯 HTTP)
用法:
  python regions_http_server.py [端口]     默认 :80
路径:
  全部自适应;regions.yaml 便携包不存在时会从本机游戏缓存自动生成。
"""
import http.server, socketserver, urllib.request, sys, os, glob

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REGION_BUNDLE = os.path.join(SCRIPT_DIR, "regions.yaml")
REGION_APPDATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                  "wotblitz", "DAVAProject", "region_cache")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
# 真实 CDN IP(公开 DNS 可查);按 Host 头区分转发目标
UPSTREAM = {
    "cdn.static.wotb.app": "34.117.103.161",
    "dl-wotblitz-gc.wargaming.net": "92.223.95.95",
}

def find_yaml():
    """优先 AppData 缓存最新版(跟随游戏版本);否则脚本旁 regions.yaml 便携包"""
    best = None
    best_t = 0
    for p in glob.glob(os.path.join(REGION_APPDATA_DIR, "regions_*.yaml")):
        t = os.path.getmtime(p)
        if t > best_t:
            best, best_t = p, t
    if best:
        # 同步便携包(便携部署用)
        try:
            if (not os.path.exists(REGION_BUNDLE)) or os.path.getmtime(REGION_BUNDLE) < best_t:
                open(REGION_BUNDLE, "wb").write(open(best, "rb").read())
                sys.stderr.write("[regions] 便携包 regions.yaml 已更新\n")
        except Exception as e:
            sys.stderr.write("[regions] 便携包同步失败: %s\n" % e)
        return open(best, "rb").read()
    if os.path.exists(REGION_BUNDLE):
        return open(REGION_BUNDLE, "rb").read()
    return None

LOCAL_YAML = find_yaml()
if LOCAL_YAML:
    sys.stderr.write("[regions] 已加载 regions yaml (%d bytes)\n" % len(LOCAL_YAML))
else:
    sys.stderr.write("[regions] 未找到 regions yaml,/conf/regions_* 将返回 404\n")

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        if self.path.startswith("/conf/regions_"):
            yaml = find_yaml() or LOCAL_YAML
            if not yaml:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml")
            self.send_header("Content-Length", str(len(yaml)))
            self.end_headers()
            self.wfile.write(yaml)
            return
        real = UPSTREAM.get(host)
        if not real:
            self.send_error(404)
            return
        url = "http://%s%s" % (real, self.path)
        req = urllib.request.Request(url, headers={"Host": host, "User-Agent": self.headers.get("User-Agent", "wotb")})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read()
                self.send_response(r.status)
                for k, v in r.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            self.send_error(502, str(e))

    do_HEAD = do_GET
    def do_POST(self):
        self.send_error(405)

class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    sys.stderr.write("regions http server on :%d\n" % PORT)
    TS(("0.0.0.0", PORT), Handler).serve_forever()
