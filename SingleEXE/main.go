package main

// WoTB_PC_CN — WOTB 国服登录一体化服务(便携版单文件)
//
// 默认(无参数): 自动补丁检查(游戏存在时) + regions 服务(:80) + WGNI 代理(:443)
// 子命令: check / revert
// 便携性: 全部数据文件基于 exe 所在目录;证书缺失时自动生成(首次运行导出 ca.cer 供模拟器安装)
//
// 常用参数:
//   -tls :443        代理监听地址
//   -http :80        regions 监听地址
//   -ip 1.2.3.4      提示给模拟器 hosts 用的 IP(默认自动探测局域网 IP)
//   -game <路径>     游戏 exe(补丁用;找不到则跳过)

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ---------- 便携路径(全部相对 exe) ----------
var exeDir = func() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}()

var (
	certDir      = filepath.Join(exeDir, "proxy_certs")
	logDir       = filepath.Join(exeDir, "proxy_logs")
	capDir       = filepath.Join(exeDir, "capture")
	tokenDisk    = filepath.Join(capDir, "token_cache.json")
	ovFile       = filepath.Join(capDir, "idtoken_overrides.json")
	sauthFile    = filepath.Join(capDir, "sauth_live.json")
	regionBundle = filepath.Join(exeDir, "regions.yaml")
	regionAppData = filepath.Join(os.Getenv("LOCALAPPDATA"), "wotblitz", "DAVAProject", "region_cache")
	upstreamIP   = "42.186.11.184"
	upstreamHN   = "cn1.plt.ms1shanghai.cn"
	clientID     = "yFgIPcLBlKVLBs6K9mtK3yDnDsLJXqsDNidGESQL"
	tokenMaxAge  = 35000 * time.Second
)

var regionsUpstream = map[string]string{
	"cdn.static.wotb.app":          "34.117.103.161",
	"dl-wotblitz-gc.wargaming.net": "92.223.95.95",
}

func syscallSetUTF8() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("SetConsoleOutputCP").Call(65001)
}

// enableVT 启用控制台 ANSI 转义(Win10+),失败则红色降级为普通文本
func enableVT() bool {
	k := syscall.NewLazyDLL("kernel32.dll")
	h, _, _ := k.NewProc("GetStdHandle").Call(uintptr(0xFFFFFFF5)) // STD_OUTPUT_HANDLE
	var mode uint32
	r, _, _ := k.NewProc("GetConsoleMode").Call(h, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}
	r, _, _ = k.NewProc("SetConsoleMode").Call(h, uintptr(mode|0x0004))
	return r != 0
}

// ---------- 日志 ----------
var logMu sync.Mutex

func logf(format string, a ...interface{}) {
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, a...)
	logMu.Lock()
	fmt.Println(line)
	f, err := os.OpenFile(filepath.Join(logDir, "proxy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		f.WriteString(line + "\n")
		f.Close()
	}
	logMu.Unlock()
}

// ---------- 补丁 ----------
var patchSites = []struct {
	va  uint32
	off int64
}{{0x018A4D39, 0x014A4139}, {0x018AF1D9, 0x014AE5D9}}

var (
	patchOrig    = mustHex("837e1c000f8581000000")
	patchPatched = mustHex("837e1c00909090909090")
)

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &b[i])
	}
	return b
}

func eqAt(data []byte, off int64, pat []byte) bool {
	if off < 0 || off+int64(len(pat)) > int64(len(data)) {
		return false
	}
	for i, v := range pat {
		if data[off+int64(i)] != v {
			return false
		}
	}
	return true
}

func patchExe(gameExe string) {
	if _, err := os.Stat(gameExe); err != nil {
		logf("[patch] 本机未找到游戏 exe,跳过补丁(不影响服务)")
		return
	}
	data, err := os.ReadFile(gameExe)
	if err != nil {
		logf("[patch] 读取 exe 失败: %v", err)
		return
	}
	patched, orig := 0, 0
	for _, s := range patchSites {
		switch {
		case eqAt(data, s.off-4, patchPatched):
			patched++
		case eqAt(data, s.off-4, patchOrig):
			orig++
		}
	}
	if patched == len(patchSites) {
		logf("[patch] 已补丁,跳过")
		return
	}
	if orig < len(patchSites) {
		logf("[patch] 偏移字节不匹配(exe 版本变更?),跳过——不影响注入方案")
		return
	}
	bak := gameExe + ".bak"
	if _, err := os.Stat(bak); err != nil {
		if err := os.WriteFile(bak, data, 0644); err != nil {
			logf("[patch] 备份失败: %v", err)
			return
		}
	}
	for _, s := range patchSites {
		if eqAt(data, s.off-4, patchOrig) {
			copy(data[s.off:s.off+6], []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90})
		}
	}
	if err := os.WriteFile(gameExe, data, 0644); err != nil {
		logf("[patch] 写入失败(游戏在运行?): %v", err)
		return
	}
	logf("[patch] 已应用 NOP 补丁")
}

func doRevert(gameExe string) {
	bak := gameExe + ".bak"
	if _, err := os.Stat(bak); err != nil {
		fmt.Println("[!] 无备份:", bak)
		os.Exit(1)
	}
	b, _ := os.ReadFile(bak)
	if err := os.WriteFile(gameExe, b, 0644); err != nil {
		fmt.Println("[!] 还原失败:", err)
		os.Exit(1)
	}
	fmt.Println("[ok] 已还原")
}

func doCheck(gameExe string) {
	data, err := os.ReadFile(gameExe)
	if err != nil {
		fmt.Println("[!] 读取失败:", err)
		os.Exit(1)
	}
	for _, s := range patchSites {
		switch {
		case eqAt(data, s.off-4, patchPatched):
			fmt.Printf("  VA %#x: 已补丁\n", s.va)
		case eqAt(data, s.off-4, patchOrig):
			fmt.Printf("  VA %#x: 原始字节\n", s.va)
		default:
			fmt.Printf("  VA %#x: 字节不匹配(版本变更?)\n", s.va)
		}
	}
}

// ---------- 证书(缺失时自动生成) ----------
func ensureCerts() error {
	certPath := filepath.Join(certDir, "srv_chain.pem")
	keyPath := filepath.Join(certDir, "srv.key")
	caPath := filepath.Join(certDir, "ca.cer")
	if _, err := os.Stat(certPath); err == nil {
		if _, err2 := os.Stat(keyPath); err2 == nil {
			return nil // 已有证书,沿用
		}
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}
	fmt.Println("[certs] 未找到证书,自动生成自签 CA + 服务器证书...")
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "WOTB-CN Portable CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: upstreamHN},
		DNSNames:     []string{upstreamHN, "cdn.static.wotb.app", "dl-wotblitz-gc.wargaming.net", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	w := func(p string, blk *pem.Block) error {
		return os.WriteFile(p, pem.EncodeToMemory(blk), 0600)
	}
	if err := w(certPath, &pem.Block{Type: "CERTIFICATE", Bytes: srvDER}); err != nil {
		return err
	}
	f, _ := os.OpenFile(certPath, os.O_APPEND|os.O_WRONLY, 0600)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	f.Close()
	if err := w(keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)}); err != nil {
		return err
	}
	if err := w(caPath, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		return err
	}
	fmt.Println("[certs] 已生成:", caPath)
	fmt.Println("[certs] >>> 请将该 ca.cer 安装为模拟器的系统证书(需要 root),一次性操作 <<<")
	return nil
}

// ---------- 令牌缓存 ----------
var (
	tokMu   sync.Mutex
	tokBody []byte
	tokTS   time.Time
	tokInit bool
)

func loadToken() map[string]interface{} {
	tokMu.Lock()
	defer tokMu.Unlock()
	if !tokInit {
		tokInit = true
		if b, err := os.ReadFile(tokenDisk); err == nil {
			tokBody = b
			if st, err2 := os.Stat(tokenDisk); err2 == nil {
				tokTS = st.ModTime()
			}
			logf("[token] loaded from disk")
		}
	}
	if tokBody != nil && time.Since(tokTS) < tokenMaxAge {
		var m map[string]interface{}
		if json.Unmarshal(tokBody, &m) == nil {
			return m
		}
	}
	return nil
}

func saveTokenDisk(payload []byte) {
	tokMu.Lock()
	tokBody = append([]byte(nil), payload...)
	tokTS = time.Now()
	tokMu.Unlock()
	if err := os.WriteFile(tokenDisk, payload, 0644); err != nil {
		logf("[harvest] disk write failed: %v", err)
	}
	logf("[harvest] access_token cached (%d bytes)", len(payload))
}

// ---------- 原始 HTTP ----------
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadBytes('\n')
		line = append(line, chunk...)
		if err != nil || len(chunk) == 0 {
			return line, err
		}
		if len(line) >= 2 && line[len(line)-2] == '\r' {
			return line, nil
		}
	}
}

func readHeaders(r *bufio.Reader) (map[string]string, error) {
	h := map[string]string{}
	for {
		line, err := readLine(r)
		if err != nil {
			return h, err
		}
		s := strings.TrimSpace(string(line))
		if s == "" {
			return h, nil
		}
		k, v, _ := strings.Cut(s, ":")
		h[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
}

func readBody(r *bufio.Reader, h map[string]string) []byte {
	n := 0
	fmt.Sscanf(h["content-length"], "%d", &n)
	if n <= 0 {
		return nil
	}
	buf := make([]byte, n)
	io.ReadFull(r, buf)
	return buf
}

type rawResp struct {
	status  int
	headers map[string]string
	payload []byte
}

func httpRawResp(status int, ctype string, payload []byte) []byte {
	reason := map[int]string{200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
		500: "Internal Server Error", 502: "Bad Gateway"}[status]
	if reason == "" {
		reason = "OK"
	}
	hdr := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, reason, ctype, len(payload))
	return append([]byte(hdr), payload...)
}

func cn1Conn() (net.Conn, error) {
	d := &net.Dialer{Timeout: 20 * time.Second}
	return tls.DialWithDialer(d, "tcp", upstreamIP+":443",
		&tls.Config{ServerName: upstreamHN, InsecureSkipVerify: true})
}

func readFullResp(c net.Conn) (rawResp, error) {
	var resp []byte
	buf := make([]byte, 65536)
	for {
		n, err := c.Read(buf)
		resp = append(resp, buf[:n]...)
		if err != nil {
			break
		}
	}
	head, payload, _ := strings.Cut(string(resp), "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	var st int
	fmt.Sscanf(lines[0], "HTTP/1.1 %d", &st)
	hm := map[string]string{}
	for _, l := range lines[1:] {
		k, v, _ := strings.Cut(l, ":")
		hm[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	pl := []byte(payload)
	if strings.EqualFold(hm["transfer-encoding"], "chunked") {
		pl = dechunk(pl)
	}
	return rawResp{status: st, headers: hm, payload: pl}, nil
}

func dechunk(raw []byte) []byte {
	var out []byte
	for {
		i := strings.Index(string(raw), "\r\n")
		if i < 0 {
			break
		}
		szStr := strings.Split(string(raw[:i]), ";")[0]
		var sz int64
		fmt.Sscanf(szStr, "%x", &sz)
		if sz == 0 {
			break
		}
		start := i + 2
		if start+int(sz) > len(raw) {
			out = append(out, raw[start:]...)
			break
		}
		out = append(out, raw[start:start+int(sz)]...)
		raw = raw[start+int(sz)+2:]
	}
	return out
}

func rawHTTPSRequest(method, path string, body []byte, extra map[string]string, timeout time.Duration) (rawResp, error) {
	c, err := cn1Conn()
	if err != nil {
		return rawResp{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	var req strings.Builder
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, upstreamHN)
	req.WriteString("User-Agent: wotb-cn/11.20.0_china\r\nAccept: */*\r\nCache-Control: no-cache\r\nAccept-Language: zh-Hans\r\nConnection: close\r\n")
	for k, v := range extra {
		req.WriteString(k + ": " + v + "\r\n")
	}
	fmt.Fprintf(&req, "Content-Length: %d\r\n\r\n", len(body))
	c.Write([]byte(req.String()))
	c.Write(body)
	return readFullResp(c)
}

func passthrough(method, path string, h map[string]string, body []byte) []byte {
	c, err := cn1Conn()
	if err != nil {
		logf("ERR: dial %v", err)
		return httpRawResp(502, "text/plain", []byte("proxy dial failed"))
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var req strings.Builder
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, upstreamHN)
	for k, v := range h {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "connection" || lk == "content-length" || lk == "expect" {
			continue
		}
		req.WriteString(k + ": " + v + "\r\n")
	}
	req.WriteString("Connection: close\r\n")
	fmt.Fprintf(&req, "Content-Length: %d\r\n\r\n", len(body))
	c.Write([]byte(req.String()))
	c.Write(body)

	var resp []byte
	buf := make([]byte, 65536)
	for {
		n, err := c.Read(buf)
		resp = append(resp, buf[:n]...)
		if err != nil {
			break
		}
	}
	first := strings.Split(string(resp), "\r\n")[0]
	logf("<< %s", first)
	if i := strings.Index(string(resp), "\r\n\r\n"); i >= 0 {
		payload := resp[i+4:]
		if len(payload) > 0 && payload[0] != '<' && len(payload) < 1001 {
			logf("<< BODY: %s", string(payload))
		}
		// token1-grant 轮询响应是数组 [{...}];引擎的解析器只认对象,
		// 数组会导致 AuthResponse != STATUS_OK(GGM/商店被拦)。解包成对象还给引擎。
		trimmed := strings.TrimSpace(string(payload))
		if method == "GET" && strings.Contains(path, "/credentials/create/oauth/token/") &&
			strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, `"access_token"`) {
			var arr []map[string]interface{}
			if json.Unmarshal([]byte(trimmed), &arr) == nil && len(arr) > 0 {
				if obj, err := json.Marshal(arr[0]); err == nil {
					head := string(resp[:i])
					var sb strings.Builder
					for _, l := range strings.Split(head, "\r\n") {
						lk := strings.ToLower(l)
						if strings.HasPrefix(lk, "content-length:") {
							continue
						}
						sb.WriteString(l + "\r\n")
					}
					fmt.Fprintf(&sb, "Content-Length: %d\r\n\r\n", len(obj))
					resp = append([]byte(sb.String()), obj...)
					payload = obj
					logf("[unwrap] 数组响应已解包为对象(%d bytes)", len(obj))
				}
			}
		}
		if len(payload) > 0 && payload[0] != '<' && len(payload) < 1001 {
			// (二次打印忽略:上方已打印原始体)
		}
		if strings.Contains(path, "/credentials/create/oauth/token/") && method == "GET" &&
			strings.Contains(string(payload), `"access_token"`) {
			saveTokenDisk(payload)
			logf("[harvest] 会话令牌已刷新(真实服务器签发)")
		}
	}
	resp = []byte(strings.ReplaceAll(string(resp), "Connection: keep-alive", "Connection: close"))
	return resp
}

// ---------- 注入 ----------
func nicknameFromToken(tok map[string]interface{}) string {
	idt, _ := tok["id_token"].(string)
	parts := strings.Split(idt, ".")
	if len(parts) < 2 {
		return "wotb"
	}
	p := parts[1]
	if pad := len(p) % 4; pad != 0 {
		p += strings.Repeat("=", 4-pad)
	}
	b, err := base64.URLEncoding.DecodeString(strings.ReplaceAll(p, "-", "+"))
	if err != nil {
		return "wotb"
	}
	var claims map[string]interface{}
	if json.Unmarshal(b, &claims) != nil {
		return "wotb"
	}
	if n, ok := claims["nickname"].(string); ok && n != "" {
		return n
	}
	return "wotb"
}

func handleInject(method, path string, h map[string]string, body []byte) []byte {
	tok := loadToken()
	if tok == nil {
		logf("[inject] 无有效令牌 — 请先在模拟器中登录一次收割")
		return httpRawResp(400, "application/json",
			[]byte(`{"error": "no_cn_session", "error_description": "login on emulator first"}`))
	}
	out := map[string]interface{}{}
	for k, v := range tok {
		out[k] = v
	}
	out["client_id"] = clientID
	if s, ok := out["scope"].(string); ok {
		if ns := strings.ReplaceAll(s, "account.credentials.netease", "account.credentials.steam"); ns != s {
			logf("[inject] scope rewritten: netease -> steam")
			out["scope"] = ns
		}
	}
	if ov, err := os.ReadFile(ovFile); err == nil {
		var overrides map[string]interface{}
		if json.Unmarshal(ov, &overrides) == nil && len(overrides) > 0 {
			logf("[inject] applying id_token overrides: %v", overrides)
			if idt, ok := out["id_token"].(string); ok {
				out["id_token"] = forgeIDToken(idt, overrides)
			}
		}
	}
	payload, _ := json.Marshal(out)
	logf("[inject] token served (account %v)", out["user"])
	return httpRawResp(200, "application/json", payload)
}

func forgeIDToken(idToken string, overrides map[string]interface{}) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return idToken
	}
	p := parts[1]
	if pad := len(p) % 4; pad != 0 {
		p += strings.Repeat("=", 4-pad)
	}
	b, err := base64.URLEncoding.DecodeString(strings.ReplaceAll(p, "-", "+"))
	if err != nil {
		return idToken
	}
	var claims map[string]interface{}
	json.Unmarshal(b, &claims)
	for k, v := range overrides {
		claims[k] = v
	}
	nb, _ := json.Marshal(claims)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(nb) + "." + parts[2]
}

func freshToken1(bearer string) map[string]interface{} {
	r, err := rawHTTPSRequest("POST", "/id/api/v2/account/credentials/create/token1/",
		[]byte("requested_for=wotb"), map[string]string{"Content-Type": "application/x-www-form-urlencoded",
			"Authorization": "Bearer " + bearer}, 25*time.Second)
	if err != nil {
		logf("[reg] token1 err: %v", err)
		return nil
	}
	logf("[reg] token1 POST -> %d", r.status)
	if r.status == 202 && r.headers["location"] != "" {
		loc := r.headers["location"]
		if i := strings.Index(loc, upstreamHN); i >= 0 {
			loc = loc[i+len(upstreamHN):]
		}
		if !strings.HasPrefix(loc, "/") {
			loc = "/"
		}
		for i := 0; i < 15; i++ {
			r2, err := rawHTTPSRequest("GET", loc, nil, nil, 20*time.Second)
			if err != nil {
				return nil
			}
			logf("[reg] poll -> %d", r2.status)
			if r2.status == 200 {
				var m map[string]interface{}
				if json.Unmarshal(r2.payload, &m) == nil {
					return m
				}
				return nil
			}
			if r2.status != 202 {
				return nil
			}
			time.Sleep(1500 * time.Millisecond)
		}
	}
	return nil
}

func handleRegistration(method, path string, h map[string]string, body []byte) []byte {
	tok := loadToken()
	if tok == nil {
		return httpRawResp(400, "application/json", []byte(`{"error": "no_cn_session"}`))
	}
	nick := nicknameFromToken(tok)
	at, _ := tok["access_token"].(string)
	creds := freshToken1(at)
	if creds == nil {
		logf("[reg] token1 fetch failed")
		return httpRawResp(500, "application/json", []byte(`{"error": "token1_failed"}`))
	}
	aid, _ := creds["account_id"].(float64)
	tk, _ := creds["token"].(string)
	resp, _ := json.Marshal(map[string]interface{}{
		"account_id": int(aid), "token": tk, "name": nick, "nickname": nick,
		"game_realm": "sg", "realm": "sg",
	})
	logf("[reg] credentials served: %s", resp)
	return httpRawResp(200, "application/json", resp)
}

func handleCredentials(method, path string, h map[string]string, body []byte) []byte {
	nick := "WoTB_PC_CN"
	if tok := loadToken(); tok != nil {
		nick = nicknameFromToken(tok)
	}
	resp, _ := json.Marshal(map[string]string{"state": "complete", "login": nick})
	logf("[creds] fake credentials-state served: %s", resp)
	return httpRawResp(200, "application/json", resp)
}

func captureSauth(body []byte) {
	i := strings.Index(string(body), "sauth_json=")
	if i < 0 {
		return
	}
	rest := string(body)[i+len("sauth_json="):]
	if j := strings.Index(rest, "&"); j >= 0 {
		rest = rest[:j]
	}
	sj, err := urlUnescape(rest)
	if err != nil {
		return
	}
	var m map[string]interface{}
	if json.Unmarshal([]byte(sj), &m) != nil {
		return
	}
	logf("[capture] fresh sauth: sessionid=%v", m["sessionid"])
	os.WriteFile(sauthFile, []byte(sj), 0644)
}

func urlUnescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var v int
			fmt.Sscanf(s[i+1:i+3], "%02x", &v)
			b.WriteByte(byte(v))
			i += 2
		} else if s[i] == '+' {
			b.WriteByte(' ')
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String(), nil
}

// stripScope 删除表单里的 scope 参数:PC 引擎请求的是国际服 scope 集合,
// CN1 会回 invalid_scope;不带 scope 时 CN1 按默认集签发(实测 202 通过)。
func stripScope(body []byte) []byte {
	parts := strings.Split(string(body), "&")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.HasPrefix(p, "scope=") {
			continue
		}
		out = append(out, p)
	}
	return []byte(strings.Join(out, "&"))
}

// ---------- :443 ----------
var tlsSrvConf *tls.Config

func handle443(conn net.Conn) {
	defer conn.Close()
	tlsConn := tls.Server(conn, tlsSrvConf)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	r := bufio.NewReader(tlsConn)
	line, err := readLine(r)
	if err != nil || len(line) < 10 {
		return
	}
	parts := strings.Fields(string(line))
	if len(parts) < 2 {
		return
	}
	method, path := parts[0], parts[1]
	h, err := readHeaders(r)
	if err != nil {
		return
	}
	body := readBody(r, h)
	logf(">> %s %s", method, path)
	if len(body) > 0 && len(body) < 1500 {
		logf(">> BODY: %s", string(body))
	}
	grant := ""
	if strings.Contains(string(body), "grant_type=") {
		for _, kv := range strings.Split(string(body), "&") {
			if strings.HasPrefix(kv, "grant_type=") {
				grant, _ = urlUnescape(strings.TrimPrefix(kv, "grant_type="))
			}
		}
	}
	var resp []byte
	switch {
	case strings.HasPrefix(path, "/id/api/") && strings.Contains(path, "credentials/create/oauth/token/") && method == "POST":
		switch {
		case strings.Contains(grant, "external-steam"):
			// CN1 不支持 Steam grant,必须注入
			resp = handleInject(method, path, h, body)
		case strings.Contains(grant, "external-netease"):
			captureSauth(body)
			resp = passthrough(method, path, h, stripScope(body))
		default:
			// token1/basic 等自带真实凭证 → 透传(剥掉国际服 scope,CN1 会拒)
			logf("[passthrough] grant=%s → 真实 CN1(原生会话,scope 已剥离)", grant)
			resp = passthrough(method, path, h, stripScope(body))
		}
	case strings.HasPrefix(path, "/registration/api/v3/account/external/") && method == "POST":
		resp = handleRegistration(method, path, h, body)
	case strings.HasPrefix(path, "/personal/api/v3/account/credentials/"):
		resp = handleCredentials(method, path, h, body)
	default:
		resp = passthrough(method, path, h, body)
	}
	tlsConn.Write(resp)
}

// ---------- :80 ----------
var regionYAML []byte

func loadRegionYAML() {
	appDataNewest := ""
	var appDataT time.Time
	if entries, err := os.ReadDir(regionAppData); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, "regions_") || !strings.HasSuffix(name, ".yaml") {
				continue
			}
			if info, err := e.Info(); err == nil && info.ModTime().After(appDataT) {
				appDataNewest, appDataT = name, info.ModTime()
			}
		}
	}
	if appDataNewest != "" {
		if b, err := os.ReadFile(filepath.Join(regionAppData, appDataNewest)); err == nil {
			regionYAML = b
			needCopy := false
			if _, err := os.Stat(regionBundle); err != nil {
				needCopy = true
			} else if st, err2 := os.Stat(regionBundle); err2 == nil && st.ModTime().Before(appDataT) {
				needCopy = true
			}
			if needCopy {
				os.WriteFile(regionBundle, b, 0644)
				logf("[regions] 便携包 regions.yaml 已更新")
			}
			logf("[regions] 已加载 AppData/%s (%d bytes)", appDataNewest, len(b))
			return
		}
	}
	if b, err := os.ReadFile(regionBundle); err == nil {
		regionYAML = b
		logf("[regions] 已加载便携包 regions.yaml (%d bytes)", len(b))
		return
	}
	logf("[regions] 未找到任何 regions yaml(:80 仅转发 CDN)")
}

func handle80(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	line, err := readLine(r)
	if err != nil || len(line) < 10 {
		return
	}
	parts := strings.Fields(string(line))
	if len(parts) < 2 {
		return
	}
	method, path := parts[0], parts[1]
	h, err := readHeaders(r)
	if err != nil {
		return
	}
	readBody(r, h)

	if method == "POST" {
		conn.Write(httpRawResp(405, "text/plain", []byte("method not allowed")))
		return
	}
	if strings.HasPrefix(path, "/conf/regions_") && regionYAML != nil {
		conn.Write(httpRawResp(200, "text/yaml", regionYAML))
		return
	}
	host := strings.ToLower(strings.Split(h["host"], ":")[0])
	real, ok := regionsUpstream[host]
	if !ok {
		conn.Write(httpRawResp(404, "text/plain", []byte("not found")))
		return
	}
	ua := h["user-agent"]
	if ua == "" {
		ua = "wotb"
	}
	c, err := net.DialTimeout("tcp", real+":80", 30*time.Second)
	if err != nil {
		conn.Write(httpRawResp(502, "text/plain", []byte(err.Error())))
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", path, host, ua)
	var resp []byte
	buf := make([]byte, 65536)
	for {
		n, err := c.Read(buf)
		resp = append(resp, buf[:n]...)
		if err != nil {
			break
		}
	}
	conn.Write(resp)
}

// ---------- main ----------
func lanIP() string {
	addrs, _ := net.InterfaceAddrs()
	best := ""
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		ip := ipnet.IP.String()
		if strings.HasPrefix(ip, "169.254.") {
			continue // 链路本地
		}
		if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
			return ip // 内网段最优
		}
		if best == "" {
			best = ip
		}
	}
	if best != "" {
		return best
	}
	return "127.0.0.1"
}

func normAddr(a string) string {
	if !strings.Contains(a, ":") {
		return ":" + a
	}
	return a
}

func main() {
	syscallSetUTF8()
	tlsAddr := flag.String("tls", ":443", "代理监听地址")
	httpAddr := flag.String("http", ":80", "regions 监听地址")
	ipHint := flag.String("ip", "", "提示给模拟器 hosts 的 IP(默认自动探测)")
	gameExe := flag.String("game", filepath.Join(exeDir, "..", "World of Tanks Blitz", "wotblitz.exe"), "游戏 exe 路径")
	flag.Parse()
	args := flag.Args()
	switch {
	case len(args) > 0 && args[0] == "revert":
		doRevert(*gameExe)
		return
	case len(args) > 0 && args[0] == "check":
		doCheck(*gameExe)
		return
	}

	os.MkdirAll(logDir, 0755)
	os.MkdirAll(capDir, 0755)
	logf("===== WoTB PC 国服登录 =====")

	// 红色免责警告(仅控制台,不写日志文件)
	red := func(s string) string {
		if enableVT() {
			return "\x1b[91m" + s + "\x1b[0m"
		}
		return s
	}
	fmt.Println(red("" +
		"======================================================================\n" +
		"  ⚠  警告 WARNING\n" +
		"  使用本软件通过 Steam 客户端登录国服账号，可能导致网易的封禁，\n" +
		"  后果自行承担！\n" +
		"  Legal notice: this tool may violate the game's EULA. Use at your own risk.\n" +
		"======================================================================"))

	patchExe(*gameExe)
	loadRegionYAML()

	if err := ensureCerts(); err != nil {
		logf("[!] 证书生成失败: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "srv_chain.pem"), filepath.Join(certDir, "srv.key"))
	if err != nil {
		logf("[!] 加载证书失败: %v", err)
	} else {
		tlsSrvConf = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	hint := *ipHint
	if hint == "" {
		hint = lanIP()
	}
	fmt.Println("---------------- 模拟器收割配置(单次,需root) ----------------")
	fmt.Printf("  1) 模拟器 hosts:   %s cn1.plt.ms1shanghai.cn\n", hint)
	fmt.Printf("  2) 安装系统证书:          %s\n", filepath.Join(certDir, "ca.cer"))
	fmt.Println("  3) 在模拟器里登录一次游戏,日志出现 [harvest] 即收割成功")
	fmt.Println("-------------------------------------------------------------")

	errs := make(chan error, 2)
	go func() {
		ln, err := net.Listen("tcp", normAddr(*httpAddr))
		if err != nil {
			errs <- errors.New(*httpAddr + " listen: " + err.Error())
			return
		}
		logf("regions http server on %s", *httpAddr)
		for {
			c, err := ln.Accept()
			if err != nil {
				continue
			}
			go handle80(c)
		}
	}()
	go func() {
		if tlsSrvConf == nil {
			errs <- errors.New(":443 无证书,未启动")
			return
		}
		ln, err := net.Listen("tcp", normAddr(*tlsAddr))
		if err != nil {
			errs <- errors.New(*tlsAddr + " listen: " + err.Error())
			return
		}
		logf("wgni proxy on %s (inject+passthrough)", *tlsAddr)
		for {
			c, err := ln.Accept()
			if err != nil {
				continue
			}
			go handle443(c)
		}
	}()

	logf("[ok] 服务已启动。Steam 启动游戏 → 点「立即畅玩」，或自动登录。Ctrl+C 退出。")
	err = <-errs
	logf("[!] %v", err)
}
