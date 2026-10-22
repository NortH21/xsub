package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Node — один узел подписки, уже переведённый в outbound Xray.
type Node struct {
	Tag      string         `json:"tag"`
	Name     string         `json:"name"`
	Sub      string         `json:"sub"`
	Proto    string         `json:"proto"`
	Address  string         `json:"address"`
	Port     int            `json:"port"`
	Outbound map[string]any `json:"-"`
}

// fetchURL качает ссылку: сначала напрямую, при неудаче — через VPN (локальный probe-вход Xray).
func fetchURL(c *Config, u, ua string, limit int64) ([]byte, http.Header, error) {
	try := func(proxyPort int) ([]byte, http.Header, error) {
		tr := &http.Transport{DisableKeepAlives: true}
		if proxyPort > 0 {
			tr.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", proxyPort)})
		}
		cl := &http.Client{Transport: tr, Timeout: 90 * time.Second}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, nil, err
		}
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		resp, err := cl.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		return b, resp.Header, err
	}
	b, h, err := try(0)
	if err == nil {
		return b, h, nil
	}
	b, h, err2 := try(c.Xray.ProbePort)
	if err2 == nil {
		return b, h, nil
	}
	return nil, nil, fmt.Errorf("напрямую: %v; через VPN: %v", cleanErr(err), cleanErr(err2))
}

// cleanErr убирает из ошибки адрес подписки (в нём часто секретный токен).
func cleanErr(err error) string {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err.Error()
	}
	return err.Error()
}

// UserInfo — заголовок subscription-userinfo: трафик и срок действия.
type UserInfo struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

func parseUserInfo(h http.Header) *UserInfo {
	v := h.Get("Subscription-Userinfo")
	if v == "" {
		return nil
	}
	ui := &UserInfo{}
	for _, part := range strings.Split(v, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		switch strings.ToLower(kv[0]) {
		case "upload":
			ui.Upload = n
		case "download":
			ui.Download = n
		case "total":
			ui.Total = n
		case "expire":
			ui.Expire = n
		}
	}
	return ui
}

// decodeSubscription: base64 (любой вариант) или сразу текст со ссылками.
func decodeSubscription(b []byte) string {
	s := strings.TrimSpace(string(b))
	if strings.Contains(s, "://") {
		return s
	}
	if d, ok := decodeB64(s); ok {
		return d
	}
	return s
}

func decodeB64(s string) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if d, err := enc.DecodeString(clean); err == nil {
			return string(d), true
		}
	}
	return "", false
}

type parseOpts struct {
	sub      string
	exclude  *regexp.Regexp
	include  *regexp.Regexp
	sockopt  any
	maxNodes int
}

// parseSubscription разбирает текст подписки; возвращает узлы и список предупреждений.
func parseSubscription(text string, o parseOpts) ([]Node, []string) {
	var nodes []Node
	var warns []string
	seen := map[string]bool{}
	skippedInfo := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		n, err := parseLink(line, o.sockopt)
		if err == errInfoNode {
			skippedInfo++
			continue
		}
		if err != nil {
			warns = append(warns, fmt.Sprintf("пропущен узел (%v): %s", err, short(line)))
			continue
		}
		if o.exclude != nil && o.exclude.MatchString(n.Name) {
			continue
		}
		if o.include != nil && !o.include.MatchString(n.Name) {
			continue
		}
		if seen[n.Tag] {
			continue
		}
		seen[n.Tag] = true
		n.Sub = o.sub
		nodes = append(nodes, n)
		if o.maxNodes > 0 && len(nodes) >= o.maxNodes {
			warns = append(warns, fmt.Sprintf("взяты первые %d узлов", o.maxNodes))
			break
		}
	}
	if skippedInfo > 0 {
		warns = append(warns, fmt.Sprintf("пропущено информационных записей (не серверов): %d", skippedInfo))
	}
	return nodes, warns
}

var errInfoNode = fmt.Errorf("информационная запись")

func short(s string) string {
	if i := strings.Index(s, "://"); i > 0 {
		if j := strings.LastIndex(s, "@"); j > i {
			s = s[:i+3] + "…" + s[j:]
		} else if len(s) > i+3+8 {
			s = s[:i+3+8] + "…"
		}
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

func isInfoAddress(host string, port int) bool {
	if port <= 1 || host == "" || host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsUnspecified() || ip.IsLoopback()
	}
	return false
}

func nodeTag(link string) string {
	if i := strings.Index(link, "#"); i >= 0 {
		link = link[:i]
	}
	h := sha1.Sum([]byte(link))
	return "node-" + hex.EncodeToString(h[:])[:8]
}

func parseLink(link string, sockopt any) (Node, error) {
	scheme := strings.ToLower(link[:max(0, strings.Index(link, "://"))])
	switch scheme {
	case "vless":
		return parseVless(link, sockopt)
	case "trojan":
		return parseTrojan(link, sockopt)
	case "ss":
		return parseSS(link, sockopt)
	case "vmess":
		return parseVmess(link, sockopt)
	case "":
		return Node{}, fmt.Errorf("не ссылка")
	default:
		return Node{}, fmt.Errorf("протокол %s не поддерживается", scheme)
	}
}

func hostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if isInfoAddress(host, port) {
		return "", 0, errInfoNode
	}
	return host, port, nil
}

func nameOf(u *url.URL, host string) string {
	if u.Fragment != "" {
		return strings.TrimSpace(u.Fragment)
	}
	return host
}

// buildStream собирает streamSettings из параметров ссылки (общий формат vless/trojan/vmess).
func buildStream(q url.Values, defSecurity string, sockopt any) (map[string]any, string, error) {
	network := strings.ToLower(q.Get("type"))
	switch network {
	case "", "tcp", "raw":
		network = "tcp"
	case "splithttp":
		network = "xhttp"
	case "ws", "grpc", "xhttp", "httpupgrade":
	default:
		return nil, "", fmt.Errorf("транспорт %q не поддерживается", network)
	}
	if network == "tcp" && q.Get("headerType") != "" && q.Get("headerType") != "none" {
		return nil, "", fmt.Errorf("tcp headerType=%s не поддерживается", q.Get("headerType"))
	}

	security := strings.ToLower(q.Get("security"))
	if security == "" {
		security = defSecurity
	}
	stream := map[string]any{"network": network, "security": security}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	fp := q.Get("fp")
	switch security {
	case "reality":
		if q.Get("pbk") == "" {
			return nil, "", fmt.Errorf("reality без pbk")
		}
		if fp == "" {
			fp = "chrome"
		}
		rs := map[string]any{"serverName": sni, "fingerprint": fp, "publicKey": q.Get("pbk"), "shortId": q.Get("sid")}
		if v := q.Get("spx"); v != "" {
			rs["spiderX"] = v
		}
		if v := q.Get("pqv"); v != "" {
			rs["mldsa65Verify"] = v
		}
		stream["realitySettings"] = rs
	case "tls":
		ts := map[string]any{}
		if sni != "" {
			ts["serverName"] = sni
		}
		if fp != "" {
			ts["fingerprint"] = fp
		}
		if v := q.Get("alpn"); v != "" {
			ts["alpn"] = strings.Split(v, ",")
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" || q.Get("allowInsecure") == "true" {
			ts["allowInsecure"] = true
		}
		stream["tlsSettings"] = ts
	case "none":
	default:
		return nil, "", fmt.Errorf("security %q не поддерживается", security)
	}

	hostHdr, path := q.Get("host"), q.Get("path")
	switch network {
	case "ws", "httpupgrade":
		s := map[string]any{}
		if path != "" {
			s["path"] = path
		}
		if hostHdr != "" {
			s["host"] = hostHdr
		}
		stream[network+"Settings"] = s
	case "grpc":
		sn := q.Get("serviceName")
		if sn == "" {
			sn = path
		}
		s := map[string]any{"serviceName": sn}
		if q.Get("mode") == "multi" {
			s["multiMode"] = true
		}
		if v := q.Get("authority"); v != "" {
			s["authority"] = v
		}
		stream["grpcSettings"] = s
	case "xhttp":
		s := map[string]any{}
		if path != "" {
			s["path"] = path
		}
		if hostHdr != "" {
			s["host"] = hostHdr
		}
		if v := q.Get("mode"); v != "" {
			s["mode"] = v
		}
		if v := q.Get("extra"); v != "" {
			var extra any
			if json.Unmarshal([]byte(v), &extra) == nil {
				s["extra"] = extra
			}
		}
		stream["xhttpSettings"] = s
	}
	if sockopt != nil {
		stream["sockopt"] = sockopt
	}
	return stream, network, nil
}

func parseVless(link string, sockopt any) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Node{}, err
	}
	id := u.User.Username()
	if id == "" || strings.Trim(id, "0-") == "" {
		return Node{}, errInfoNode
	}
	q := u.Query()
	stream, _, err := buildStream(q, "none", sockopt)
	if err != nil {
		return Node{}, err
	}
	enc := q.Get("encryption")
	if enc == "" {
		enc = "none"
	}
	user := map[string]any{"id": id, "encryption": enc}
	if v := q.Get("flow"); v != "" {
		user["flow"] = v
	}
	tag := nodeTag(link)
	ob := map[string]any{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{user}}},
		},
		"streamSettings": stream,
	}
	return Node{Tag: tag, Name: nameOf(u, host), Proto: "vless", Address: host, Port: port, Outbound: ob}, nil
}

func parseTrojan(link string, sockopt any) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Node{}, err
	}
	pass := u.User.Username()
	if pass == "" {
		return Node{}, fmt.Errorf("нет пароля")
	}
	stream, _, err := buildStream(u.Query(), "tls", sockopt)
	if err != nil {
		return Node{}, err
	}
	tag := nodeTag(link)
	ob := map[string]any{
		"tag":            tag,
		"protocol":       "trojan",
		"settings":       map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "password": pass}}},
		"streamSettings": stream,
	}
	return Node{Tag: tag, Name: nameOf(u, host), Proto: "trojan", Address: host, Port: port, Outbound: ob}, nil
}

// parseSS понимает SIP002 (ss://base64(method:pass)@host:port#name),
// открытый userinfo (ss://method:pass@host:port) и старый формат (ss://base64(method:pass@host:port)#name).
func parseSS(link string, sockopt any) (Node, error) {
	rest := link[len("ss://"):]
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	if q, _ := url.ParseQuery(query); q.Get("plugin") != "" {
		return Node{}, fmt.Errorf("плагин %s не поддерживается", strings.SplitN(q.Get("plugin"), ";", 2)[0])
	}
	var userinfo, hp string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo, hp = rest[:i], rest[i+1:]
		if d, ok := decodeB64(userinfo); ok && strings.Contains(d, ":") {
			userinfo = d
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
	} else {
		d, ok := decodeB64(rest)
		if !ok {
			return Node{}, fmt.Errorf("не удалось разобрать ss-ссылку")
		}
		i := strings.LastIndex(d, "@")
		if i < 0 {
			return Node{}, fmt.Errorf("не удалось разобрать ss-ссылку")
		}
		userinfo, hp = d[:i], d[i+1:]
	}
	mp := strings.SplitN(userinfo, ":", 2)
	if len(mp) != 2 || mp[0] == "" {
		return Node{}, fmt.Errorf("нет метода шифрования или пароля")
	}
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return Node{}, err
	}
	port, _ := strconv.Atoi(p)
	if isInfoAddress(h, port) {
		return Node{}, errInfoNode
	}
	if name == "" {
		name = h
	}
	stream := map[string]any{"network": "tcp", "security": "none"}
	if sockopt != nil {
		stream["sockopt"] = sockopt
	}
	tag := nodeTag(link)
	ob := map[string]any{
		"tag":      tag,
		"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": h, "port": port, "method": strings.ToLower(mp[0]), "password": mp[1],
		}}},
		"streamSettings": stream,
	}
	return Node{Tag: tag, Name: strings.TrimSpace(name), Proto: "ss", Address: h, Port: port, Outbound: ob}, nil
}

// parseVmess — vmess://base64(JSON) в формате v2rayN.
func parseVmess(link string, sockopt any) (Node, error) {
	d, ok := decodeB64(link[len("vmess://"):])
	if !ok {
		return Node{}, fmt.Errorf("vmess: не base64")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(d), &m); err != nil {
		return Node{}, fmt.Errorf("vmess: %v", err)
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	host := str("add")
	port, _ := strconv.Atoi(str("port"))
	if isInfoAddress(host, port) {
		return Node{}, errInfoNode
	}
	id := str("id")
	if id == "" || strings.Trim(id, "0-") == "" {
		return Node{}, errInfoNode
	}
	if aid, _ := strconv.Atoi(str("aid")); aid > 0 {
		return Node{}, fmt.Errorf("vmess с alterId>0 Xray больше не поддерживает")
	}
	q := url.Values{}
	q.Set("type", str("net"))
	q.Set("headerType", str("type"))
	q.Set("host", str("host"))
	q.Set("path", str("path"))
	q.Set("security", str("tls"))
	q.Set("sni", str("sni"))
	q.Set("alpn", str("alpn"))
	q.Set("fp", str("fp"))
	if q.Get("type") == "grpc" {
		q.Set("serviceName", str("path"))
		if str("type") == "multi" {
			q.Set("mode", "multi")
		}
		q.Del("headerType")
	}
	stream, _, err := buildStream(q, "none", sockopt)
	if err != nil {
		return Node{}, err
	}
	scy := str("scy")
	if scy == "" {
		scy = "auto"
	}
	name := str("ps")
	if name == "" {
		name = host
	}
	tag := nodeTag(link)
	ob := map[string]any{
		"tag":      tag,
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{map[string]any{"id": id, "security": scy}}}},
		},
		"streamSettings": stream,
	}
	return Node{Tag: tag, Name: name, Proto: "vmess", Address: host, Port: port, Outbound: ob}, nil
}
