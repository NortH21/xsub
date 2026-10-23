package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// parseLink разбирает одну ссылку-узел.
func parseLink(link string, sockopt any) (Node, error) {
	i := strings.Index(link, "://")
	if i <= 0 {
		return Node{}, fmt.Errorf("не ссылка")
	}
	switch scheme := strings.ToLower(link[:i]); scheme {
	case "vless":
		return parseVless(link, sockopt)
	case "trojan":
		return parseTrojan(link, sockopt)
	case "ss":
		return parseSS(link, sockopt)
	case "vmess":
		return parseVmess(link, sockopt)
	case "hysteria2", "hy2":
		return parseHysteria2(link, sockopt)
	case "wireguard", "wg":
		return parseWireGuard(link, sockopt)
	case "socks", "socks5", "socks5h":
		return parseProxy(link, "socks", sockopt)
	case "http", "https":
		return parseProxy(link, scheme, sockopt)
	case "tuic", "hysteria", "hy", "anytls", "naive+https", "naive+quic", "juicity", "ssr", "ssh", "mieru":
		return Node{}, fmt.Errorf("протокол %s не поддерживается ядром Xray", scheme)
	default:
		return Node{}, fmt.Errorf("протокол %s не поддерживается", scheme)
	}
}

func newNode(link, proto, name, host string, port int, warn string, ob map[string]any) Node {
	tag := identityTag("node-", ob)
	ob["tag"] = tag
	return Node{Tag: tag, Name: name, Proto: proto, Address: host, Port: port, Warn: warn, Outbound: ob}
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
	stream, warn, err := buildStream(q, "none", sockopt)
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
	ob := map[string]any{
		"protocol":       "vless",
		"settings":       map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{user}}}},
		"streamSettings": stream,
	}
	return newNode(link, "vless", nameOf(u, host), host, port, warn, ob), nil
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
	q := u.Query()
	stream, warn, err := buildStream(q, "tls", sockopt)
	if err != nil {
		return Node{}, err
	}
	srv := map[string]any{"address": host, "port": port, "password": pass}
	if v := q.Get("flow"); v != "" {
		srv["flow"] = v
	}
	ob := map[string]any{
		"protocol":       "trojan",
		"settings":       map[string]any{"servers": []any{srv}},
		"streamSettings": stream,
	}
	return newNode(link, "trojan", nameOf(u, host), host, port, warn, ob), nil
}

// splitLink делит ссылку на части вручную (url.Parse не понимает, например, base64 в userinfo
// или несколько портов «443,20000-30000»).
type linkParts struct {
	userinfo, hostport, path string
	query                    url.Values
	name                     string
}

func splitLink(link string) linkParts {
	var p linkParts
	rest := link[strings.Index(link, "://")+3:]
	if i := strings.Index(rest, "#"); i >= 0 {
		p.name, _ = url.PathUnescape(rest[i+1:])
		p.name = strings.TrimSpace(p.name)
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		p.query, _ = url.ParseQuery(rest[i+1:])
		rest = rest[:i]
	}
	if p.query == nil {
		p.query = url.Values{}
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		p.path = rest[i:]
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		p.userinfo, p.hostport = rest[:i], rest[i+1:]
	} else {
		p.hostport = rest
	}
	return p
}

// splitHostPorts: «host:443», «[::1]:443», «host:443,20000-30000».
func splitHostPorts(hp string) (host, ports string, err error) {
	if strings.HasPrefix(hp, "[") {
		i := strings.Index(hp, "]")
		if i < 0 || i+1 >= len(hp) || hp[i+1] != ':' {
			return "", "", fmt.Errorf("неверный адрес %q", hp)
		}
		return hp[1:i], hp[i+2:], nil
	}
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		return hp, "", nil
	}
	return hp[:i], hp[i+1:], nil
}

func parseSS(link string, sockopt any) (Node, error) {
	p := splitLink(link)
	if p.query.Get("plugin") != "" {
		return Node{}, fmt.Errorf("плагин %s Xray не поддерживает", strings.SplitN(p.query.Get("plugin"), ";", 2)[0])
	}
	userinfo, hp := p.userinfo, p.hostport
	if userinfo != "" {
		if d, ok := decodeB64(userinfo); ok && strings.Contains(d, ":") {
			userinfo = d
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
	} else {
		d, ok := decodeB64(hp)
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
	h, ps, err := splitHostPorts(hp)
	if err != nil {
		return Node{}, err
	}
	port, _ := strconv.Atoi(ps)
	if isInfoAddress(h, port) {
		return Node{}, errInfoNode
	}
	name := firstNonEmpty(p.name, h)
	stream := map[string]any{"network": "tcp", "security": "none"}
	if sockopt != nil {
		stream["sockopt"] = sockopt
	}
	ob := map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": h, "port": port, "method": strings.ToLower(mp[0]), "password": mp[1],
		}}},
		"streamSettings": stream,
	}
	return newNode(link, "ss", name, h, port, "", ob), nil
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
	str := func(k string) string { return anyStr(m[k]) }
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
	for k, v := range map[string]string{
		"type": str("net"), "headerType": str("type"), "host": str("host"), "path": str("path"),
		"security": str("tls"), "sni": str("sni"), "alpn": str("alpn"), "fp": str("fp"),
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	switch q.Get("type") {
	case "grpc":
		q.Set("serviceName", str("path"))
		if str("type") == "multi" {
			q.Set("mode", "multi")
		}
		q.Del("headerType")
	case "kcp", "mkcp":
		if s := str("path"); s != "" {
			q.Set("seed", s)
		}
	}
	stream, warn, err := buildStream(q, "none", sockopt)
	if err != nil {
		return Node{}, err
	}
	scy := firstNonEmpty(str("scy"), "auto")
	ob := map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{map[string]any{"id": id, "security": scy}}}},
		},
		"streamSettings": stream,
	}
	return newNode(link, "vmess", firstNonEmpty(str("ps"), host), host, port, warn, ob), nil
}

func anyStr(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case bool:
		if x {
			return "1"
		}
		return ""
	}
	return ""
}

// parseHysteria2: hysteria2://auth@host:port[,hop-ports]/?sni=&insecure=1&obfs=salamander&obfs-password=&pinSHA256=&mport=#name
func parseHysteria2(link string, sockopt any) (Node, error) {
	p := splitLink(link)
	host, ports, err := splitHostPorts(p.hostport)
	if err != nil {
		return Node{}, err
	}
	hop := p.query.Get("mport")
	mainPort := ports
	if strings.ContainsAny(ports, ",-") {
		if hop == "" {
			hop = ports
		}
		mainPort = strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == '-' })[0]
	}
	port, _ := strconv.Atoi(mainPort)
	if port == 0 && ports == "" {
		port = 443
	}
	if isInfoAddress(host, port) {
		return Node{}, errInfoNode
	}
	auth, _ := url.PathUnescape(p.userinfo)
	if auth == "" {
		auth = p.query.Get("auth")
	}
	if auth == "" {
		return Node{}, fmt.Errorf("нет пароля")
	}
	q := p.query
	ts, warn := tlsSettings(q, firstNonEmpty(q.Get("sni"), q.Get("peer"), host), "h3")
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      ts,
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
	}
	var masks []any
	if hop != "" {
		hop = strings.ReplaceAll(hop, ":", "-")
		masks = append(masks, map[string]any{"type": "udphop", "settings": map[string]any{"mode": "intervalRemote", "remotePorts": hop}})
	}
	switch obfs := strings.ToLower(q.Get("obfs")); obfs {
	case "", "none":
	case "salamander":
		masks = append(masks, map[string]any{"type": "salamander", "settings": map[string]any{"password": q.Get("obfs-password")}})
	default:
		return Node{}, fmt.Errorf("обфускация %s не поддерживается", obfs)
	}
	if len(masks) > 0 {
		stream["finalmask"] = map[string]any{"udp": masks}
	}
	if sockopt != nil {
		stream["sockopt"] = sockopt
	}
	ob := map[string]any{
		"protocol":       "hysteria",
		"settings":       map[string]any{"version": 2, "address": host, "port": port},
		"streamSettings": stream,
	}
	return newNode(link, "hysteria2", firstNonEmpty(p.name, host), host, port, warn, ob), nil
}

// parseWireGuard: wireguard://<приватный ключ>@host:port?publickey=&address=&presharedkey=&reserved=&mtu=#name
func parseWireGuard(link string, sockopt any) (Node, error) {
	p := splitLink(link)
	q := p.query
	host, ps, err := splitHostPorts(p.hostport)
	if err != nil {
		return Node{}, err
	}
	port, _ := strconv.Atoi(ps)
	if isInfoAddress(host, port) {
		return Node{}, errInfoNode
	}
	secret, _ := url.PathUnescape(p.userinfo)
	secret = firstNonEmpty(secret, q.Get("privatekey"), q.Get("secretKey"), q.Get("private_key"))
	pub := firstNonEmpty(q.Get("publickey"), q.Get("publicKey"), q.Get("public_key"), q.Get("peer_public_key"))
	if secret == "" || pub == "" {
		return Node{}, fmt.Errorf("нет ключей WireGuard")
	}
	var addrs []string
	for _, a := range strings.Split(firstNonEmpty(q.Get("address"), q.Get("ip"), q.Get("local_address")), ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		if !strings.Contains(a, "/") {
			if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
				a += "/128"
			} else {
				a += "/32"
			}
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return Node{}, fmt.Errorf("нет адреса интерфейса WireGuard (address)")
	}
	peer := map[string]any{"publicKey": pub, "endpoint": net.JoinHostPort(host, strconv.Itoa(port))}
	if v := firstNonEmpty(q.Get("presharedkey"), q.Get("preSharedKey"), q.Get("pre_shared_key")); v != "" {
		peer["preSharedKey"] = v
	}
	if v, _ := strconv.Atoi(q.Get("keepalive")); v > 0 {
		peer["keepAlive"] = v
	}
	settings := map[string]any{"secretKey": secret, "address": addrs, "peers": []any{peer}, "noKernelTun": true}
	if mtu, _ := strconv.Atoi(q.Get("mtu")); mtu > 0 {
		settings["mtu"] = mtu
	}
	if r := parseReserved(q.Get("reserved")); r != nil {
		settings["reserved"] = r
	}
	ob := map[string]any{"protocol": "wireguard", "settings": settings}
	if sockopt != nil {
		ob["streamSettings"] = map[string]any{"sockopt": sockopt}
	}
	return newNode(link, "wireguard", firstNonEmpty(p.name, host), host, port, "", ob), nil
}

// parseReserved: «1,2,3» или base64 из трёх байт.
func parseReserved(s string) []int {
	s = strings.TrimSpace(strings.Trim(s, "[]"))
	if s == "" {
		return nil
	}
	if strings.Contains(s, ",") {
		var out []int
		for _, f := range strings.Split(s, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || n < 0 || n > 255 {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 3 {
		return []int{int(b[0]), int(b[1]), int(b[2])}
	}
	return nil
}

// parseProxy: socks5://user:pass@host:port, socks://base64(user:pass)@host:port, http(s)://user:pass@host:port.
func parseProxy(link, kind string, sockopt any) (Node, error) {
	p := splitLink(link)
	host, ps, err := splitHostPorts(p.hostport)
	if err != nil {
		return Node{}, err
	}
	if p.path != "" && p.path != "/" {
		return Node{}, fmt.Errorf("похоже на обычную ссылку, а не на прокси")
	}
	port, _ := strconv.Atoi(ps)
	if (kind == "http" || kind == "https") && port == 0 && p.userinfo == "" {
		return Node{}, fmt.Errorf("похоже на обычную ссылку, а не на прокси")
	}
	if port == 0 {
		switch kind {
		case "socks":
			port = 1080
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}
	if isInfoAddress(host, port) {
		return Node{}, errInfoNode
	}
	ui := p.userinfo
	if ui != "" && !strings.Contains(ui, ":") {
		if d, ok := decodeB64(ui); ok && strings.Contains(d, ":") {
			ui = d
		}
	}
	srv := map[string]any{"address": host, "port": port}
	if ui != "" {
		up := strings.SplitN(ui, ":", 2)
		user, _ := url.PathUnescape(up[0])
		pass := ""
		if len(up) == 2 {
			pass, _ = url.PathUnescape(up[1])
		}
		srv["users"] = []any{map[string]any{"user": user, "pass": pass}}
	}
	proto := kind
	warn := ""
	stream := map[string]any{}
	if kind == "https" || p.query.Get("security") == "tls" {
		if kind == "https" {
			proto = "http"
		}
		ts, w := tlsSettings(p.query, firstNonEmpty(p.query.Get("sni"), host), "")
		warn = w
		stream["security"] = "tls"
		stream["tlsSettings"] = ts
	}
	if sockopt != nil {
		stream["sockopt"] = sockopt
	}
	ob := map[string]any{"protocol": proto, "settings": map[string]any{"servers": []any{srv}}}
	if len(stream) > 0 {
		ob["streamSettings"] = stream
	}
	return newNode(link, kind, firstNonEmpty(p.name, host), host, port, warn, ob), nil
}
