package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var clashRe = regexp.MustCompile(`(?m)^proxies:\s*$|^proxies:\s*\[`)

func looksClash(s string) bool { return clashRe.MatchString(s) }

// ---------- общий построитель ссылок (для Clash и sing-box) ----------

type linkSpec struct {
	scheme, user, pass, host string
	port                     int
	q                        url.Values
	name                     string
}

func (l linkSpec) String() string {
	u := url.URL{Scheme: l.scheme, Host: net.JoinHostPort(l.host, strconv.Itoa(l.port)), Fragment: l.name}
	if l.pass != "" {
		u.User = url.UserPassword(l.user, l.pass)
	} else if l.user != "" {
		u.User = url.User(l.user)
	}
	if len(l.q) > 0 {
		u.RawQuery = l.q.Encode()
	}
	return u.String()
}

func set(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func vmessLink(m map[string]any) string {
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// ---------- Clash / mihomo YAML ----------

func fromClash(text string) ([]entry, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	var es []entry
	for _, p := range doc.Proxies {
		name := anyStr(p["name"])
		link, err := clashToLink(p)
		es = append(es, entry{link: link, err: err, name: "«" + name + "»"})
	}
	return es, nil
}

func cs(p map[string]any, k string) string { return anyStr(p[k]) }

func cmap(p map[string]any, k string) map[string]any {
	if m, ok := p[k].(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func clist(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, i := range x {
			if s := anyStr(i); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x != "" {
			return []string{x}
		}
	}
	return nil
}

func ctrue(p map[string]any, k string) bool {
	b, ok := p[k].(bool)
	return ok && b
}

// clashTransport переводит network/*-opts в параметры ссылки.
func clashTransport(p map[string]any, q url.Values) error {
	network := cs(p, "network")
	switch network {
	case "", "tcp":
	case "ws":
		ws := cmap(p, "ws-opts")
		if ctrue(ws, "v2ray-http-upgrade") {
			q.Set("type", "httpupgrade")
		} else {
			q.Set("type", "ws")
		}
		set(q, "path", cs(ws, "path"))
		set(q, "host", cs(cmap(ws, "headers"), "Host"))
	case "grpc":
		q.Set("type", "grpc")
		set(q, "serviceName", cs(cmap(p, "grpc-opts"), "grpc-service-name"))
	case "xhttp":
		x := cmap(p, "xhttp-opts")
		q.Set("type", "xhttp")
		set(q, "path", cs(x, "path"))
		set(q, "host", cs(x, "host"))
		set(q, "mode", cs(x, "mode"))
	case "http":
		h := cmap(p, "http-opts")
		q.Set("headerType", "http")
		set(q, "path", strings.Join(clist(h["path"]), ","))
		set(q, "host", strings.Join(clist(cmap(h, "headers")["Host"]), ","))
	case "h2":
		return fmt.Errorf("транспорт h2 удалён из Xray")
	default:
		return fmt.Errorf("транспорт %s не поддерживается", network)
	}
	return nil
}

func clashTLS(p map[string]any, q url.Values, sniKey string, defTLS bool) {
	r := cmap(p, "reality-opts")
	switch {
	case cs(r, "public-key") != "":
		q.Set("security", "reality")
		q.Set("pbk", cs(r, "public-key"))
		set(q, "sid", cs(r, "short-id"))
	case ctrue(p, "tls") || defTLS:
		q.Set("security", "tls")
	default:
		q.Set("security", "none")
	}
	set(q, "sni", firstNonEmpty(cs(p, sniKey), cs(p, "sni"), cs(p, "servername")))
	set(q, "fp", cs(p, "client-fingerprint"))
	set(q, "alpn", strings.Join(clist(p["alpn"]), ","))
	if ctrue(p, "skip-cert-verify") {
		q.Set("insecure", "1")
	}
}

func clashToLink(p map[string]any) (string, error) {
	t := strings.ToLower(cs(p, "type"))
	port, _ := strconv.Atoi(cs(p, "port"))
	l := linkSpec{host: cs(p, "server"), port: port, q: url.Values{}, name: cs(p, "name")}
	switch t {
	case "vless":
		l.scheme, l.user = "vless", cs(p, "uuid")
		l.q.Set("encryption", firstNonEmpty(cs(p, "encryption"), "none"))
		set(l.q, "flow", cs(p, "flow"))
		clashTLS(p, l.q, "servername", false)
		if err := clashTransport(p, l.q); err != nil {
			return "", err
		}
	case "trojan":
		l.scheme, l.user = "trojan", cs(p, "password")
		clashTLS(p, l.q, "sni", true)
		if err := clashTransport(p, l.q); err != nil {
			return "", err
		}
	case "vmess":
		q := url.Values{}
		clashTLS(p, q, "servername", false)
		if err := clashTransport(p, q); err != nil {
			return "", err
		}
		tlsMode := ""
		if q.Get("security") == "tls" {
			tlsMode = "tls"
		}
		m := map[string]any{
			"v": "2", "ps": l.name, "add": l.host, "port": strconv.Itoa(port), "id": cs(p, "uuid"),
			"aid": firstNonEmpty(cs(p, "alterId"), "0"), "scy": firstNonEmpty(cs(p, "cipher"), "auto"),
			"net": firstNonEmpty(q.Get("type"), "tcp"), "type": firstNonEmpty(q.Get("headerType"), "none"),
			"host": q.Get("host"), "path": firstNonEmpty(q.Get("path"), q.Get("serviceName")),
			"tls": tlsMode, "sni": q.Get("sni"), "alpn": q.Get("alpn"), "fp": q.Get("fp"),
		}
		return vmessLink(m), nil
	case "ss":
		if cs(p, "plugin") != "" {
			return "", fmt.Errorf("плагин %s Xray не поддерживает", cs(p, "plugin"))
		}
		l.scheme = "ss"
		l.user = base64.RawURLEncoding.EncodeToString([]byte(cs(p, "cipher") + ":" + cs(p, "password")))
	case "hysteria2", "hy2":
		l.scheme, l.user = "hysteria2", firstNonEmpty(cs(p, "password"), cs(p, "auth"))
		set(l.q, "sni", cs(p, "sni"))
		set(l.q, "obfs", cs(p, "obfs"))
		set(l.q, "obfs-password", cs(p, "obfs-password"))
		set(l.q, "mport", cs(p, "ports"))
		set(l.q, "pinSHA256", cs(p, "fingerprint"))
		set(l.q, "alpn", strings.Join(clist(p["alpn"]), ","))
		if ctrue(p, "skip-cert-verify") {
			l.q.Set("insecure", "1")
		}
	case "wireguard":
		l.scheme, l.user = "wireguard", cs(p, "private-key")
		peer := p
		if peers, ok := p["peers"].([]any); ok && len(peers) > 0 {
			if m, ok := peers[0].(map[string]any); ok {
				peer = m
				l.host = cs(m, "server")
				l.port, _ = strconv.Atoi(cs(m, "port"))
			}
		}
		set(l.q, "publickey", cs(peer, "public-key"))
		set(l.q, "presharedkey", cs(peer, "pre-shared-key"))
		var addrs []string
		for _, k := range []string{"ip", "ipv6"} {
			if v := cs(p, k); v != "" {
				addrs = append(addrs, v)
			}
		}
		set(l.q, "address", strings.Join(addrs, ","))
		set(l.q, "mtu", cs(p, "mtu"))
		if r := clist(peer["reserved"]); len(r) > 0 {
			l.q.Set("reserved", strings.Join(r, ","))
		}
	case "socks5", "http":
		l.scheme = t
		if t == "http" && ctrue(p, "tls") {
			l.scheme = "https"
		}
		if t == "socks5" && ctrue(p, "tls") {
			l.q.Set("security", "tls")
		}
		l.user, l.pass = cs(p, "username"), cs(p, "password")
		set(l.q, "sni", cs(p, "sni"))
	case "direct", "reject", "dns", "relay", "selector", "url-test", "fallback", "load-balance":
		return "", fmt.Errorf("служебная запись %s", t)
	default:
		return "", fmt.Errorf("тип %s не поддерживается ядром Xray", t)
	}
	return l.String(), nil
}

// ---------- JSON: Xray и sing-box ----------

var xrayProxyProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria": true,
	"wireguard": true, "socks": true, "http": true,
}

func fromJSON(text string, sockopt any) ([]entry, string, error) {
	var v any
	if err := json.Unmarshal(stripJSONComments([]byte(text)), &v); err != nil {
		return nil, "", err
	}
	var configs []map[string]any
	switch x := v.(type) {
	case []any:
		for _, i := range x {
			if m, ok := i.(map[string]any); ok {
				configs = append(configs, m)
			}
		}
	case map[string]any:
		configs = []map[string]any{x}
	}
	if len(configs) == 0 {
		return nil, "", fmt.Errorf("пустой JSON")
	}
	// sing-box: outbounds с полем type; Xray: outbounds с полем protocol.
	if obs, ok := configs[0]["outbounds"].([]any); ok && len(obs) > 0 {
		if m, ok := obs[0].(map[string]any); ok && m["type"] != nil && m["protocol"] == nil {
			es := fromSingBox(configs[0])
			return es, "sing-box JSON", nil
		}
	}
	var es []entry
	for i, cfg := range configs {
		name := firstNonEmpty(anyStr(cfg["remarks"]), anyStr(cfg["ps"]), fmt.Sprintf("узел %d", i+1))
		node, err := xrayConfigNode(cfg, name, sockopt)
		e := entry{name: "«" + name + "»", err: err}
		if err == nil {
			e.node = &node
		}
		es = append(es, e)
	}
	return es, "JSON Xray", nil
}

// xrayConfigNode берёт из полного конфига Xray исходящий узел (обычно с тегом proxy).
func xrayConfigNode(cfg map[string]any, name string, sockopt any) (Node, error) {
	obs, _ := cfg["outbounds"].([]any)
	var ob map[string]any
	for _, o := range obs {
		m, ok := o.(map[string]any)
		if !ok || !xrayProxyProtocols[anyStr(m["protocol"])] {
			continue
		}
		if ob == nil || anyStr(m["tag"]) == "proxy" {
			ob = m
		}
	}
	if ob == nil {
		return Node{}, fmt.Errorf("нет подходящего outbound")
	}
	if ps, ok := ob["proxySettings"]; ok && ps != nil {
		return Node{}, fmt.Errorf("цепочки прокси не поддерживаются")
	}
	ss, _ := ob["streamSettings"].(map[string]any)
	if ss == nil {
		ss = map[string]any{}
	}
	if so, ok := ss["sockopt"].(map[string]any); ok && so["dialerProxy"] != nil {
		return Node{}, fmt.Errorf("цепочки прокси (dialerProxy) не поддерживаются")
	}
	warn := ""
	if ts, ok := ss["tlsSettings"].(map[string]any); ok && ts["allowInsecure"] != nil {
		delete(ts, "allowInsecure")
		warn = "в конфиге allowInsecure — Xray так больше не умеет, проверка сертификата включена"
	}
	// метка XKeen: добавляем недостающие поля sockopt, не трогая заданные
	if tmpl, ok := sockopt.(map[string]any); ok {
		so, _ := ss["sockopt"].(map[string]any)
		if so == nil {
			so = map[string]any{}
		}
		for k, v := range tmpl {
			if _, has := so[k]; !has {
				so[k] = v
			}
		}
		ss["sockopt"] = so
		ob["streamSettings"] = ss
	}
	proto := anyStr(ob["protocol"])
	if proto == "wireguard" {
		if st, ok := ob["settings"].(map[string]any); ok {
			st["noKernelTun"] = true
		}
	}
	delete(ob, "tag")
	b, _ := json.Marshal(ob)
	h := sha1.Sum(b)
	tag := "node-" + hex.EncodeToString(h[:])[:8]
	ob["tag"] = tag
	host, port := outboundAddr(ob)
	if isInfoAddress(host, port) {
		return Node{}, errInfoNode
	}
	return Node{Tag: tag, Name: name, Proto: proto, Address: host, Port: port, Warn: warn, Outbound: ob}, nil
}

func outboundAddr(ob map[string]any) (string, int) {
	st, _ := ob["settings"].(map[string]any)
	if st == nil {
		return "", 0
	}
	pick := func(m map[string]any) (string, int) {
		p, _ := strconv.Atoi(anyStr(m["port"]))
		return anyStr(m["address"]), p
	}
	for _, k := range []string{"vnext", "servers"} {
		if l, ok := st[k].([]any); ok && len(l) > 0 {
			if m, ok := l[0].(map[string]any); ok {
				return pick(m)
			}
		}
	}
	if peers, ok := st["peers"].([]any); ok && len(peers) > 0 {
		if m, ok := peers[0].(map[string]any); ok {
			if h, ps, err := net.SplitHostPort(anyStr(m["endpoint"])); err == nil {
				p, _ := strconv.Atoi(ps)
				return h, p
			}
		}
	}
	return pick(st)
}

// ---------- sing-box ----------

func fromSingBox(cfg map[string]any) []entry {
	var es []entry
	var items []map[string]any
	for _, k := range []string{"outbounds", "endpoints"} {
		if l, ok := cfg[k].([]any); ok {
			for _, i := range l {
				if m, ok := i.(map[string]any); ok {
					items = append(items, m)
				}
			}
		}
	}
	for _, o := range items {
		t := anyStr(o["type"])
		switch t {
		case "direct", "block", "dns", "selector", "urltest":
			continue
		}
		link, err := singBoxToLink(o)
		es = append(es, entry{link: link, err: err, name: "«" + anyStr(o["tag"]) + "»"})
	}
	return es
}

func singBoxTLS(o map[string]any, q url.Values, defTLS bool) {
	t := cmap(o, "tls")
	r := cmap(t, "reality")
	switch {
	case ctrue(r, "enabled"):
		q.Set("security", "reality")
		set(q, "pbk", cs(r, "public_key"))
		set(q, "sid", cs(r, "short_id"))
	case ctrue(t, "enabled") || defTLS:
		q.Set("security", "tls")
	default:
		q.Set("security", "none")
	}
	set(q, "sni", cs(t, "server_name"))
	set(q, "alpn", strings.Join(clist(t["alpn"]), ","))
	set(q, "fp", cs(cmap(t, "utls"), "fingerprint"))
	if ctrue(t, "insecure") {
		q.Set("insecure", "1")
	}
}

func singBoxTransport(o map[string]any, q url.Values) error {
	tr := cmap(o, "transport")
	switch tt := cs(tr, "type"); tt {
	case "":
	case "ws", "httpupgrade":
		q.Set("type", tt)
		set(q, "path", cs(tr, "path"))
		set(q, "host", firstNonEmpty(cs(tr, "host"), cs(cmap(tr, "headers"), "Host")))
	case "grpc":
		q.Set("type", "grpc")
		set(q, "serviceName", cs(tr, "service_name"))
	default:
		return fmt.Errorf("транспорт %s не поддерживается Xray", tt)
	}
	return nil
}

func singBoxToLink(o map[string]any) (string, error) {
	t := anyStr(o["type"])
	port, _ := strconv.Atoi(cs(o, "server_port"))
	l := linkSpec{host: cs(o, "server"), port: port, q: url.Values{}, name: cs(o, "tag")}
	switch t {
	case "vless":
		l.scheme, l.user = "vless", cs(o, "uuid")
		l.q.Set("encryption", "none")
		set(l.q, "flow", cs(o, "flow"))
		singBoxTLS(o, l.q, false)
		if err := singBoxTransport(o, l.q); err != nil {
			return "", err
		}
	case "trojan":
		l.scheme, l.user = "trojan", cs(o, "password")
		singBoxTLS(o, l.q, false)
		if err := singBoxTransport(o, l.q); err != nil {
			return "", err
		}
	case "vmess":
		q := url.Values{}
		singBoxTLS(o, q, false)
		if err := singBoxTransport(o, q); err != nil {
			return "", err
		}
		tlsMode := ""
		if q.Get("security") == "tls" {
			tlsMode = "tls"
		}
		return vmessLink(map[string]any{
			"v": "2", "ps": l.name, "add": l.host, "port": strconv.Itoa(port), "id": cs(o, "uuid"),
			"aid": firstNonEmpty(cs(o, "alter_id"), "0"), "scy": firstNonEmpty(cs(o, "security"), "auto"),
			"net": firstNonEmpty(q.Get("type"), "tcp"), "host": q.Get("host"),
			"path": firstNonEmpty(q.Get("path"), q.Get("serviceName")),
			"tls":  tlsMode, "sni": q.Get("sni"), "alpn": q.Get("alpn"), "fp": q.Get("fp"),
		}), nil
	case "shadowsocks":
		if cs(o, "plugin") != "" {
			return "", fmt.Errorf("плагин %s Xray не поддерживает", cs(o, "plugin"))
		}
		l.scheme = "ss"
		l.user = base64.RawURLEncoding.EncodeToString([]byte(cs(o, "method") + ":" + cs(o, "password")))
	case "hysteria2":
		l.scheme, l.user = "hysteria2", cs(o, "password")
		tq := url.Values{}
		singBoxTLS(o, tq, true)
		for _, k := range []string{"sni", "alpn", "insecure"} {
			set(l.q, k, tq.Get(k))
		}
		ob := cmap(o, "obfs")
		set(l.q, "obfs", cs(ob, "type"))
		set(l.q, "obfs-password", cs(ob, "password"))
		if sp := clist(o["server_ports"]); len(sp) > 0 {
			l.q.Set("mport", strings.ReplaceAll(strings.Join(sp, ","), ":", "-"))
		}
	case "wireguard":
		l.scheme, l.user = "wireguard", cs(o, "private_key")
		peer := o
		if peers, ok := o["peers"].([]any); ok && len(peers) > 0 {
			if m, ok := peers[0].(map[string]any); ok {
				peer = m
				l.host = firstNonEmpty(cs(m, "address"), cs(m, "server"))
				l.port, _ = strconv.Atoi(firstNonEmpty(cs(m, "port"), cs(m, "server_port")))
			}
		}
		set(l.q, "publickey", firstNonEmpty(cs(peer, "public_key"), cs(o, "peer_public_key")))
		set(l.q, "presharedkey", firstNonEmpty(cs(peer, "pre_shared_key"), cs(o, "pre_shared_key")))
		addrs := clist(o["address"])
		if len(addrs) == 0 {
			addrs = clist(o["local_address"])
		}
		set(l.q, "address", strings.Join(addrs, ","))
		set(l.q, "mtu", cs(o, "mtu"))
		r := clist(peer["reserved"])
		if len(r) == 0 {
			r = clist(o["reserved"])
		}
		set(l.q, "reserved", strings.Join(r, ","))
	case "socks", "http":
		l.scheme = map[string]string{"socks": "socks5", "http": "http"}[t]
		if t == "http" && ctrue(cmap(o, "tls"), "enabled") {
			l.scheme = "https"
		}
		l.user, l.pass = cs(o, "username"), cs(o, "password")
	default:
		return "", fmt.Errorf("тип %s не поддерживается ядром Xray", t)
	}
	return l.String(), nil
}
