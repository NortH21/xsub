package main

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Вымышленные ключи: сгенерированы случайно только для тестов.
const (
	wgPriv = "aAnxn+54zTYTGpwFDu+ZLBumaHFYInuJBSD9ERYH8RQ="
	wgPub  = "2nUZPpyByl6LMhIjPwEAkWdZXMmFFRqFJYeB07lwt8g="
	pinHex = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
)

func names(nodes []Node) string {
	var s []string
	for _, n := range nodes {
		s = append(s, n.Proto+":"+n.Name)
	}
	return strings.Join(s, "|")
}

func extraLinks() string {
	return strings.Join([]string{
		"hysteria2://p%40ss@hy.example.com:443,20000-30000/?sni=hy.example.com&obfs=salamander&obfs-password=ob&pinSHA256=" + pinHex + "#HY2%20hop",
		"hy2://pw@hy2.example.com:8443?insecure=1#HY2%20insecure",
		"wireguard://" + url.QueryEscape(wgPriv) + "@wg.example.com:51820?publickey=" + url.QueryEscape(wgPub) + "&address=10.7.0.2,fd00::2&reserved=1,2,3&mtu=1280#WG",
		"socks5://user:pa%3Ass@s5.example.com:1080#SOCKS",
		"socks://dXNlcjpwYXNz@s4.example.com:1080#SOCKS%20b64",
		"https://u:p@hp.example.com:8443#HTTPS%20proxy",
		"https://t.me/some_channel",
		"vless://" + tUUID + "@kcp.example.com:443?type=kcp&seed=sd#KCP",
		"vless://" + tUUID + "@th.example.com:80?type=tcp&headerType=http&host=a.example,b.example&path=/x#TCP%20http",
		"tuic://u:p@tu.example.com:443#TUIC",
		"vless://" + tUUID + "@h2.example.com:443?type=h2&security=tls#H2",
	}, "\n")
}

func TestExtraLinks(t *testing.T) {
	nodes, warns := parseSubscription(extraLinks(), parseOpts{sockopt: map[string]any{"mark": 255}})
	want := "hysteria2:HY2 hop|hysteria2:HY2 insecure|wireguard:WG|socks:SOCKS|socks:SOCKS b64|https:HTTPS proxy|vless:KCP|vless:TCP http"
	if names(nodes) != want {
		t.Fatalf("узлы:\n%s\nожидалось:\n%s\n%v", names(nodes), want, warns)
	}
	j := strings.Join(warns, "\n")
	for _, w := range []string{"insecure", "tuic не поддерживается ядром Xray", "h2 удалён", "обычную ссылку"} {
		if !strings.Contains(j, w) {
			t.Errorf("нет предупреждения %q:\n%s", w, j)
		}
	}
	hy, _ := json.Marshal(nodes[0].Outbound)
	for _, s := range []string{`"auth":"p@ss"`, `"remotePorts":"443,20000-30000"`, `"type":"salamander"`, `"pinnedPeerCertSha256":"` + pinHex, `"alpn":["h3"]`, `"port":443`} {
		if !strings.Contains(string(hy), s) {
			t.Errorf("hysteria2: нет %s в %s", s, hy)
		}
	}
	if i, s := strings.Index(string(hy), "udphop"), strings.Index(string(hy), "salamander"); i > s {
		t.Error("udphop должен идти раньше salamander")
	}
	wg, _ := json.Marshal(nodes[2].Outbound)
	for _, s := range []string{`"secretKey":"` + wgPriv, `"10.7.0.2/32"`, `"fd00::2/128"`, `"reserved":[1,2,3]`, `"noKernelTun":true`, `"endpoint":"wg.example.com:51820"`} {
		if !strings.Contains(string(wg), s) {
			t.Errorf("wireguard: нет %s в %s", s, wg)
		}
	}
	s5, _ := json.Marshal(nodes[3].Outbound)
	if !strings.Contains(string(s5), `"pass":"pa:ss"`) {
		t.Errorf("socks: %s", s5)
	}
	if b, _ := json.Marshal(nodes[4].Outbound); !strings.Contains(string(b), `"user":"user","pass":"pass"`) && !strings.Contains(string(b), `"pass":"pass","user":"user"`) {
		t.Errorf("socks base64: %s", b)
	}
}

const clashSample = `
mixed-port: 7890
proxies:
  - {name: "🇳🇱 NL reality", type: vless, server: nl.example.com, port: 443, uuid: 2d32250e-fb36-4495-bf21-07fa0b2e7f9d, network: tcp, tls: true, flow: xtls-rprx-vision, servername: www.example.org, client-fingerprint: chrome, reality-opts: {public-key: 4oPjFhCGYBbtVD2aCoA4x3EULVckDGWQYjvci2tp6Jo, short-id: ab}}
  - name: VMess WS
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 2d32250e-fb36-4495-bf21-07fa0b2e7f9d
    alterId: 0
    cipher: auto
    tls: true
    servername: vm.example.com
    network: ws
    ws-opts:
      path: /vm
      headers:
        Host: vm.example.com
  - {name: Trojan gRPC, type: trojan, server: tr.example.com, port: 443, password: secret, sni: tr.example.com, network: grpc, grpc-opts: {grpc-service-name: svc}}
  - {name: SS, type: ss, server: ss.example.com, port: 8388, cipher: aes-256-gcm, password: pw}
  - {name: SS obfs, type: ss, server: ss.example.com, port: 8389, cipher: aes-256-gcm, password: pw, plugin: obfs}
  - {name: HY2, type: hysteria2, server: hy.example.com, port: 443, ports: 20000-30000, password: pw, obfs: salamander, obfs-password: ob, sni: hy.example.com}
  - {name: WG, type: wireguard, server: wg.example.com, port: 51820, ip: 10.7.0.2, private-key: "aAnxn+54zTYTGpwFDu+ZLBumaHFYInuJBSD9ERYH8RQ=", public-key: "2nUZPpyByl6LMhIjPwEAkWdZXMmFFRqFJYeB07lwt8g=", reserved: [1, 2, 3], mtu: 1280}
  - {name: S5, type: socks5, server: s5.example.com, port: 1080, username: u, password: p}
  - {name: HTTPS, type: http, server: hp.example.com, port: 443, username: u, password: p, tls: true}
  - {name: TUIC, type: tuic, server: tu.example.com, port: 443, uuid: x, password: y}
  - {name: DIRECT, type: direct}
proxy-groups:
  - {name: PROXY, type: select, proxies: [SS]}
`

func TestClash(t *testing.T) {
	nodes, warns := parseSubscription(clashSample, parseOpts{})
	want := "vless:🇳🇱 NL reality|vmess:VMess WS|trojan:Trojan gRPC|ss:SS|hysteria2:HY2|wireguard:WG|socks:S5|https:HTTPS"
	if names(nodes) != want {
		t.Fatalf("узлы:\n%s\nожидалось:\n%s\n%v", names(nodes), want, warns)
	}
	j := strings.Join(warns, "\n")
	for _, w := range []string{"Clash", "плагин obfs", "tuic не поддерживается"} {
		if !strings.Contains(j, w) {
			t.Errorf("нет предупреждения %q:\n%s", w, j)
		}
	}
	b, _ := json.Marshal(nodes[0].Outbound)
	if !strings.Contains(string(b), `"security":"reality"`) || !strings.Contains(string(b), `"flow":"xtls-rprx-vision"`) {
		t.Errorf("reality: %s", b)
	}
}

const singBoxSample = `{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["a"]},
    {"type": "vless", "tag": "SB VLESS", "server": "sb.example.com", "server_port": 443, "uuid": "2d32250e-fb36-4495-bf21-07fa0b2e7f9d", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "www.example.org", "utls": {"enabled": true, "fingerprint": "chrome"}, "reality": {"enabled": true, "public_key": "4oPjFhCGYBbtVD2aCoA4x3EULVckDGWQYjvci2tp6Jo", "short_id": "ab"}}},
    {"type": "hysteria2", "tag": "SB HY2", "server": "hy.example.com", "server_port": 443, "server_ports": ["20000:30000"], "password": "pw",
     "obfs": {"type": "salamander", "password": "ob"}, "tls": {"enabled": true, "server_name": "hy.example.com"}},
    {"type": "trojan", "tag": "SB Trojan WS", "server": "tr.example.com", "server_port": 443, "password": "pw", "tls": {"enabled": true}, "transport": {"type": "ws", "path": "/t", "headers": {"Host": "tr.example.com"}}},
    {"type": "tuic", "tag": "SB TUIC", "server": "tu.example.com", "server_port": 443},
    {"type": "direct", "tag": "direct"}
  ],
  "endpoints": [
    {"type": "wireguard", "tag": "SB WG", "address": ["10.7.0.2/32"], "private_key": "aAnxn+54zTYTGpwFDu+ZLBumaHFYInuJBSD9ERYH8RQ=",
     "peers": [{"address": "wg.example.com", "port": 51820, "public_key": "2nUZPpyByl6LMhIjPwEAkWdZXMmFFRqFJYeB07lwt8g=", "reserved": [1,2,3]}]}
  ]
}`

func TestSingBox(t *testing.T) {
	nodes, warns := parseSubscription(singBoxSample, parseOpts{})
	want := "vless:SB VLESS|hysteria2:SB HY2|trojan:SB Trojan WS|wireguard:SB WG"
	if names(nodes) != want {
		t.Fatalf("узлы:\n%s\nожидалось:\n%s\n%v", names(nodes), want, warns)
	}
	if j := strings.Join(warns, "\n"); !strings.Contains(j, "sing-box") || !strings.Contains(j, "tuic") {
		t.Errorf("предупреждения:\n%s", j)
	}
}

const xrayJSONSample = `[
 {"remarks": "🇩🇪 Xray DE", "outbounds": [
   {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "de.example.com", "port": 443, "users": [{"id": "2d32250e-fb36-4495-bf21-07fa0b2e7f9d", "encryption": "none"}]}]},
    "streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "de.example.com", "allowInsecure": true}, "xhttpSettings": {"path": "/x"}}},
   {"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]},
 {"remarks": "Chain", "outbounds": [
   {"tag": "proxy", "protocol": "trojan", "settings": {"servers": [{"address": "c.example.com", "port": 443, "password": "x"}]}, "streamSettings": {"sockopt": {"dialerProxy": "f"}}},
   {"tag": "f", "protocol": "trojan", "settings": {"servers": [{"address": "f.example.com", "port": 443, "password": "y"}]}}]}
]`

func TestXrayJSON(t *testing.T) {
	nodes, warns := parseSubscription(xrayJSONSample, parseOpts{sockopt: map[string]any{"mark": 255}})
	if names(nodes) != "vless:🇩🇪 Xray DE" {
		t.Fatalf("%s %v", names(nodes), warns)
	}
	b, _ := json.Marshal(nodes[0].Outbound)
	if strings.Contains(string(b), "allowInsecure") || !strings.Contains(string(b), `"mark":255`) || !strings.Contains(string(b), `"tag":"node-`) {
		t.Errorf("outbound: %s", b)
	}
	if nodes[0].Address != "de.example.com" || nodes[0].Port != 443 {
		t.Errorf("адрес: %s:%d", nodes[0].Address, nodes[0].Port)
	}
	if j := strings.Join(warns, "\n"); !strings.Contains(j, "dialerProxy") || !strings.Contains(j, "allowInsecure") {
		t.Errorf("предупреждения:\n%s", j)
	}
}

// Все форматы через настоящий xray -test: XSUB_TEST_XRAY=путь.
func TestAllFormatsRealXray(t *testing.T) {
	xray := os.Getenv("XSUB_TEST_XRAY")
	if xray == "" {
		t.Skip("нет XSUB_TEST_XRAY")
	}
	c := defaultConfig()
	c.Xray.Bin = xray
	var all []Node
	for _, body := range []string{sampleSub(), extraLinks(), clashSample, singBoxSample, xrayJSONSample} {
		n, _ := parseSubscription(body, parseOpts{sockopt: map[string]any{"mark": 255}})
		all = append(all, n...)
	}
	good, bad := validateNodes(c, all)
	if len(bad) > 0 {
		t.Fatalf("Xray не принял %d из %d:\n%s", len(bad), len(all), strings.Join(bad, "\n"))
	}
	t.Logf("Xray принял все %d узлов", len(good))

	// заведомо битый узел отсеивается, остальные остаются
	broken := all[0]
	broken.Name = "битый"
	broken.Outbound = map[string]any{"tag": "node-bad", "protocol": "vless", "settings": map[string]any{"vnext": "x"}}
	good, bad = validateNodes(c, append([]Node{broken}, all[:3]...))
	if len(bad) != 1 || len(good) != 3 || !strings.Contains(bad[0], "битый") {
		t.Fatalf("good=%d bad=%v", len(good), bad)
	}
}
