package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	routingFile = "05_routing.json"
	xsubFile    = "07_xsub.json"
	probeTag    = "xsub-probe"
	testPrefix  = "xsub-test-"
	ownDirect   = "xsub-direct"
)

// Lists — разобранные vpn.txt / direct.txt.
type Lists struct {
	VPNDomains, VPNIPs       []string
	DirectDomains, DirectIPs []string
}

// parseList переводит строки файла в правила Xray. Возвращает ошибки по строкам.
func parseList(text string) (domains, ips []string, errs []string) {
	for i, raw := range strings.Split(text, "\n") {
		line := raw
		if j := strings.Index(line, "#"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "ip:"):
			ips = append(ips, strings.TrimSpace(line[3:]))
		case strings.HasPrefix(low, "geoip:"):
			ips = append(ips, low)
		case strings.HasPrefix(low, "regexp:"), strings.HasPrefix(low, "ext:"):
			domains = append(domains, line) // регистр в regexp и именах файлов важен
		case strings.HasPrefix(low, "geosite:"), strings.HasPrefix(low, "domain:"),
			strings.HasPrefix(low, "full:"), strings.HasPrefix(low, "keyword:"):
			domains = append(domains, low)
		case strings.HasPrefix(line, "="):
			d := strings.TrimSpace(low[1:])
			if !validDomain(d) {
				errs = append(errs, fmt.Sprintf("строка %d: %q — не похоже на домен", i+1, raw))
				continue
			}
			domains = append(domains, "full:"+d)
		default:
			if _, _, err := net.ParseCIDR(line); err == nil {
				ips = append(ips, line)
				continue
			}
			if net.ParseIP(line) != nil {
				ips = append(ips, line)
				continue
			}
			d := strings.TrimPrefix(strings.TrimPrefix(low, "*."), ".")
			if !validDomain(d) {
				errs = append(errs, fmt.Sprintf("строка %d: %q — не похоже на домен", i+1, raw))
				continue
			}
			domains = append(domains, "domain:"+d)
		}
	}
	return
}

func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, r := range d {
		if !(r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 127) {
			return false
		}
	}
	return !strings.HasPrefix(d, ".") && !strings.HasSuffix(d, ".") && !strings.Contains(d, "..")
}

func readLists(c *Config) (Lists, []string, error) {
	var l Lists
	var errs []string
	vb, err := os.ReadFile(c.path("vpn.txt"))
	if err != nil && !os.IsNotExist(err) {
		return l, nil, err
	}
	db, err := os.ReadFile(c.path("direct.txt"))
	if err != nil && !os.IsNotExist(err) {
		return l, nil, err
	}
	var e1, e2 []string
	l.VPNDomains, l.VPNIPs, e1 = parseList(string(vb))
	l.DirectDomains, l.DirectIPs, e2 = parseList(string(db))
	for _, e := range e1 {
		errs = append(errs, "vpn.txt: "+e)
	}
	for _, e := range e2 {
		errs = append(errs, "direct.txt: "+e)
	}
	return l, errs, nil
}

func testTag(n Node) string { return testPrefix + strings.TrimPrefix(n.Tag, "node-") }

// Env — то, что уже есть в конфигах Xray помимо файлов xsub.
type Env struct {
	OutTags      map[string]string // tag -> protocol
	FirstFreedom string
	InTags       map[string]bool
	sockByTag    map[string]any
	anySockopt   any
	API          []string // файлы с секцией api
	Observatory  []string // файлы с observatory / burstObservatory
	LaterRouting []string // файлы с routing, читаемые после 05_routing.json
}

// scanEnv читает все *.json из папки конфигов (кроме файлов xsub).
func scanEnv(c *Config) (Env, error) {
	e := Env{OutTags: map[string]string{}, InTags: map[string]bool{}, sockByTag: map[string]any{}}
	files, _ := filepath.Glob(filepath.Join(c.Xray.ConfDir, "*.json"))
	sort.Strings(files)
	for _, f := range files {
		base := filepath.Base(f)
		if base == routingFile || base == xsubFile {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return e, err
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(stripJSONComments(b), &doc); err != nil {
			return e, fmt.Errorf("%s: %v", base, err)
		}
		if _, ok := doc["api"]; ok {
			e.API = append(e.API, base)
		}
		if _, ok := doc["observatory"]; ok {
			e.Observatory = append(e.Observatory, base)
		}
		if _, ok := doc["burstObservatory"]; ok {
			e.Observatory = append(e.Observatory, base)
		}
		if _, ok := doc["routing"]; ok && base > routingFile {
			e.LaterRouting = append(e.LaterRouting, base)
		}
		var outs []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Stream   struct {
				Sockopt any `json:"sockopt"`
			} `json:"streamSettings"`
		}
		if raw, ok := doc["outbounds"]; ok {
			_ = json.Unmarshal(raw, &outs)
		}
		for _, o := range outs {
			if o.Tag == "" {
				continue
			}
			e.OutTags[o.Tag] = o.Protocol
			if o.Protocol == "freedom" && e.FirstFreedom == "" {
				e.FirstFreedom = o.Tag
			}
			if o.Stream.Sockopt != nil {
				e.sockByTag[o.Tag] = o.Stream.Sockopt
				if e.anySockopt == nil && o.Protocol != "blackhole" {
					e.anySockopt = o.Stream.Sockopt
				}
			}
		}
		var ins []struct {
			Tag string `json:"tag"`
		}
		if raw, ok := doc["inbounds"]; ok {
			_ = json.Unmarshal(raw, &ins)
		}
		for _, in := range ins {
			if in.Tag != "" {
				e.InTags[in.Tag] = true
			}
		}
	}
	return e, nil
}

// Sockopt для узлов подписки: у template_tag, иначе у первого outbound, где он задан
// (XKeen помечает исходящий трафик ядра, чтобы он не заворачивался обратно).
func (e Env) Sockopt(c *Config) any {
	if c.Xray.TemplateTag != "" {
		if s, ok := e.sockByTag[c.Xray.TemplateTag]; ok {
			return s
		}
	}
	return e.anySockopt
}

func (e Env) directTag(c *Config) (tag string, own bool) {
	if p, ok := e.OutTags[c.Xray.DirectTag]; ok && p == "freedom" {
		return c.Xray.DirectTag, false
	}
	if e.FirstFreedom != "" {
		return e.FirstFreedom, false
	}
	return ownDirect, true
}

func (e Env) fallbackTag(c *Config) string {
	if c.Xray.FallbackTag == "" {
		return ""
	}
	if _, ok := e.OutTags[c.Xray.FallbackTag]; ok {
		return c.Xray.FallbackTag
	}
	return ""
}

// check — конфликты, при которых xsub не может безопасно управлять Xray.
func (e Env) check(c *Config) error {
	var errs []string
	if c.Xray.ManageAPI && len(e.API) > 0 {
		errs = append(errs, fmt.Sprintf("в %s уже есть секция api — xsub добавляет свою. Удалите её или задайте в config.json \"manage_api\": false и включите RoutingService на адресе %s",
			strings.Join(e.API, ", "), c.Xray.APIListen))
	}
	if len(e.Observatory) > 0 {
		errs = append(errs, fmt.Sprintf("в %s уже есть observatory — xsub нужен свой; удалите его оттуда", strings.Join(e.Observatory, ", ")))
	}
	if len(e.LaterRouting) > 0 {
		errs = append(errs, fmt.Sprintf("в %s есть секция routing, и она перекроет %s — перенесите правила в списки xsub", strings.Join(e.LaterRouting, ", "), routingFile))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
}

// generate собирает содержимое 05_routing.json и 07_xsub.json.
func generate(c *Config, env Env, nodes []Node, l Lists) (routing, xsub []byte, err error) {
	if err := env.check(c); err != nil {
		return nil, nil, err
	}
	x := c.Xray
	directTag, ownDir := env.directTag(c)
	fallback := env.fallbackTag(c)

	// Куда вести «VPN»-трафик: балансировщик по узлам подписки или запасной outbound.
	var target map[string]any
	switch {
	case len(nodes) > 0:
		target = map[string]any{"balancerTag": x.Balancer}
	case fallback != "":
		target = map[string]any{"outboundTag": fallback}
	}
	rule := func(match map[string]any, t map[string]any) map[string]any {
		r := map[string]any{"type": "field"}
		for k, v := range match {
			r[k] = v
		}
		for k, v := range t {
			r[k] = v
		}
		return r
	}
	direct := map[string]any{"outboundTag": directTag}

	var rules []any
	if target != nil {
		rules = append(rules, rule(map[string]any{"inboundTag": []string{probeTag}}, target))
	}
	for _, n := range nodes {
		rules = append(rules, rule(map[string]any{"inboundTag": []string{testTag(n)}}, map[string]any{"outboundTag": n.Tag}))
	}
	var force []string
	for _, t := range x.ForceProxyInbounds {
		if env.InTags[t] {
			force = append(force, t)
		}
	}
	if target != nil && len(force) > 0 {
		rules = append(rules, rule(map[string]any{"inboundTag": force}, target))
	}
	if len(l.DirectDomains) > 0 {
		rules = append(rules, rule(map[string]any{"domain": l.DirectDomains}, direct))
	}
	if len(l.DirectIPs) > 0 {
		rules = append(rules, rule(map[string]any{"ip": l.DirectIPs}, direct))
	}
	if target != nil && len(l.VPNDomains) > 0 {
		rules = append(rules, rule(map[string]any{"domain": l.VPNDomains}, target))
	}
	if target != nil && len(l.VPNIPs) > 0 {
		rules = append(rules, rule(map[string]any{"ip": l.VPNIPs}, target))
	}
	rules = append(rules, rule(map[string]any{"network": "tcp,udp"}, direct))

	rt := map[string]any{"domainStrategy": "AsIs", "rules": rules}
	if len(nodes) > 0 {
		bal := map[string]any{
			"tag":      x.Balancer,
			"selector": []string{"node-"},
			"strategy": map[string]any{"type": "leastPing"},
		}
		if fallback != "" {
			bal["fallbackTag"] = fallback
		}
		rt["balancers"] = []any{bal}
	}
	routing, err = marshal(map[string]any{"routing": rt})
	if err != nil {
		return
	}

	var inbounds, outbounds []any
	if target != nil {
		inbounds = append(inbounds, socksIn(probeTag, x.ProbePort))
	}
	for i, n := range nodes {
		inbounds = append(inbounds, socksIn(testTag(n), x.TestPortBase+i))
		outbounds = append(outbounds, n.Outbound)
	}
	if ownDir {
		ob := map[string]any{"tag": ownDirect, "protocol": "freedom"}
		if so := env.Sockopt(c); so != nil {
			ob["streamSettings"] = map[string]any{"sockopt": so}
		}
		outbounds = append(outbounds, ob)
	}
	doc := map[string]any{}
	if x.ManageAPI {
		doc["api"] = map[string]any{"tag": "xsub-api", "listen": x.APIListen, "services": []string{"RoutingService"}}
	}
	if len(inbounds) > 0 {
		doc["inbounds"] = inbounds
	}
	if len(outbounds) > 0 {
		doc["outbounds"] = outbounds
	}
	if len(nodes) > 0 {
		doc["observatory"] = map[string]any{
			"subjectSelector":   []string{"node-"},
			"probeURL":          x.ObservatoryURL,
			"probeInterval":     x.ObservatoryEvery,
			"enableConcurrency": true,
		}
	}
	xsub, err = marshal(doc)
	return
}

func socksIn(tag string, port int) map[string]any {
	return map[string]any{
		"tag":      tag,
		"listen":   "127.0.0.1",
		"port":     port,
		"protocol": "socks",
		"settings": map[string]any{"auth": "noauth", "udp": false},
	}
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
