package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Fallback — резервный узел, которым управляет xsub. Включается, когда не работает
// ни один узел подписок. Задаётся ссылкой (как в подписке) или готовым outbound Xray
// (так переносятся резервы из конфигов XKeen).
type Fallback struct {
	Name     string         `json:"name"`
	Link     string         `json:"link,omitempty"`
	Outbound map[string]any `json:"outbound,omitempty"`
	// Import — тег outbound из конфигов Xray, который нужно перенести сюда (только при сохранении со страницы).
	Import string `json:"import,omitempty"`
}

const (
	fallbacksFile = "fallbacks.json"
	maxFallbacks  = 10
	fbPrefix      = "fb-"
)

func isFallbackTag(tag string) bool { return strings.HasPrefix(tag, fbPrefix) }

func loadFallbacks(c *Config) ([]Fallback, error) {
	b, err := os.ReadFile(c.path(fallbacksFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var fbs []Fallback
	if err := json.Unmarshal(b, &fbs); err != nil {
		return nil, fmt.Errorf("%s: %w", fallbacksFile, err)
	}
	return fbs, nil
}

func saveFallbacksFile(c *Config, fbs []Fallback) error {
	if fbs == nil {
		fbs = []Fallback{}
	}
	b, err := marshal(fbs)
	if err != nil {
		return err
	}
	return writeAtomicMode(c.path(fallbacksFile), b, 0o600)
}

// fallbackNode переводит резерв в узел Xray с тегом fb-….
func fallbackNode(f Fallback, sockopt any) (Node, error) {
	var n Node
	var err error
	switch {
	case strings.TrimSpace(f.Link) != "":
		n, err = parseLink(strings.TrimSpace(f.Link), sockopt)
		if err == errInfoNode {
			err = fmt.Errorf("в ссылке нет адреса сервера")
		}
		if err == nil {
			h := sha1.Sum([]byte(f.Link))
			n.Tag = fbPrefix + hex.EncodeToString(h[:])[:8]
			n.Outbound["tag"] = n.Tag
		}
	case f.Outbound != nil:
		n, err = outboundNode(copyMap(f.Outbound), f.Name, sockopt, fbPrefix)
		if err == errInfoNode {
			err = fmt.Errorf("в outbound нет адреса сервера")
		}
	default:
		err = fmt.Errorf("нужна ссылка")
	}
	if err != nil {
		return Node{}, err
	}
	if strings.TrimSpace(f.Name) != "" {
		n.Name = strings.TrimSpace(f.Name)
	}
	n.Sub = "резерв"
	return n, nil
}

// fallbackNodes — все резервы в порядке приоритета; неразобранные пропускаются с предупреждением.
func fallbackNodes(c *Config, sockopt any) ([]Node, []string) {
	fbs, err := loadFallbacks(c)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var nodes []Node
	var warns []string
	seen := map[string]bool{}
	for i, f := range fbs {
		n, err := fallbackNode(f, sockopt)
		if err != nil {
			warns = append(warns, fmt.Sprintf("резерв «%s»: %v", firstNonEmpty(f.Name, fmt.Sprint(i+1)), err))
			continue
		}
		if seen[n.Tag] {
			continue
		}
		seen[n.Tag] = true
		nodes = append(nodes, n)
	}
	return nodes, warns
}

// prepareFallbacks проверяет список со страницы и подставляет outbound'ы для переноса из конфигов Xray.
func prepareFallbacks(c *Config, fbs []Fallback) ([]Fallback, error) {
	if len(fbs) > maxFallbacks {
		return nil, fmt.Errorf("резервов не больше %d", maxFallbacks)
	}
	env, err := scanEnv(c)
	if err != nil {
		return nil, err
	}
	out := make([]Fallback, 0, len(fbs))
	for i, f := range fbs {
		f.Name = strings.TrimSpace(f.Name)
		f.Link = strings.TrimSpace(f.Link)
		if f.Import != "" {
			raw, ok := env.RawOut[f.Import]
			if !ok {
				return nil, fmt.Errorf("в конфигах Xray нет outbound %q", f.Import)
			}
			ob := copyMap(raw)
			delete(ob, "tag")
			f.Outbound, f.Link = ob, ""
			if f.Name == "" {
				f.Name = f.Import
			}
			f.Import = ""
		}
		if f.Name == "" {
			f.Name = fmt.Sprintf("Резерв %d", i+1)
		}
		if _, err := fallbackNode(f, nil); err != nil {
			return nil, fmt.Errorf("резерв «%s»: %v", f.Name, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// sameOutbound — outbound'ы совпадают без учёта тега (чтобы показать «уже перенесён»).
func sameOutbound(a, b map[string]any) bool {
	strip := func(m map[string]any) string {
		cp := map[string]any{}
		for k, v := range m {
			if k != "tag" {
				cp[k] = v
			}
		}
		s, _ := json.Marshal(cp)
		return string(s)
	}
	return strip(a) == strip(b)
}

type FallbackView struct {
	Fallback
	Tag     string `json:"tag"`
	Summary string `json:"summary"`
	Err     string `json:"err,omitempty"`
}

type ImportCandidate struct {
	Tag      string `json:"tag"`
	Summary  string `json:"summary"`
	Imported bool   `json:"imported"`
	Legacy   bool   `json:"legacy"` // указан в xray.fallback_tag
}

func nodeSummary(n Node) string {
	if n.Address == "" {
		return n.Proto
	}
	return fmt.Sprintf("%s %s:%d", n.Proto, n.Address, n.Port)
}

// uiFallbacks — резервы для страницы и outbound'ы из конфигов Xray, которые можно перенести.
func (a *App) uiFallbacks() map[string]any {
	fbs, err := loadFallbacks(a.c)
	views := []FallbackView{}
	for _, f := range fbs {
		v := FallbackView{Fallback: f}
		if n, err := fallbackNode(f, nil); err != nil {
			v.Err = err.Error()
		} else {
			v.Tag, v.Summary = n.Tag, nodeSummary(n)
		}
		views = append(views, v)
	}
	cands := []ImportCandidate{}
	env, _ := scanEnv(a.c)
	var tags []string
	for t := range env.RawOut {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	for _, t := range tags {
		ob := env.RawOut[t]
		if !xrayProxyProtocols[anyStr(ob["protocol"])] || strings.HasPrefix(t, "node-") || isFallbackTag(t) || strings.HasPrefix(t, "xsub-") {
			continue
		}
		ic := ImportCandidate{Tag: t, Legacy: t == a.c.Xray.FallbackTag && len(fbs) == 0}
		if n, err := outboundNode(copyMap(ob), t, nil, fbPrefix); err == nil {
			ic.Summary = nodeSummary(n)
		} else {
			ic.Summary = err.Error()
		}
		for _, f := range fbs {
			if f.Outbound != nil && sameOutbound(f.Outbound, ob) {
				ic.Imported = true
			}
		}
		cands = append(cands, ic)
	}
	res := map[string]any{"fallbacks": views, "imports": cands}
	if err != nil {
		res["error"] = err.Error()
	}
	return res
}

func copyMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// saveFallbacks сохраняет резервы и применяет конфиг; при ошибке возвращает прежний список.
func (a *App) saveFallbacks(in []Fallback) error {
	fbs, err := prepareFallbacks(a.c, in)
	if err != nil {
		return err
	}
	opMu.Lock()
	defer opMu.Unlock()
	old, _ := loadFallbacks(a.c)
	if err := saveFallbacksFile(a.c, fbs); err != nil {
		return err
	}
	a.mu.Lock()
	nodes := a.nodes
	a.mu.Unlock()
	if err := a.apply(nodes, "изменены резервные узлы", false); err != nil {
		_ = saveFallbacksFile(a.c, old)
		return err
	}
	lg.Printf("резервные узлы сохранены: %d", len(fbs))
	return nil
}
