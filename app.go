package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type SubState struct {
	Name   string    `json:"name"`
	Nodes  int       `json:"nodes"`
	At     time.Time `json:"at"`
	Err    string    `json:"err"`
	Warns  []string  `json:"warns"`
	Info   *UserInfo `json:"info"`
	Cached bool      `json:"cached"` // узлы взяты из сохранённой копии
}

type App struct {
	c *Config
	w *Watcher

	mu       sync.Mutex
	subs     []Subscription
	states   map[string]*SubState // по URL
	nodes    []Node
	geoAt    time.Time
	geoErr   string
	applyErr string
	badNodes []string

	kick chan struct{} // внеочередное обновление подписок
}

func newApp(c *Config) (*App, error) {
	subs, err := loadSubs(c)
	if err != nil {
		return nil, err
	}
	return &App{c: c, w: newWatcher(c), subs: subs, states: map[string]*SubState{}, kick: make(chan struct{}, 1)}, nil
}

func subKey(u string) string {
	h := sha1.Sum([]byte(u))
	return hex.EncodeToString(h[:])[:12]
}

func (a *App) cachePath(u string) string { return a.c.path(filepath.Join("cache", subKey(u)+".txt")) }

func (a *App) parseSub(s Subscription, raw []byte, sockopt any, multi bool) ([]Node, []string) {
	o := parseOpts{sub: s.Name, sockopt: sockopt, maxNodes: a.c.MaxNodes}
	if s.Exclude != "" {
		o.exclude, _ = regexp.Compile(s.Exclude)
	}
	if s.Include != "" {
		o.include, _ = regexp.Compile(s.Include)
	}
	nodes, warns := parseSubscription(string(raw), o)
	if multi {
		for i := range nodes {
			nodes[i].Name = s.Name + " · " + nodes[i].Name
		}
	}
	return nodes, warns
}

func (a *App) sockopt() any {
	env, err := scanEnv(a.c)
	if err != nil {
		return nil
	}
	return env.Sockopt(a.c)
}

// afterRestart: Xray перезапущен — ждём его и закрепляем узел заново (или выбираем новый).
func (a *App) afterRestart(reason string) {
	for i := 0; i < 20 && xrayStartTime(a.c) == ""; i++ {
		time.Sleep(time.Second)
	}
	time.Sleep(3 * time.Second)
	a.w.mu.Lock()
	active := a.w.active
	a.w.mu.Unlock()
	if active != "" && a.w.override(active) == nil && a.w.realTest(a.c.Xray.ProbePort) == nil {
		return
	}
	a.w.selectNode(reason)
}

// apply — применить узлы и списки. Под opMu.
// Пока xsub ни разу не управлял Xray и узлов нет, конфиги не трогаем.
func (a *App) apply(nodes []Node, reason string, force bool) error {
	if !force && len(nodes) == 0 && !managed(a.c) {
		a.mu.Lock()
		a.nodes = nil
		a.mu.Unlock()
		a.w.setNodes(nil)
		return nil
	}
	good, bad := validateNodes(a.c, nodes)
	for _, b := range bad {
		lg.Printf("%s", b)
	}
	a.mu.Lock()
	a.badNodes = bad
	a.mu.Unlock()
	nodes = good
	changed, err := applyConfig(a.c, nodes, reason)
	a.mu.Lock()
	if err != nil {
		a.applyErr = err.Error()
	} else {
		a.applyErr = ""
		a.nodes = nodes
	}
	a.mu.Unlock()
	if err != nil {
		lg.Printf("конфиг не применён (%s): %v", reason, err)
		return err
	}
	a.w.setNodes(nodes)
	if changed && len(nodes) > 0 {
		a.afterRestart(reason)
	}
	return nil
}

// startup: geo-файлы, узлы из кэша, применение, выбор узла.
func (a *App) startup() {
	opMu.Lock()
	defer opMu.Unlock()
	a.updateGeoLocked(false)
	nodes := a.collect(false)
	a.mu.Lock()
	haveSubs := len(a.subs) > 0
	a.mu.Unlock()
	// Сохранённых копий нет, а подписки есть — их сейчас скачает subLoop; лишний перезапуск Xray не нужен.
	if len(nodes) > 0 || !haveSubs {
		_ = a.apply(nodes, "запуск", false)
	}
	if len(nodes) > 0 {
		a.w.mu.Lock()
		active := a.w.active
		a.w.mu.Unlock()
		if active == "" {
			a.w.selectNode("запуск")
		}
	}
}

// collect собирает узлы всех подписок: fetch=true — скачивает, иначе берёт сохранённые копии.
// Если подписка не скачалась, используется её сохранённая копия.
func (a *App) collect(fetch bool) []Node {
	a.mu.Lock()
	subs := append([]Subscription(nil), a.subs...)
	a.mu.Unlock()
	sock := a.sockopt()
	multi := len(subs) > 1
	var all []Node
	seen := map[string]bool{}
	newStates := map[string]*SubState{}
	for _, s := range subs {
		a.mu.Lock()
		prev := a.states[s.URL]
		a.mu.Unlock()
		st := &SubState{Name: s.Name}
		if prev != nil {
			st.At, st.Info = prev.At, prev.Info
		}
		var raw []byte
		if fetch {
			ua := s.UserAgent
			if ua == "" {
				ua = a.c.UserAgent
			}
			b, h, err := fetchURL(a.c, s.URL, ua, 8<<20)
			if err == nil {
				if n, w := a.parseSub(s, b, sock, false); len(n) == 0 {
					err = fmt.Errorf("в ответе нет подходящих узлов (проверьте ссылку, фильтры и user_agent)")
					st.Warns = w
				}
			}
			if err != nil {
				st.Err = err.Error()
				lg.Printf("подписка «%s» не обновлена: %v", s.Name, err)
			} else {
				raw = b
				st.At = time.Now()
				st.Info = parseUserInfo(h)
				_ = os.MkdirAll(a.c.path("cache"), 0o700)
				_ = writeAtomicMode(a.cachePath(s.URL), b, 0o600)
				if st.Info != nil {
					if ib, err := json.Marshal(st.Info); err == nil {
						_ = writeAtomicMode(strings.TrimSuffix(a.cachePath(s.URL), ".txt")+".info", ib, 0o600)
					}
				}
			}
		}
		if raw == nil {
			b, err := os.ReadFile(a.cachePath(s.URL))
			if err == nil {
				raw = b
				st.Cached = true
				if st.At.IsZero() {
					if fi, err := os.Stat(a.cachePath(s.URL)); err == nil {
						st.At = fi.ModTime()
					}
				}
				if st.Info == nil {
					if ib, err := os.ReadFile(strings.TrimSuffix(a.cachePath(s.URL), ".txt") + ".info"); err == nil {
						var ui UserInfo
						if json.Unmarshal(ib, &ui) == nil {
							st.Info = &ui
						}
					}
				}
			}
		}
		if raw != nil {
			nodes, warns := a.parseSub(s, raw, sock, multi)
			st.Warns = append(st.Warns, warns...)
			for _, n := range nodes {
				if seen[n.Tag] {
					continue
				}
				seen[n.Tag] = true
				all = append(all, n)
				st.Nodes++
			}
		}
		newStates[s.URL] = st
	}
	a.mu.Lock()
	a.states = newStates
	a.mu.Unlock()
	return all
}

// refreshSubs скачивает все подписки и применяет. Возвращает true, если какая-то не скачалась.
func (a *App) refreshSubs() (failed bool) {
	opMu.Lock()
	defer opMu.Unlock()
	nodes := a.collect(true)
	a.mu.Lock()
	for _, st := range a.states {
		if st.Err != "" {
			failed = true
		}
	}
	a.mu.Unlock()
	if err := a.apply(nodes, "обновление подписок", false); err != nil {
		return true
	}
	if len(nodes) > 0 {
		a.w.mu.Lock()
		active, recent := a.w.active, time.Since(a.w.lastSelect) < time.Minute
		a.w.mu.Unlock()
		if active == "" && !recent {
			a.w.selectNode("после обновления подписок")
		}
	}
	return failed
}

// subLoop обновляет подписки по расписанию; после неудачи — повтор через 10 минут.
func (a *App) subLoop(ctx context.Context) {
	for {
		failed := a.refreshSubs()
		d := time.Duration(a.c.SubIntervalHours) * time.Hour
		if failed {
			d = 10 * time.Minute
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-a.kick:
			t.Stop()
		}
	}
}

func (a *App) kickRefresh() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// saveSubs сохраняет список подписок с веб-страницы и запускает их обновление.
func (a *App) saveSubs(subs []Subscription) error {
	for i := range subs {
		subs[i].Name = strings.TrimSpace(subs[i].Name)
		subs[i].URL = strings.TrimSpace(subs[i].URL)
		subs[i].IntervalHours = 0
		if subs[i].Name == "" {
			subs[i].Name = fmt.Sprintf("Подписка %d", i+1)
		}
	}
	if err := validateSubs(subs); err != nil {
		return err
	}
	if err := saveSubsFile(a.c, subs); err != nil {
		return err
	}
	a.mu.Lock()
	a.subs = subs
	a.mu.Unlock()
	lg.Printf("список подписок сохранён: %d", len(subs))
	a.kickRefresh()
	return nil
}

// saveList сохраняет vpn.txt/direct.txt и применяет; при ошибке возвращает старый файл.
func (a *App) saveList(name, text string) error {
	if name != "vpn" && name != "direct" {
		return fmt.Errorf("нет списка %s", name)
	}
	if _, _, errs := parseList(text); len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	opMu.Lock()
	defer opMu.Unlock()
	p := a.c.path(name + ".txt")
	old, _ := os.ReadFile(p)
	if err := writeAtomic(p, []byte(text)); err != nil {
		return err
	}
	a.mu.Lock()
	nodes := a.nodes
	a.mu.Unlock()
	if err := a.apply(nodes, "изменён "+name+".txt", false); err != nil {
		_ = writeAtomic(p, old)
		return err
	}
	lg.Printf("сохранён %s.txt", name)
	return nil
}

func (a *App) updateGeo(force bool) {
	opMu.Lock()
	defer opMu.Unlock()
	a.updateGeoLocked(force)
}

// updateGeoLocked: при force=false качает только отсутствующие файлы.
func (a *App) updateGeoLocked(force bool) {
	var changed []string
	var errs []string
	for _, g := range a.c.Geo.Files {
		p := filepath.Join(a.c.Xray.AssetDir, g.Name)
		old, oerr := os.ReadFile(p)
		if !force && oerr == nil {
			continue
		}
		b, _, err := fetchURL(a.c, g.URL, "", 200<<20)
		if err == nil && len(b) < 1024 {
			err = fmt.Errorf("слишком маленький файл (%d байт)", len(b))
		}
		if err != nil {
			errs = append(errs, g.Name+": "+err.Error())
			continue
		}
		if bytes.Equal(old, b) {
			continue
		}
		if oerr == nil {
			_ = os.WriteFile(p+".bak", old, 0o644)
		}
		if err := writeAtomic(p, b); err != nil {
			errs = append(errs, g.Name+": "+err.Error())
			continue
		}
		changed = append(changed, p)
	}
	a.mu.Lock()
	a.geoAt = time.Now()
	a.geoErr = strings.Join(errs, "; ")
	a.mu.Unlock()
	if len(errs) > 0 {
		lg.Printf("geo-файлы: %s", strings.Join(errs, "; "))
	}
	if len(changed) == 0 || xrayStartTime(a.c) == "" {
		return
	}
	if err := xrayTest(a.c, a.c.Xray.ConfDir); err != nil {
		lg.Printf("новые geo-файлы не прошли проверку, возвращаю старые: %v", err)
		for _, p := range changed {
			if b, e := os.ReadFile(p + ".bak"); e == nil {
				_ = writeAtomic(p, b)
			}
		}
		return
	}
	lg.Printf("geo-файлы обновлены: %d — перезапускаю Xray", len(changed))
	if err := restartXray(a.c); err != nil {
		lg.Printf("ошибка перезапуска: %v", err)
		return
	}
	if len(a.w.status().Nodes) > 0 {
		a.afterRestart("после обновления geo")
	}
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

type AppStatus struct {
	Status
	Version  string         `json:"version"`
	Subs     []SubStatusOut `json:"subs"`
	GeoAt    time.Time      `json:"geo_at"`
	GeoErr   string         `json:"geo_err"`
	ApplyErr string         `json:"apply_err"`
	BadNodes []string       `json:"bad_nodes"`
	Managed  bool           `json:"managed"`
	Log      []string       `json:"log"`
}

type SubStatusOut struct {
	Subscription
	State *SubState `json:"state"`
}

func (a *App) status() AppStatus {
	s := AppStatus{Status: a.w.status(), Version: version, Managed: managed(a.c)}
	a.mu.Lock()
	for _, sub := range a.subs {
		s.Subs = append(s.Subs, SubStatusOut{Subscription: sub, State: a.states[sub.URL]})
	}
	s.GeoAt, s.GeoErr, s.ApplyErr = a.geoAt, a.geoErr, a.applyErr
	s.BadNodes = a.badNodes
	a.mu.Unlock()
	s.Log = lg.Tail(80)
	return s
}
