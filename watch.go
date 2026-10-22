package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type NodeState struct {
	Node
	TestPort  int        `json:"test_port"`
	LatencyMs int        `json:"latency_ms"` // 0 — не проверялся, -1 — недоступен
	CheckedAt time.Time  `json:"checked_at"`
	BadUntil  time.Time  `json:"bad_until"`
	LastErr   string     `json:"last_err"`
	Stats     *NodeStats `json:"stats"`
}

// Target — то, за чем следит сторож: основной балансировщик или балансировщик группы.
type Target struct {
	TargetDef
	tags       map[string]bool
	Active     string
	Pinned     bool
	Fails      int
	LastOK     time.Time
	Down       bool
	lastSelect time.Time
	Slots      []Slot // доступность цели по получасам
}

func (t *Target) has(tag string) bool { return t.tags == nil || t.tags[tag] }

func (t *Target) where() string {
	if t.ID == "" {
		return ""
	}
	return " [" + t.Name + "]"
}

type Watcher struct {
	c *Config

	mu        sync.Mutex
	nodes     []*NodeState
	targets   []*Target
	stats     map[string]*NodeStats // переживает обновление подписки
	xrayStart string
	bgIdx     int
	lastBg    time.Time

	notify func(key, text string) // уведомления (Telegram); может быть nil
}

func newWatcher(c *Config) *Watcher { return &Watcher{c: c, stats: map[string]*NodeStats{}} }

// say пишет в журнал, в историю и (если key не пустой) отправляет уведомление.
func (w *Watcher) say(key, kind, text string) {
	lg.Printf("%s", text)
	events.add(kind, text)
	if w.notify != nil && key != "" {
		w.notify(key, text)
	}
}

// setNodes обновляет узлы и цели, сохраняя накопленное состояние.
func (w *Watcher) setNodes(nodes []Node, defs []TargetDef) {
	w.mu.Lock()
	defer w.mu.Unlock()
	old := map[string]*NodeState{}
	for _, n := range w.nodes {
		old[n.Tag] = n
	}
	var ns []*NodeState
	for i, n := range nodes {
		st := &NodeState{Node: n}
		if o, ok := old[n.Tag]; ok {
			st.LatencyMs, st.CheckedAt, st.BadUntil, st.LastErr = o.LatencyMs, o.CheckedAt, o.BadUntil, o.LastErr
		}
		if w.stats[n.Tag] == nil {
			w.stats[n.Tag] = newStats()
		}
		st.Stats = w.stats[n.Tag]
		st.TestPort = w.c.Xray.TestPortBase + i
		ns = append(ns, st)
	}
	w.nodes = ns

	oldT := map[string]*Target{}
	for _, t := range w.targets {
		oldT[t.ID] = t
	}
	var ts []*Target
	for _, d := range defs {
		if len(ns) == 0 || (d.ID != "" && d.Empty) {
			continue // у группы нет узлов — её трафик идёт основной целью
		}
		t := &Target{TargetDef: d}
		if d.Tags != nil {
			t.tags = map[string]bool{}
			for _, tag := range d.Tags {
				t.tags[tag] = true
			}
		}
		if o, ok := oldT[d.ID]; ok {
			t.Active, t.Pinned, t.Fails, t.LastOK, t.Down, t.lastSelect, t.Slots = o.Active, o.Pinned, o.Fails, o.LastOK, o.Down, o.lastSelect, o.Slots
		}
		if t.Active != "" && (!t.has(t.Active) || w.find(t.Active) == nil) {
			t.Active, t.Pinned = "", false
		}
		ts = append(ts, t)
	}
	w.targets = ts
}

func (w *Watcher) find(tag string) *NodeState {
	for _, n := range w.nodes {
		if n.Tag == tag {
			return n
		}
	}
	return nil
}

func (w *Watcher) target(id string) *Target {
	for _, t := range w.targets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (w *Watcher) nodeName(tag string) string {
	if n := w.find(tag); n != nil {
		return n.Name
	}
	return tag
}

func (w *Watcher) record(tag string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s := w.stats[tag]; s != nil {
		s.record(ok, time.Now())
	}
}

func (w *Watcher) allTargets() []*Target {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*Target(nil), w.targets...)
}

func socksClient(port int, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}),
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// realTest — реальная загрузка через локальный вход Xray плюс открытие адресов из check_urls.
func (w *Watcher) realTest(port int) error {
	cl := socksClient(port, time.Duration(w.c.Watch.TimeoutSec)*time.Second)
	resp, err := cl.Get(w.c.Watch.TestURL)
	if err != nil {
		return err
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, w.c.Watch.TestBytes))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if n < w.c.Watch.TestBytes {
		if err == nil {
			err = fmt.Errorf("получено %d из %d байт", n, w.c.Watch.TestBytes)
		}
		return fmt.Errorf("обрыв на %d байтах: %v", n, err)
	}
	for _, u := range w.c.Watch.CheckURLs {
		resp, err := cl.Get(u)
		if err != nil {
			return fmt.Errorf("%s не открывается: %s", hostOf(u), shortErr(err))
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		resp.Body.Close()
	}
	return nil
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}

func (w *Watcher) latency(port int) (int, error) {
	cl := socksClient(port, 5*time.Second)
	start := time.Now()
	resp, err := cl.Get(w.c.Watch.LatencyURL)
	if err != nil {
		return -1, err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return -1, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return int(time.Since(start).Milliseconds()), nil
}

func (w *Watcher) internetOK() bool {
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	for _, u := range w.c.Watch.DirectURLs {
		if resp, err := cl.Get(u); err == nil {
			resp.Body.Close()
			return true
		}
	}
	return false
}

// checkAll меряет задержку всех узлов параллельно (по 4 сразу).
func (w *Watcher) checkAll() {
	w.mu.Lock()
	nodes := append([]*NodeState(nil), w.nodes...)
	w.mu.Unlock()
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n *NodeState) {
			defer wg.Done()
			defer func() { <-sem }()
			ms, err := w.latency(n.TestPort)
			w.mu.Lock()
			n.LatencyMs, n.CheckedAt = ms, time.Now()
			if err != nil {
				n.LastErr = shortErr(err)
			} else if !strings.HasPrefix(n.LastErr, "залип") {
				n.LastErr = ""
			}
			w.mu.Unlock()
		}(n)
	}
	wg.Wait()
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}

// rank: сначала не помеченные «залип», затем по надёжности (история проверок), затем по задержке.
func rank(cands []*NodeState, now time.Time) {
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		ab, bb := now.Before(a.BadUntil), now.Before(b.BadUntil)
		if ab != bb {
			return !ab
		}
		if ta, tb := a.Stats.tier(), b.Stats.tier(); ta != tb {
			return ta < tb
		}
		return a.LatencyMs < b.LatencyMs
	})
}

// selectNode подбирает рабочий узел для цели. Вызывать под opMu.
func (w *Watcher) selectNode(t *Target, reason string) {
	w.mu.Lock()
	t.lastSelect = time.Now()
	w.mu.Unlock()
	w.checkAll()

	w.mu.Lock()
	var cands []*NodeState
	for _, n := range w.nodes {
		if n.LatencyMs > 0 && t.has(n.Tag) {
			cands = append(cands, n)
		}
	}
	rank(cands, time.Now())
	prev := t.Active
	w.mu.Unlock()

	tried := 0
	for _, n := range cands {
		if tried >= w.c.Watch.MaxTry {
			break
		}
		tried++
		err := w.realTest(n.TestPort)
		w.record(n.Tag, err == nil)
		if err != nil {
			w.mu.Lock()
			n.LastErr = "загрузка: " + shortErr(err)
			w.mu.Unlock()
			continue
		}
		if err := w.override(t.Balancer, n.Tag); err != nil {
			lg.Printf("не удалось переключить балансировщик %s: %v", t.Balancer, err)
			return
		}
		w.mu.Lock()
		wasDown := t.Down
		t.Active, t.Pinned, t.Fails, t.LastOK, t.Down = n.Tag, false, 0, time.Now(), false
		n.BadUntil, n.LastErr = time.Time{}, ""
		w.mu.Unlock()
		switch {
		case wasDown:
			w.say("up"+t.ID, "up", fmt.Sprintf("%s%s: связь восстановлена через «%s»", reason, t.where(), n.Name))
		case prev != "" && prev != n.Tag:
			w.say("switch"+t.ID, "switch", fmt.Sprintf("%s%s: переключено на «%s» (%d мс)", reason, t.where(), n.Name, n.LatencyMs))
		case prev != n.Tag:
			w.say("", "info", fmt.Sprintf("%s%s: выбран «%s» (%d мс, проверено узлов: %d)", reason, t.where(), n.Name, n.LatencyMs, tried))
		}
		return
	}
	_ = w.override(t.Balancer, "")
	w.mu.Lock()
	wasDown := t.Down
	t.Active, t.Pinned, t.Down = "", false, true
	w.mu.Unlock()
	if !wasDown {
		w.say("down"+t.ID, "down", fmt.Sprintf("%s%s: рабочих узлов не нашлось (проверено: %d) — трафик идёт через автовыбор Xray", reason, t.where(), tried))
	}
}

// override закрепляет балансировщик за узлом (tag="" — снять закрепление).
func (w *Watcher) override(balancer, tag string) error {
	args := []string{"api", "bo", "-s", w.c.Xray.APIListen, "-b", balancer}
	if tag == "" {
		args = append(args, "-r")
	} else {
		args = append(args, tag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := runCmd(ctx, nil, w.c.Xray.Bin, args...)
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(tail(out, 2)))
	}
	w.mu.Lock()
	w.xrayStart = xrayStartTime(w.c)
	w.mu.Unlock()
	return nil
}

// pin — ручной выбор узла с веб-страницы.
func (w *Watcher) pin(targetID, tag string) error {
	w.mu.Lock()
	t := w.target(targetID)
	n := w.find(tag)
	ok := t != nil && n != nil && t.has(tag)
	w.mu.Unlock()
	if !ok {
		return fmt.Errorf("нет такого узла в этой группе")
	}
	if err := w.override(t.Balancer, tag); err != nil {
		return err
	}
	w.mu.Lock()
	t.Active, t.Pinned, t.Fails, t.Down = tag, true, 0, false
	w.mu.Unlock()
	w.say("", "info", fmt.Sprintf("вручную выбран «%s»%s", n.Name, t.where()))
	return nil
}

// reselect — автовыбор для всех целей. Под opMu.
func (w *Watcher) reselect(reason string) {
	for _, t := range w.allTargets() {
		w.selectNode(t, reason)
	}
}

// selectMissing — выбрать узлы для целей, у которых их ещё нет. Под opMu.
func (w *Watcher) selectMissing(reason string) {
	for _, t := range w.allTargets() {
		w.mu.Lock()
		need := t.Active == "" && time.Since(t.lastSelect) > time.Minute
		w.mu.Unlock()
		if need {
			w.selectNode(t, reason)
		}
	}
}

// repin закрепляет выбранные узлы заново (после перезапуска Xray закрепления сбрасываются).
// Цели, чей узел закрепить не удалось или он не работает, получают новый узел.
func (w *Watcher) repin(reason string) {
	for _, t := range w.allTargets() {
		w.mu.Lock()
		active := t.Active
		w.mu.Unlock()
		if active != "" && w.override(t.Balancer, active) == nil && w.realTest(t.ProbePort) == nil {
			continue
		}
		w.selectNode(t, reason)
	}
}

// xrayStartTime — отпечаток запущенных процессов ядра (меняется при перезапуске).
func xrayStartTime(c *Config) string { return procStamp(filepath.Base(c.Xray.Bin)) }

func procStamp(name string) string {
	if len(name) > 15 {
		name = name[:15] // /proc/*/comm обрезается до 15 символов
	}
	var marks []string
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		comm, err := os.ReadFile(d + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != name {
			continue
		}
		st, err := os.ReadFile(d + "/stat")
		if err != nil {
			continue
		}
		s := string(st)
		if i := strings.LastIndex(s, ")"); i > 0 {
			f := strings.Fields(s[i+1:])
			if len(f) > 19 {
				marks = append(marks, filepath.Base(d)+":"+f[19])
			}
		}
	}
	sort.Strings(marks)
	return strings.Join(marks, ",")
}

func (w *Watcher) loop(ctx context.Context) {
	t := time.NewTicker(time.Duration(w.c.Watch.IntervalSec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if w.c.Watch.Enabled {
			w.tick()
		}
	}
}

func (w *Watcher) tick() {
	opMu.Lock()
	defer opMu.Unlock()
	st := xrayStartTime(w.c)
	if st == "" {
		return // ядро не запущено — этим занимается самовосстановление
	}
	w.mu.Lock()
	restarted := st != w.xrayStart
	w.mu.Unlock()
	if len(w.allTargets()) == 0 {
		return
	}
	if restarted {
		time.Sleep(3 * time.Second)
		lg.Printf("Xray перезапущен — закрепляю выбранные узлы снова")
		w.repin("после перезапуска Xray")
	}
	for _, t := range w.allTargets() {
		w.checkTarget(t)
	}
	w.background()
}

func (w *Watcher) checkTarget(t *Target) {
	w.mu.Lock()
	active, pinned, since := t.Active, t.Pinned, time.Since(t.lastSelect)
	w.mu.Unlock()
	if active == "" {
		if since > 5*time.Minute {
			w.selectNode(t, "поиск рабочего узла")
		}
		return
	}
	err := w.realTest(t.ProbePort)
	if err != nil {
		if !w.internetOK() {
			return // нет интернета вообще — VPN не виноват
		}
		// Закрепление могло пропасть (Xray перезапускался) — восстанавливаем и проверяем ещё раз.
		if w.override(t.Balancer, active) == nil {
			time.Sleep(2 * time.Second)
			if w.realTest(t.ProbePort) == nil {
				err = nil
			}
		}
	}
	w.record(active, err == nil)
	w.mu.Lock()
	addSlot(&t.Slots, err == nil, time.Now())
	if err == nil {
		t.Fails, t.LastOK = 0, time.Now()
		w.mu.Unlock()
		return
	}
	t.Fails++
	fails := t.Fails
	name := w.nodeName(active)
	w.mu.Unlock()
	lg.Printf("проверка не прошла (%d/%d), узел «%s»%s: %s", fails, w.c.Watch.FailsToSwitch, name, t.where(), shortErr(err))
	if fails < w.c.Watch.FailsToSwitch {
		return
	}
	w.mu.Lock()
	if n := w.find(active); n != nil {
		n.BadUntil = time.Now().Add(time.Duration(w.c.Watch.BadCooldownMin) * time.Minute)
		n.LastErr = "залип: " + shortErr(err)
	}
	t.Fails = 0
	w.mu.Unlock()
	if pinned {
		lg.Printf("вручную выбранный узел «%s» залип — снимаю ручной выбор", name)
	}
	w.selectNode(t, fmt.Sprintf("узел «%s» залип", name))
}

// background по очереди проверяет загрузкой узлы, которые сейчас не активны,
// чтобы у каждого копилась история и при сбое выбирался проверенный узел.
func (w *Watcher) background() {
	every := time.Duration(w.c.Watch.BackgroundProbeMin) * time.Minute
	if every <= 0 || time.Since(w.lastBg) < every {
		return
	}
	w.mu.Lock()
	w.lastBg = time.Now()
	active := map[string]bool{}
	for _, t := range w.targets {
		active[t.Active] = true
	}
	var pick *NodeState
	for i := 0; i < len(w.nodes); i++ {
		n := w.nodes[(w.bgIdx+i)%len(w.nodes)]
		if !active[n.Tag] {
			pick = n
			w.bgIdx = (w.bgIdx + i + 1) % len(w.nodes)
			break
		}
	}
	w.mu.Unlock()
	if pick == nil {
		return
	}
	err := w.realTest(pick.TestPort)
	w.record(pick.Tag, err == nil)
	w.mu.Lock()
	if err != nil {
		pick.LastErr = "фоновая проверка: " + shortErr(err)
	} else if strings.HasPrefix(pick.LastErr, "фоновая проверка") || strings.HasPrefix(pick.LastErr, "загрузка") {
		pick.LastErr = ""
	}
	w.mu.Unlock()
}

type TargetStatus struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Active     string    `json:"active"`
	ActiveName string    `json:"active_name"`
	Pinned     bool      `json:"pinned"`
	Down       bool      `json:"down"`
	LastOK     time.Time `json:"last_ok"`
	Tags       []string  `json:"tags"`
	Slots      []Slot    `json:"slots"`
}

type Status struct {
	Targets []TargetStatus `json:"targets"`
	XrayUp  bool           `json:"xray_up"`
	Nodes   []*NodeState   `json:"nodes"`
}

func (w *Watcher) status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := Status{XrayUp: xrayStartTime(w.c) != ""}
	for _, t := range w.targets {
		s.Targets = append(s.Targets, TargetStatus{
			ID: t.ID, Name: t.Name, Active: t.Active, ActiveName: w.nodeName(t.Active), Pinned: t.Pinned,
			Down: t.Down, LastOK: t.LastOK, Tags: t.Tags, Slots: append([]Slot(nil), t.Slots...),
		})
	}
	for _, n := range w.nodes {
		cp := *n
		if n.Stats != nil {
			sc := *n.Stats
			sc.Slots = append([]Slot(nil), n.Stats.Slots...)
			cp.Stats = &sc
		}
		s.Nodes = append(s.Nodes, &cp)
	}
	return s
}
