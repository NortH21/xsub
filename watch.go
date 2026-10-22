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
	TestPort  int       `json:"test_port"`
	LatencyMs int       `json:"latency_ms"` // 0 — не проверялся, -1 — недоступен
	CheckedAt time.Time `json:"checked_at"`
	BadUntil  time.Time `json:"bad_until"`
	LastErr   string    `json:"last_err"`
}

type Watcher struct {
	c *Config

	mu         sync.Mutex
	nodes      []*NodeState
	active     string
	pinned     bool
	fails      int
	lastOK     time.Time
	lastSelect time.Time
	xrayStart  string
}

func newWatcher(c *Config) *Watcher { return &Watcher{c: c} }

// setNodes обновляет список узлов, сохраняя накопленное состояние совпадающих.
func (w *Watcher) setNodes(nodes []Node) {
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
		st.TestPort = w.c.Xray.TestPortBase + i
		ns = append(ns, st)
	}
	w.nodes = ns
	found := false
	for _, n := range ns {
		if n.Tag == w.active {
			found = true
		}
	}
	if !found {
		w.active, w.pinned = "", false
	}
}

func (w *Watcher) nodeName(tag string) string {
	for _, n := range w.nodes {
		if n.Tag == tag {
			return n.Name
		}
	}
	return tag
}

func socksClient(port int, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}),
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// realTest — реальная загрузка через указанный локальный вход Xray.
func (w *Watcher) realTest(port int) error {
	cl := socksClient(port, time.Duration(w.c.Watch.TimeoutSec)*time.Second)
	resp, err := cl.Get(w.c.Watch.TestURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, w.c.Watch.TestBytes))
	if n < w.c.Watch.TestBytes {
		if err == nil {
			err = fmt.Errorf("получено %d из %d байт", n, w.c.Watch.TestBytes)
		}
		return fmt.Errorf("обрыв на %d байтах: %v", n, err)
	}
	return nil
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
			} else {
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

// selectNode подбирает рабочий узел: сортировка по задержке, затем реальная загрузка.
// Вызывать под opMu.
func (w *Watcher) selectNode(reason string) {
	w.mu.Lock()
	w.lastSelect = time.Now()
	w.mu.Unlock()
	w.checkAll()

	w.mu.Lock()
	// Сначала узлы без отметки «залип», за ними — отмеченные (лучше они, чем ничего).
	var cands, badOnes []*NodeState
	now := time.Now()
	for _, n := range w.nodes {
		if n.LatencyMs <= 0 {
			continue
		}
		if now.After(n.BadUntil) {
			cands = append(cands, n)
		} else {
			badOnes = append(badOnes, n)
		}
	}
	byLat := func(l []*NodeState) {
		sort.Slice(l, func(i, j int) bool { return l[i].LatencyMs < l[j].LatencyMs })
	}
	byLat(cands)
	byLat(badOnes)
	cands = append(cands, badOnes...)
	prev := w.active
	w.mu.Unlock()

	tried := 0
	for _, n := range cands {
		if tried >= w.c.Watch.MaxTry {
			break
		}
		tried++
		if err := w.realTest(n.TestPort); err != nil {
			w.mu.Lock()
			n.LastErr = "загрузка: " + shortErr(err)
			w.mu.Unlock()
			continue
		}
		if err := w.override(n.Tag); err != nil {
			lg.Printf("не удалось переключить балансировщик: %v", err)
			return
		}
		w.mu.Lock()
		w.active, w.pinned, w.fails, w.lastOK = n.Tag, false, 0, time.Now()
		n.BadUntil, n.LastErr = time.Time{}, ""
		w.mu.Unlock()
		if prev != n.Tag {
			lg.Printf("%s: выбран «%s» (%d мс, проверено узлов: %d)", reason, n.Name, n.LatencyMs, tried)
		}
		return
	}
	_ = w.override("")
	w.mu.Lock()
	w.active, w.pinned = "", false
	w.mu.Unlock()
	lg.Printf("%s: рабочих узлов не нашлось (проверено: %d) — трафик идёт через автовыбор Xray", reason, tried)
}

// override закрепляет балансировщик за узлом (tag="" — снять закрепление).
func (w *Watcher) override(tag string) error {
	args := []string{"api", "bo", "-s", w.c.Xray.APIListen, "-b", w.c.Xray.Balancer}
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
func (w *Watcher) pin(tag string) error {
	w.mu.Lock()
	var n *NodeState
	for _, x := range w.nodes {
		if x.Tag == tag {
			n = x
		}
	}
	w.mu.Unlock()
	if n == nil {
		return fmt.Errorf("нет узла %s", tag)
	}
	if err := w.override(tag); err != nil {
		return err
	}
	w.mu.Lock()
	w.active, w.pinned, w.fails = tag, true, 0
	w.mu.Unlock()
	lg.Printf("вручную выбран «%s»", n.Name)
	return nil
}

// xrayStartTime — время старта процесса xray (меняется при перезапуске),
// чтобы заново закрепить узел после перезапуска.
func xrayStartTime(c *Config) string {
	name := filepath.Base(c.Xray.Bin)
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
	iv := time.Duration(w.c.Watch.IntervalSec) * time.Second
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !w.c.Watch.Enabled {
			continue
		}
		w.tick()
	}
}

func (w *Watcher) tick() {
	opMu.Lock()
	defer opMu.Unlock()

	st := xrayStartTime(w.c)
	if st == "" {
		return // xray не запущен — ждём
	}
	w.mu.Lock()
	active, pinned, nNodes := w.active, w.pinned, len(w.nodes)
	restarted := st != w.xrayStart
	since := time.Since(w.lastSelect)
	w.mu.Unlock()
	if nNodes == 0 {
		return
	}
	if active == "" {
		if since > 5*time.Minute {
			w.selectNode("поиск рабочего узла")
		}
		return
	}
	if restarted {
		time.Sleep(3 * time.Second)
		if err := w.override(active); err != nil {
			lg.Printf("xray перезапущен, не удалось вернуть узел «%s»: %v", w.nodeName(active), err)
			w.selectNode("после перезапуска Xray")
			return
		}
		lg.Printf("xray перезапущен — узел «%s» закреплён снова", w.nodeName(active))
	}

	err := w.realTest(w.c.Xray.ProbePort)
	if err != nil && w.internetOK() {
		// Закрепление могло пропасть (Xray перезапущен) — восстанавливаем и проверяем ещё раз.
		if oerr := w.override(active); oerr == nil {
			time.Sleep(2 * time.Second)
			if w.realTest(w.c.Xray.ProbePort) == nil {
				lg.Printf("закрепление узла «%s» восстановлено (Xray, видимо, перезапускался)", w.nodeName(active))
				err = nil
			}
		}
	} else if err != nil {
		return // нет интернета вообще — VPN не виноват
	}
	if err == nil {
		w.mu.Lock()
		w.fails, w.lastOK = 0, time.Now()
		w.mu.Unlock()
		return
	}
	w.mu.Lock()
	w.fails++
	fails := w.fails
	name := w.nodeName(active)
	w.mu.Unlock()
	lg.Printf("проверка не прошла (%d/%d), узел «%s»: %s", fails, w.c.Watch.FailsToSwitch, name, shortErr(err))
	if fails < w.c.Watch.FailsToSwitch {
		return
	}
	w.mu.Lock()
	for _, n := range w.nodes {
		if n.Tag == active {
			n.BadUntil = time.Now().Add(time.Duration(w.c.Watch.BadCooldownMin) * time.Minute)
			n.LastErr = "залип: " + shortErr(err)
		}
	}
	w.fails = 0
	w.mu.Unlock()
	if pinned {
		lg.Printf("вручную выбранный узел «%s» залип — снимаю ручной выбор", name)
	}
	w.selectNode(fmt.Sprintf("узел «%s» залип", name))
}

type Status struct {
	Active     string       `json:"active"`
	ActiveName string       `json:"active_name"`
	Pinned     bool         `json:"pinned"`
	Fails      int          `json:"fails"`
	LastOK     time.Time    `json:"last_ok"`
	XrayUp     bool         `json:"xray_up"`
	Nodes      []*NodeState `json:"nodes"`
}

func (w *Watcher) status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := Status{Active: w.active, ActiveName: w.nodeName(w.active), Pinned: w.pinned, Fails: w.fails, LastOK: w.lastOK, XrayUp: xrayStartTime(w.c) != ""}
	for _, n := range w.nodes {
		cp := *n
		s.Nodes = append(s.Nodes, &cp)
	}
	return s
}
