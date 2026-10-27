package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Статистика узлов живёт в памяти, а копия — в watchdog.stats_file (по умолчанию
// в /tmp, то есть в оперативной памяти роутера). Флеш не изнашивается, но история
// переживает перезапуск самого xsub: сохранение настроек и самообновление делают
// syscall.Exec, и раньше после каждой правки настроек статистика начиналась с нуля.
// Перезагрузку роутера история не переживает — это и задумано.

const (
	slotDur   = 30 * time.Minute
	slotCount = 48 // сутки
)

type Slot struct {
	T    int64  `json:"t"` // начало получаса, unix
	OK   uint16 `json:"ok"`
	Fail uint16 `json:"fail"`
}

type NodeStats struct {
	Score    float64   `json:"score"` // 0..1, экспоненциальное среднее удачных проверок загрузкой
	OK       int       `json:"ok"`
	Fail     int       `json:"fail"`
	LastOK   time.Time `json:"last_ok"`
	LastFail time.Time `json:"last_fail"`
	LastTest time.Time `json:"last_test"` // последняя проверка загрузкой (любая)
	Slots    []Slot    `json:"slots"`

	Seen time.Time `json:"-"` // когда узел последний раз был в списке; по нему убираются сироты
}

const unknownScore = 0.75

func newStats() *NodeStats { return &NodeStats{Score: unknownScore, Seen: time.Now()} }

func (s *NodeStats) record(ok bool, now time.Time) {
	s.LastTest = now
	if ok {
		s.OK++
		s.LastOK = now
		s.Score = 0.8*s.Score + 0.2
	} else {
		s.Fail++
		s.LastFail = now
		s.Score = 0.8 * s.Score
	}
	addSlot(&s.Slots, ok, now)
}

func addSlot(slots *[]Slot, ok bool, now time.Time) {
	t := now.Truncate(slotDur).Unix()
	l := *slots
	if n := len(l); n == 0 || l[n-1].T != t {
		l = append(l, Slot{T: t})
	}
	if ok {
		l[len(l)-1].OK++
	} else {
		l[len(l)-1].Fail++
	}
	cut := now.Add(-slotDur * slotCount).Unix()
	for len(l) > 0 && l[0].T <= cut {
		l = l[1:]
	}
	*slots = l
}

// tier — грубая оценка надёжности: 0 — надёжный, 1 — так себе, 2 — ненадёжный.
func (s *NodeStats) tier() int {
	switch {
	case s == nil:
		return 1
	case s.Score >= 0.9:
		return 0
	case s.Score >= 0.6:
		return 1
	}
	return 2
}

// Event — запись в истории переключений и сбоев.
type Event struct {
	T    time.Time `json:"t"`
	Text string    `json:"text"`
	Kind string    `json:"kind"` // switch, down, up, heal, info
}

type eventLog struct {
	mu sync.Mutex
	l  []Event
}

func (e *eventLog) add(kind, text string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.l = append(e.l, Event{T: time.Now(), Text: text, Kind: kind})
	if len(e.l) > 200 {
		e.l = e.l[len(e.l)-200:]
	}
}

func (e *eventLog) list() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, len(e.l))
	copy(out, e.l)
	return out
}

var events = &eventLog{}

// statsDump — то, что кладётся в файл. Seen не сохраняется: после загрузки он
// ставится заново, иначе первый же setNodes счёл бы все узлы сиротами.
type statsDump struct {
	At    time.Time             `json:"at"`
	Nodes map[string]*NodeStats `json:"nodes"`
}

// saveStats кладёт историю проверок в файл: периодически и при остановке.
func (w *Watcher) saveStats() {
	path := w.c.Watch.StatsFile
	if path == "" {
		return
	}
	d := statsDump{At: time.Now(), Nodes: map[string]*NodeStats{}}
	w.mu.Lock()
	for tag, s := range w.stats {
		cp := *s
		cp.Slots = append([]Slot(nil), s.Slots...)
		d.Nodes[tag] = &cp
	}
	w.mu.Unlock()
	if len(d.Nodes) == 0 {
		return
	}
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	if err := writeAtomicMode(path, b, 0o600); err != nil {
		lg.Printf("история проверок не сохранена: %v", err)
	}
}

// loadStats поднимает историю прошлого запуска, если она не старше суток: за сутки
// получасовые засечки всё равно вытесняются целиком, а счётчики становятся враньём.
func (w *Watcher) loadStats() {
	path := w.c.Watch.StatsFile
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var d statsDump
	if json.Unmarshal(b, &d) != nil || len(d.Nodes) == 0 || time.Since(d.At) > slotDur*slotCount {
		return
	}
	now := time.Now()
	w.mu.Lock()
	for tag, s := range d.Nodes {
		if s == nil {
			continue
		}
		s.Seen = now
		w.stats[tag] = s
	}
	n := len(w.stats)
	w.mu.Unlock()
	lg.Printf("история проверок восстановлена: узлов %d, последняя запись %s", n, d.At.Format("15:04:05"))
}
