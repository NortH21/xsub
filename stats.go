package main

import (
	"sync"
	"time"
)

// Статистика узлов живёт только в памяти: после перезапуска xsub набирается заново
// (так ничего не пишется на флеш-память).

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
	Slots    []Slot    `json:"slots"`
}

const unknownScore = 0.75

func newStats() *NodeStats { return &NodeStats{Score: unknownScore} }

func (s *NodeStats) record(ok bool, now time.Time) {
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
