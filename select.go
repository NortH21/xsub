// Выбор узла для цели: ранжирование, переключение, резервы, ручной выбор.

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

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
		case isFallbackTag(prev):
			w.say("up"+t.ID, "up", fmt.Sprintf("%s%s: узлы подписки снова работают — выбран «%s»", reason, t.where(), n.Name))
		case wasDown:
			w.say("up"+t.ID, "up", fmt.Sprintf("%s%s: связь восстановлена через «%s»", reason, t.where(), n.Name))
		case prev != "" && prev != n.Tag:
			w.say("switch"+t.ID, "switch", fmt.Sprintf("%s%s: переключено на «%s» (%d мс)", reason, t.where(), n.Name, n.LatencyMs))
		case prev != n.Tag:
			w.say("", "info", fmt.Sprintf("%s%s: выбран «%s» (%d мс, проверено узлов: %d)", reason, t.where(), n.Name, n.LatencyMs, tried))
		}
		return
	}
	if w.tryFallbacks(t, prev, reason, tried) {
		return
	}
	_ = w.override(t.Balancer, "")
	w.mu.Lock()
	wasDown := t.Down
	t.Active, t.Pinned, t.Down = "", false, true
	w.mu.Unlock()
	if !wasDown || isFallbackTag(prev) {
		w.say("down"+t.ID, "down", fmt.Sprintf("%s%s: рабочих узлов не нашлось (проверено: %d) — трафик идёт через автовыбор Xray", reason, t.where(), tried))
	}
}

// tryFallbacks — ни один узел подписок не работает: пробуем резервы по порядку.
func (w *Watcher) tryFallbacks(t *Target, prev, reason string, tried int) bool {
	w.mu.Lock()
	fbs := append([]*NodeState(nil), w.fbs...)
	w.mu.Unlock()
	for _, n := range fbs {
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
			return true
		}
		w.mu.Lock()
		t.Active, t.Pinned, t.Fails, t.LastOK, t.Down = n.Tag, false, 0, time.Now(), false
		n.BadUntil, n.LastErr = time.Time{}, ""
		w.mu.Unlock()
		if prev != n.Tag {
			if isFallbackTag(prev) {
				w.say("switch"+t.ID, "switch", fmt.Sprintf("%s%s: переключено на резерв «%s»", reason, t.where(), n.Name))
			} else {
				w.say("down"+t.ID, "down", fmt.Sprintf("%s%s: рабочих узлов подписок не нашлось (проверено: %d) — работаю через резерв «%s»", reason, t.where(), tried, n.Name))
			}
		}
		return true
	}
	return false
}

// faster ищет узел, ради скорости которого стоит переключиться: проверка загрузкой
// на нём прошла, надёжность не хуже текущего, а задержка меньше на switch_faster_ms
// и больше. Резервы не рассматриваются — они только на случай, когда не работает
// ничего. Под w.mu.
func (w *Watcher) faster(t *Target) *NodeState {
	gain := w.c.Watch.SwitchFasterMs
	if gain <= 0 || t.Pinned || t.Active == "" || isFallbackTag(t.Active) {
		return nil
	}
	cur := w.find(t.Active)
	if cur == nil || cur.LatencyMs <= 0 {
		return nil
	}
	now, best := time.Now(), cur
	for _, n := range w.nodes {
		if n.Tag == cur.Tag || !t.has(n.Tag) || n.LatencyMs <= 0 || now.Before(n.BadUntil) {
			continue
		}
		// Последняя проверка загрузкой должна быть удачной, иначе узел «быстрый», но нерабочий.
		if !n.Stats.LastOK.After(n.Stats.LastFail) || n.Stats.tier() > cur.Stats.tier() {
			continue
		}
		if cur.LatencyMs-n.LatencyMs >= gain && n.LatencyMs < best.LatencyMs {
			best = n
		}
	}
	if best == cur {
		return nil
	}
	return best
}

// switchFaster переводит цели на заметно более быстрые узлы. Под opMu.
// Чаще раза за цикл фоновых проверок не переключает: решение принимается по задержкам,
// которые туда и записываются, и за цикл каждый запасной успевает обновить свою.
func (w *Watcher) switchFaster() {
	cycle := time.Duration(w.c.Watch.BackgroundCycleMin) * time.Minute
	if cycle <= 0 || w.c.Watch.SwitchFasterMs <= 0 {
		return
	}
	for _, t := range w.allTargets() {
		w.mu.Lock()
		var cand *NodeState
		from, fromMs, toMs := "", 0, 0
		if time.Since(t.lastSelect) >= cycle {
			if cand = w.faster(t); cand != nil {
				cur := w.find(t.Active)
				from, fromMs, toMs = cur.Name, cur.LatencyMs, cand.LatencyMs
			}
		}
		w.mu.Unlock()
		if cand == nil {
			continue
		}
		// Задержка у кандидата могла устареть на цикл — проверяем его дважды прямо сейчас.
		allOK := true
		for range 2 {
			if err := w.realTest(cand.TestPort); err != nil {
				allOK = false
				w.record(cand.Tag, false)
				w.mu.Lock()
				cand.LastErr = "загрузка: " + shortErr(err)
				w.mu.Unlock()
				break
			}
			w.record(cand.Tag, true)
		}
		if !allOK {
			continue
		}
		if err := w.override(t.Balancer, cand.Tag); err != nil {
			lg.Printf("не удалось переключить балансировщик %s: %v", t.Balancer, err)
			continue
		}
		now := time.Now()
		w.mu.Lock()
		t.Active, t.Pinned, t.Fails, t.LastOK, t.Down, t.lastSelect = cand.Tag, false, 0, now, false, now
		cand.BadUntil, cand.LastErr = time.Time{}, ""
		w.mu.Unlock()
		w.say("switch"+t.ID, "switch", fmt.Sprintf("узел быстрее%s: переключено на «%s» (%d мс вместо %d у «%s»)", t.where(), cand.Name, toMs, fromMs, from))
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
	ok := t != nil && n != nil && t.allows(tag)
	w.mu.Unlock()
	if !ok {
		return fmt.Errorf("нет такого узла в этой группе")
	}
	if err := w.override(t.Balancer, tag); err != nil {
		return err
	}
	w.mu.Lock()
	t.Active, t.Pinned, t.Fails, t.Down = tag, true, 0, false
	n.BadUntil, n.LastErr = time.Time{}, ""
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
