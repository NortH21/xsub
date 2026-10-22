package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Logger struct {
	mu   sync.Mutex
	path string
	ring []string
}

const ringSize = 300

var lg = &Logger{}

func (l *Logger) Printf(format string, a ...any) {
	line := time.Now().Format("2006-01-02 15:04:05") + " " + fmt.Sprintf(format, a...)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring = append(l.ring, line)
	if len(l.ring) > ringSize {
		l.ring = l.ring[len(l.ring)-ringSize:]
	}
	if l.path == "" {
		fmt.Println(line)
		return
	}
	if st, err := os.Stat(l.path); err == nil && st.Size() > 300_000 {
		_ = os.Rename(l.path, l.path+".old")
	}
	_ = os.MkdirAll(filepath.Dir(l.path), 0o755)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Println(line)
		return
	}
	fmt.Fprintln(f, line)
	f.Close()
}

func (l *Logger) Tail(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.ring) {
		n = len(l.ring)
	}
	out := make([]string, n)
	copy(out, l.ring[len(l.ring)-n:])
	return out
}
