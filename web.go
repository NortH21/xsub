package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

//go:embed index.html
var indexHTML []byte

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.status())
	})
	mux.HandleFunc("/api/list", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name != "vpn" && name != "direct" {
			http.Error(w, "нет такого списка", 400)
			return
		}
		if r.Method == http.MethodGet {
			b, _ := os.ReadFile(a.c.path(name + ".txt"))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(b)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		result(w, a.saveList(name, string(body)))
	})
	mux.HandleFunc("/api/select", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Tag string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		opMu.Lock()
		defer opMu.Unlock()
		result(w, a.w.pin(req.Tag))
	})
	mux.HandleFunc("/api/auto", func(w http.ResponseWriter, r *http.Request) {
		opMu.Lock()
		defer opMu.Unlock()
		a.w.selectNode("автовыбор с веб-страницы")
		result(w, nil)
	})
	mux.HandleFunc("/api/check", func(w http.ResponseWriter, r *http.Request) {
		opMu.Lock()
		defer opMu.Unlock()
		a.w.checkAll()
		result(w, nil)
	})
	mux.HandleFunc("/api/sub/refresh", func(w http.ResponseWriter, r *http.Request) {
		a.refreshSubs()
		var errs []string
		a.mu.Lock()
		for _, st := range a.states {
			if st.Err != "" {
				errs = append(errs, st.Name+": "+st.Err)
			}
		}
		a.mu.Unlock()
		if len(errs) > 0 {
			result(w, errString(strings.Join(errs, "\n")))
			return
		}
		result(w, nil)
	})
	mux.HandleFunc("/api/subs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			a.mu.Lock()
			subs := append([]Subscription{}, a.subs...)
			a.mu.Unlock()
			writeJSON(w, subs)
			return
		}
		var subs []Subscription
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&subs); err != nil {
			result(w, err)
			return
		}
		result(w, a.saveSubs(subs))
	})
	mux.HandleFunc("/api/geo/refresh", func(w http.ResponseWriter, r *http.Request) {
		a.updateGeo(true)
		a.mu.Lock()
		e := a.geoErr
		a.mu.Unlock()
		if e != "" {
			result(w, errString(e))
			return
		}
		result(w, nil)
	})
	return a.auth(mux)
}

type errString string

func (e errString) Error() string { return string(e) }

// auth: Basic-авторизация; изменяющие запросы — только POST с заголовком X-XSub
// (чужой сайт в браузере не сможет подделать такой запрос).
func (a *App) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(a.c.User)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(a.c.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="xsub", charset="UTF-8"`)
			http.Error(w, "нужен пароль", http.StatusUnauthorized)
			return
		}
		readOnly := r.URL.Path == "/" || r.URL.Path == "/api/status" ||
			(r.Method == http.MethodGet && (r.URL.Path == "/api/list" || r.URL.Path == "/api/subs"))
		if !readOnly {
			if r.Method != http.MethodPost || r.Header.Get("X-XSub") != "1" {
				http.Error(w, "нужен POST", http.StatusMethodNotAllowed)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	b, _ := marshal(v)
	w.Write(b)
}

func result(w http.ResponseWriter, err error) {
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(422)
		b, _ := marshal(map[string]any{"ok": false, "error": err.Error()})
		w.Write(b)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
