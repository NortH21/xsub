package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFallbackSubscription(t *testing.T) {
	var requests int
	var force bool
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("User-Agent") != "test-client" {
			t.Error("не передан User-Agent")
		}
		if force && r.Header.Get("X-Hwid") == "" {
			t.Error("не передан HWID")
		}
		if fail {
			http.Error(w, "error", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("vless://" + tUUID + "@one.example:443#Keep\n" + "vless://" + tUUID + "@two.example:443#Skip\n"))
	}))
	defer srv.Close()
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	c.Xray.ProbePort = 0
	a, _ := newApp(c)
	f := Fallback{Name: "Backup", URL: srv.URL, Include: "Keep", UserAgent: "test-client", ForceHWID: true}
	if _, err := prepareFallbacks(c, []Fallback{f}); err != nil {
		t.Fatal(err)
	}
	if err := saveFallbacksFile(c, []Fallback{f, {Name: "other", Link: "socks://proxy.example:1080"}}); err != nil {
		t.Fatal(err)
	}
	force = true
	if a.refreshFallbackSubscriptions(context.Background()) {
		t.Fatal("ошибка загрузки")
	}
	ns, warns := fallbackNodes(c, nil)
	if len(ns) != 2 || len(warns) != 0 || !strings.Contains(ns[0].Name, "Keep") || ns[1].Name != "other" || !isFallbackTag(ns[0].Tag) {
		t.Fatalf("nodes=%v warns=%v", ns, warns)
	}
	if requests != 1 {
		t.Fatalf("ожидался один запрос, получено %d", requests)
	}
	tag := ns[0].Tag
	fail = true
	if !a.refreshFallbackSubscriptions(context.Background()) {
		t.Fatal("ошибка загрузки не замечена")
	}
	ns, _ = fallbackNodes(c, nil)
	if len(ns) != 2 || ns[0].Tag != tag || !a.fallbackStates[srv.URL].Cached {
		t.Fatal("сохранённая копия не использована")
	}
	if fi, err := os.Stat(fallbackCachePath(c, srv.URL)); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("неверные права кеша")
	}
}

func TestFallbackSubscriptionValidation(t *testing.T) {
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	for _, f := range []Fallback{{URL: "invalid"}, {URL: "https://example.com", Exclude: "("}, {URL: "https://example.com", Link: "socks://host:1"}} {
		if _, err := prepareFallbacks(c, []Fallback{f}); err == nil {
			t.Fatal("некорректная настройка принята")
		}
	}
}

func TestFallbackSubscriptionHWIDRetry(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-Hwid") == "" {
			_, _ = w.Write([]byte("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1#stub"))
			return
		}
		_, _ = w.Write([]byte("vless://" + tUUID + "@one.example:443#OK"))
	}))
	defer srv.Close()
	c := defaultConfig()
	c.dir = t.TempDir()
	c.Xray.ConfDir = t.TempDir()
	a, _ := newApp(c)
	if err := saveFallbacksFile(c, []Fallback{{Name: "Backup", URL: srv.URL}}); err != nil {
		t.Fatal(err)
	}
	if a.refreshFallbackSubscriptions(context.Background()) || requests != 2 {
		t.Fatalf("повтор с HWID не выполнен: запросов %d", requests)
	}
	ns, _ := fallbackNodes(c, nil)
	if len(ns) != 1 {
		t.Fatalf("узлов %d", len(ns))
	}
}

func TestFallbackSubscriptionForceHWIDRequiresPersistentID(t *testing.T) {
	hwidMu.Lock()
	hwidCache, hwidWriteErr = "", nil
	hwidMu.Unlock()
	t.Cleanup(func() { hwidMu.Lock(); hwidCache, hwidWriteErr = "", nil; hwidMu.Unlock() })
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++ }))
	defer srv.Close()
	c := defaultConfig()
	c.dir = t.TempDir()
	if err := os.Mkdir(c.path("hwid"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveFallbacksFile(c, []Fallback{{Name: "Backup", URL: srv.URL, ForceHWID: true}}); err != nil {
		t.Fatal(err)
	}
	a, _ := newApp(c)
	if !a.refreshFallbackSubscriptions(context.Background()) {
		t.Fatal("ошибка сохранения HWID не обнаружена")
	}
	if requests != 0 {
		t.Fatal("запрос с несохранённым HWID недопустим")
	}
}
