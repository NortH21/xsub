package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Панель с привязкой устройств: без x-hwid — заглушка, с ним — JSON Xray.
func TestSubscriptionSendsStableHWID(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("X-Hwid"))
		if r.Header.Get("User-Agent") != "Happ/4.8.2" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("X-Hwid") == "" {
			w.Write([]byte("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp#stub"))
			return
		}
		w.Write([]byte(`[{"remarks":"NL","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"` + tUUID + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}]}]`))
	}))
	defer srv.Close()
	c := &Config{dir: t.TempDir()}
	for i := 0; i < 2; i++ {
		b, _, err := fetchURLHeaders(c, srv.URL, subHeaders(c, "Happ/4.8.2"), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if nodes, w := parseSubscription(string(b), parseOpts{sub: "t"}); len(nodes) != 1 {
			t.Fatalf("узлов %d, %v", len(nodes), w)
		}
	}
	if len(got[0]) != 32 || got[0] != got[1] {
		t.Fatalf("HWID должен быть постоянным: %q", got)
	}
}
