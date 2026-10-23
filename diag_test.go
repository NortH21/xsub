package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnose(t *testing.T) {
	d := t.TempDir()
	oldBin, oldInit, oldDir := xkeenBin, xkeenInit, xkeenDir
	defer func() { xkeenBin, xkeenInit, xkeenDir = oldBin, oldInit, oldDir }()
	xkeenBin, xkeenInit, xkeenDir = filepath.Join(d, "xkeen"), filepath.Join(d, "S05xkeen"), d
	os.WriteFile(xkeenInit, []byte("#!/bin/sh\nstart_auto=\"off\"\n"), 0o755)
	os.WriteFile(filepath.Join(d, "xkeen.json"), []byte(`{"xkeen":{"xray":{"speed_balancer":{"enabled":true}}}}`), 0o644)
	c := defaultConfig()
	c.Xray.Bin = filepath.Join(d, "нет-xray")
	c.Xray.ConfDir = t.TempDir()
	writeConf(t, c.Xray.ConfDir, map[string]string{
		"03_inbounds.json": `{"inbounds":[{"tag":"redirect","protocol":"tunnel","port":1181},{"tag":"tproxy","protocol":"tunnel","port":1181,"sniffing":{"enabled":true}}]}`,
	})
	got := map[string]string{}
	for _, x := range diagnose(c) {
		got[x.ID] = x.Level
	}
	want := map[string]string{"xkeen": "bad", "xray": "bad", "auto": "warn", "mode": "ok", "sniff-redirect": "warn", "sb": "warn"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, ждали %q (всё: %v)", k, got[k], v, got)
		}
	}
	if _, ok := got["sniff-tproxy"]; ok {
		t.Error("у tproxy sniffing включён")
	}
	if v, _ := shellVar(xkeenInit, "start_auto"); !strings.EqualFold(v, "off") {
		t.Errorf("shellVar: %q", v)
	}
}
