package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	Listen   string `json:"listen"`
	User     string `json:"user"`
	Password string `json:"password"`
	LogFile  string `json:"log_file"`

	SubIntervalHours int    `json:"sub_interval_hours"`
	MaxNodes         int    `json:"max_nodes"` // на одну подписку
	UserAgent        string `json:"user_agent"`

	// Старый формат (одна подписка в config.json) — переносится в subscriptions.json.
	Legacy *Subscription `json:"subscription,omitempty"`

	Xray  XrayConfig  `json:"xray"`
	Watch WatchConfig `json:"watchdog"`
	Geo   GeoConfig   `json:"geo"`

	dir string // папка конфига: там же списки, подписки, кэш, бэкапы
}

type Subscription struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent,omitempty"`
	Exclude   string `json:"exclude,omitempty"` // регулярное выражение по имени узла
	Include   string `json:"include,omitempty"` // если задано — брать только совпавшие
	// только для чтения старого формата
	IntervalHours int `json:"interval_hours,omitempty"`
}

type XrayConfig struct {
	Bin                string   `json:"bin"`
	ConfDir            string   `json:"confdir"`
	AssetDir           string   `json:"assetdir"`
	RestartCmd         string   `json:"restart_cmd"`
	ManageAPI          bool     `json:"manage_api"`
	APIListen          string   `json:"api_listen"`
	ProbePort          int      `json:"probe_port"`
	TestPortBase       int      `json:"test_port_base"`
	Balancer           string   `json:"balancer"`
	FallbackTag        string   `json:"fallback_tag"`
	TemplateTag        string   `json:"template_tag"`
	DirectTag          string   `json:"direct_tag"`
	ForceProxyInbounds []string `json:"force_proxy_inbounds"`
	ObservatoryURL     string   `json:"observatory_url"`
	ObservatoryEvery   string   `json:"observatory_interval"`
}

type WatchConfig struct {
	Enabled        bool     `json:"enabled"`
	IntervalSec    int      `json:"interval_sec"`
	TestURL        string   `json:"test_url"`
	TestBytes      int64    `json:"test_bytes"`
	TimeoutSec     int      `json:"timeout_sec"`
	FailsToSwitch  int      `json:"fails_to_switch"`
	MaxTry         int      `json:"max_try"`
	BadCooldownMin int      `json:"bad_cooldown_min"`
	LatencyURL     string   `json:"latency_url"`
	DirectURLs     []string `json:"direct_urls"`
}

type GeoFile struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type GeoConfig struct {
	Files         []GeoFile `json:"files"`
	IntervalHours int       `json:"interval_hours"`
}

func defaultConfig() *Config {
	return &Config{
		Listen:           "0.0.0.0:8099",
		User:             "admin",
		LogFile:          "/opt/var/log/xsub.log",
		SubIntervalHours: 6,
		MaxNodes:         60,
		UserAgent:        "v2rayN/7.0",
		Xray: XrayConfig{
			Bin:                "/opt/sbin/xray",
			ConfDir:            "/opt/etc/xray/configs",
			AssetDir:           "/opt/etc/xray/dat",
			RestartCmd:         "xkeen -restart",
			ManageAPI:          true,
			APIListen:          "127.0.0.1:10085",
			ProbePort:          10990,
			TestPortBase:       11000,
			Balancer:           "xsub",
			DirectTag:          "direct",
			ForceProxyInbounds: []string{"force-proxy-redirect", "force-proxy-tproxy"},
			ObservatoryURL:     "https://www.gstatic.com/generate_204",
			ObservatoryEvery:   "2m",
		},
		Watch: WatchConfig{
			Enabled:        true,
			IntervalSec:    60,
			TestURL:        "https://speed.cloudflare.com/__down?bytes=65536",
			TestBytes:      65536,
			TimeoutSec:     10,
			FailsToSwitch:  2,
			MaxTry:         20,
			BadCooldownMin: 30,
			LatencyURL:     "https://www.gstatic.com/generate_204",
			DirectURLs:     []string{"https://ya.ru", "https://www.google.com", "https://1.1.1.1"},
		},
		Geo: GeoConfig{
			IntervalHours: 24,
			Files: []GeoFile{
				{Name: "geosite_itdog.dat", URL: "https://github.com/itdoginfo/allow-domains/releases/latest/download/geosite.dat"},
			},
		},
	}
}

func loadConfig(path string) (*Config, error) {
	c := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(stripJSONComments(b), c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.dir = filepath.Dir(path)
	if c.Password == "" {
		return nil, fmt.Errorf("%s: задайте password для веб-страницы", path)
	}
	if c.Watch.IntervalSec < 15 {
		c.Watch.IntervalSec = 15
	}
	if c.Legacy != nil && c.Legacy.IntervalHours > 0 {
		c.SubIntervalHours = c.Legacy.IntervalHours
	}
	if c.SubIntervalHours < 1 {
		c.SubIntervalHours = 1
	}
	if c.Geo.IntervalHours < 1 {
		c.Geo.IntervalHours = 24
	}
	if c.Watch.TestBytes < 1024 {
		c.Watch.TestBytes = 65536
	}
	if c.Xray.Balancer == "" {
		c.Xray.Balancer = "xsub"
	}
	return c, nil
}

func (c *Config) path(name string) string { return filepath.Join(c.dir, name) }

const subsFile = "subscriptions.json"

// loadSubs читает subscriptions.json; при его отсутствии переносит подписку из старого config.json.
func loadSubs(c *Config) ([]Subscription, error) {
	b, err := os.ReadFile(c.path(subsFile))
	if os.IsNotExist(err) {
		if c.Legacy != nil && strings.HasPrefix(c.Legacy.URL, "http") {
			s := *c.Legacy
			s.IntervalHours = 0
			if s.Name == "" {
				s.Name = "Подписка"
			}
			subs := []Subscription{s}
			if err := saveSubsFile(c, subs); err != nil {
				return nil, err
			}
			lg.Printf("подписка из config.json перенесена в %s", subsFile)
			return subs, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var subs []Subscription
	if err := json.Unmarshal(stripJSONComments(b), &subs); err != nil {
		return nil, fmt.Errorf("%s: %w", subsFile, err)
	}
	return subs, validateSubs(subs)
}

func validateSubs(subs []Subscription) error {
	seen := map[string]bool{}
	for i, s := range subs {
		n := s.Name
		if n == "" {
			n = fmt.Sprintf("№%d", i+1)
		}
		if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("подписка %s: ссылка должна начинаться с http:// или https://", n)
		}
		if seen[s.URL] {
			return fmt.Errorf("подписка %s: такая ссылка уже есть", n)
		}
		seen[s.URL] = true
		for _, re := range []string{s.Exclude, s.Include} {
			if re == "" {
				continue
			}
			if _, err := regexp.Compile(re); err != nil {
				return fmt.Errorf("подписка %s: ошибка в фильтре %q: %v", n, re, err)
			}
		}
	}
	return nil
}

func saveSubsFile(c *Config, subs []Subscription) error {
	if subs == nil {
		subs = []Subscription{}
	}
	b, err := marshal(subs)
	if err != nil {
		return err
	}
	return writeAtomicMode(c.path(subsFile), b, 0o600)
}

// stripJSONComments убирает // и /* */ вне строк (XKeen хранит конфиги с комментариями).
func stripJSONComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if inStr {
			out = append(out, ch)
			if esc {
				esc = false
			} else if ch == '\\' {
				esc = true
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
			out = append(out, ch)
			continue
		}
		if ch == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
			continue
		}
		if ch == '/' && i+1 < len(b) && b[i+1] == '*' {
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, ch)
	}
	return out
}
