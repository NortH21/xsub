package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	version     = "dev"
	defaultRepo = "furriest/xsub" // при сборке: -X main.defaultRepo=владелец/репозиторий
)

const defaultVPN = `# Через VPN. Одна запись на строку, комментарии после #.
#   example.com            — домен со всеми поддоменами
#   =example.com           — только этот домен
#   ext:файл.dat:категория — категория из файла в папке geo-файлов Xray
#   geosite:категория      — категория из geosite.dat
#   1.2.3.0/24             — IP или подсеть
#
# Готовые категории itdoginfo/allow-domains (файл geosite_itdog.dat скачивается сам):
# russia-inside — заблокированное в РФ; youtube, telegram, discord, meta, twitter, tiktok …
ext:geosite_itdog.dat:russia-inside
ext:geosite_itdog.dat:telegram

# Подсети Telegram (https://core.telegram.org/resources/cidr.txt)
91.108.4.0/22
91.108.8.0/22
91.108.12.0/22
91.108.16.0/22
91.108.20.0/22
91.108.56.0/22
91.105.192.0/23
95.161.64.0/20
149.154.160.0/20
185.76.151.0/24
`

const defaultDirect = `# Напрямую. Проверяется раньше списка «Через VPN» — сюда исключения.
# Формат тот же, что в vpn.txt.
`

const defaultConfigJSON = `{
  // Веб-страница xsub: http://<IP-роутера>:8099/
  "listen": "0.0.0.0:8099",
  "user": "admin",
  "password": "%s",

  // Журнал: /tmp — оперативная память (не изнашивает флеш), "" — только на веб-странице.
  // Чтобы журнал переживал перезагрузку: "/opt/var/log/xsub.log".
  "log_file": "/tmp/xsub.log",

  // Подписки добавляются на веб-странице (хранятся в subscriptions.json).
  "sub_interval_hours": 6,
  // Панели отдают разный формат в зависимости от клиента. xsub понимает ссылки
  // (vless, vmess, trojan, ss, hysteria2, wireguard, socks, http), Clash YAML,
  // sing-box JSON и JSON Xray; у каждой подписки можно задать свой User-Agent.
  "user_agent": "v2rayN/7.0",

  "xray": {
    "bin": "/opt/sbin/xray",
    "confdir": "/opt/etc/xray/configs",
    "assetdir": "/opt/etc/xray/dat",
    "restart_cmd": "xkeen -restart",
    // Запасной outbound из ваших конфигов — на случай, если не работает ни один узел подписок.
    "fallback_tag": ""
  },

  "watchdog": {
    "enabled": true,
    "interval_sec": 60,
    "fails_to_switch": 2
  }
}
`

func randomPassword(n int) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b.WriteByte(alphabet[k.Int64()])
	}
	return b.String()
}

func doInit(cfgPath string) int {
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Println("ошибка:", err)
		return 1
	}
	pw := ""
	files := []struct {
		path, content string
	}{
		{cfgPath, ""},
		{filepath.Join(dir, "vpn.txt"), defaultVPN},
		{filepath.Join(dir, "direct.txt"), defaultDirect},
	}
	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil {
			continue
		}
		content := f.content
		if f.path == cfgPath {
			pw = randomPassword(12)
			content = fmt.Sprintf(defaultConfigJSON, pw)
		}
		if err := os.WriteFile(f.path, []byte(content), 0o600); err != nil {
			fmt.Println("ошибка:", err)
			return 1
		}
		fmt.Println("создан:", f.path)
	}
	if pw != "" {
		fmt.Println()
		fmt.Println("Веб-страница: http://<IP-роутера>:8099/")
		fmt.Println("Логин: admin")
		fmt.Println("Пароль:", pw)
		fmt.Println("(пароль можно поменять в", cfgPath+")")
	}
	return 0
}

func main() {
	cfgPath := flag.String("config", "/opt/etc/xsub/config.json", "путь к конфигу")
	initFlag := flag.Bool("init", false, "создать конфиг и списки по умолчанию (существующие файлы не трогает)")
	restore := flag.Bool("restore", false, "вернуть конфиги Xray к состоянию до xsub и перезапустить Xray")
	showVer := flag.Bool("version", false, "показать версию")
	flag.Parse()

	switch {
	case *showVer:
		fmt.Println("xsub", version)
		return
	case *initFlag:
		os.Exit(doInit(*cfgPath))
	}

	c, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xsub:", err)
		os.Exit(1)
	}
	if *restore {
		if err := restoreOriginals(c); err != nil {
			fmt.Fprintln(os.Stderr, "xsub:", err)
			os.Exit(1)
		}
		fmt.Println("конфиги Xray возвращены к состоянию до xsub")
		return
	}

	lg.path, lg.maxSize = c.LogFile, int64(c.LogMaxKB)<<10
	if _, err := os.Stat(c.Xray.Bin); err != nil {
		fmt.Fprintln(os.Stderr, "xsub: не найден xray:", c.Xray.Bin)
		os.Exit(1)
	}
	a, err := newApp(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xsub:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	lg.Printf("xsub %s запущен, веб-страница: http://%s/", version, c.Listen)

	srv := &http.Server{Addr: c.Listen, Handler: a.handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lg.Printf("веб-страница не запущена: %v", err)
		}
	}()

	go func() {
		a.startup()
		go a.subLoop(ctx)
		go a.healLoop(ctx)
		go every(ctx, time.Duration(c.Geo.IntervalHours)*time.Hour, func() { a.updateGeo(true) })
		go func() {
			time.Sleep(2 * time.Minute)
			a.checkUpdate()
			every(ctx, 24*time.Hour, a.checkUpdate)
		}()
		a.w.loop(ctx)
	}()

	<-ctx.Done()
	lg.Printf("xsub остановлен")
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
}
