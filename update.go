package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// newerVersion: true, если b новее a (сравнение x.y.z).
func newerVersion(a, b string) bool {
	pa, pb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return y > x
		}
	}
	return false
}

// checkUpdate узнаёт последнюю версию на GitHub (раз в сутки).
func (a *App) checkUpdate() {
	if a.c.UpdateRepo == "" {
		return
	}
	b, _, err := fetchURL(a.c, "https://api.github.com/repos/"+a.c.UpdateRepo+"/releases/latest", "xsub/"+version, 1<<20)
	if err != nil {
		return
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if json.Unmarshal(b, &r) != nil || r.Tag == "" {
		return
	}
	latest := strings.TrimPrefix(r.Tag, "v")
	a.mu.Lock()
	a.latest = latest
	a.mu.Unlock()
	if newerVersion(version, latest) && a.c.Telegram.OnUpdate {
		a.n.send("update"+latest, fmt.Sprintf("вышла новая версия xsub %s (сейчас %s) — обновить можно на странице xsub", latest, version), 365*24*time.Hour)
	}
}

const updateLog = "/tmp/xsub-update.log"

// startUpgrade запускает обновление в отдельном процессе: при обновлении пакет останавливает
// и снова запускает xsub, поэтому сам xsub ждать окончания не может.
func (a *App) startUpgrade() error {
	if _, err := exec.LookPath("opkg"); err != nil {
		return fmt.Errorf("не найден opkg")
	}
	script := `sleep 1
echo "$(date '+%F %T') обновление xsub"
if [ -f /opt/etc/opkg/xsub.conf ]; then
  opkg update && opkg upgrade xsub
else
  curl -fsSL https://raw.githubusercontent.com/` + a.c.UpdateRepo + `/main/install.sh | sh
fi
echo "$(date '+%F %T') готово, код $?"`
	f, err := os.OpenFile(updateLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.Env = append(os.Environ(), "PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	go func() { _ = cmd.Wait() }()
	lg.Printf("запущено обновление xsub (журнал: %s)", updateLog)
	return nil
}
