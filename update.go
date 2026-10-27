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

// repoRe — «владелец/репозиторий» на GitHub. Значение из config.json попадает и в
// ссылку, и в строку, которую выполняет /bin/sh, поэтому проверяется до использования.
var repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)

func validRepo(s string) bool { return repoRe.MatchString(s) }

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
	if !validRepo(a.c.UpdateRepo) {
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
	if !validRepo(a.c.UpdateRepo) {
		return fmt.Errorf("update_repo в config.json должен быть вида владелец/репозиторий")
	}
	if _, err := exec.LookPath("opkg"); err != nil {
		return fmt.Errorf("не найден opkg")
	}
	script := `sleep 1
echo "$(date '+%F %T') обновление xsub"
RC=1
if [ -f /opt/etc/opkg/xsub.conf ]; then
  opkg update && opkg upgrade xsub
  RC=$?
else
  # Запасной путь, без фида opkg: ставим из релиза, сверив контрольную сумму.
  BASE=https://github.com/` + a.c.UpdateRepo + `/releases/latest/download
  TMP=/tmp/xsub-install.sh
  SUMS=/tmp/xsub-install.sums
  if curl -fsSL "$BASE/install.sh" -o "$TMP" && curl -fsSL "$BASE/SHA256SUMS" -o "$SUMS"; then
    WANT=$(awk '$2 ~ /install.sh$/ { print $1 }' "$SUMS")
    HAVE=$(sha256sum "$TMP" 2>/dev/null | awk '{ print $1 }')
    if [ -n "$WANT" ] && [ "$WANT" = "$HAVE" ]; then
      sh "$TMP"
      RC=$?
    else
      echo "контрольная сумма install.sh не совпала — обновление отменено"
    fi
  else
    echo "не удалось скачать install.sh или SHA256SUMS"
  fi
  rm -f "$TMP" "$SUMS"
fi
echo "$(date '+%F %T') готово, код $RC"`
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
