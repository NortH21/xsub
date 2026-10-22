package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// opMu — одна «тяжёлая» операция за раз: применение конфига, обновление geo, выбор узла.
var opMu sync.Mutex

func xrayEnv(c *Config) []string {
	return append(os.Environ(), "XRAY_LOCATION_ASSET="+c.Xray.AssetDir)
}

func runCmd(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// xrayTest проверяет конфиг из папки dir. Возвращает хвост вывода при ошибке.
func xrayTest(c *Config, dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := runCmd(ctx, xrayEnv(c), c.Xray.Bin, "run", "-test", "-confdir", dir)
	if err != nil {
		return fmt.Errorf("xray -test: %v\n%s", err, tail(out, 6))
	}
	return nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func restartXray(c *Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := runCmd(ctx, nil, "/bin/sh", "-c", c.Xray.RestartCmd)
	if err != nil {
		return fmt.Errorf("%s: %v\n%s", c.Xray.RestartCmd, err, tail(out, 6))
	}
	return nil
}

func originalDir(c *Config) string { return c.path(filepath.Join("backup", "original")) }

// managed — xsub уже хотя бы раз записал конфиг Xray (сохранены исходные файлы).
func managed(c *Config) bool {
	_, err := os.Stat(filepath.Join(originalDir(c), ".saved"))
	return err == nil
}

// saveOriginals один раз сохраняет исходные 05_routing.json/07_xsub.json — для -restore и удаления пакета.
func saveOriginals(c *Config) error {
	if managed(c) {
		return nil
	}
	dir := originalDir(c)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range []string{routingFile, xsubFile} {
		b, err := os.ReadFile(filepath.Join(c.Xray.ConfDir, f))
		if err == nil {
			if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
				return err
			}
		}
	}
	return os.WriteFile(filepath.Join(dir, ".saved"), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600)
}

// restoreOriginals возвращает конфиги Xray к состоянию до xsub и перезапускает Xray.
func restoreOriginals(c *Config) error {
	if !managed(c) {
		return fmt.Errorf("xsub ещё не менял конфиги Xray — восстанавливать нечего")
	}
	dir := originalDir(c)
	for _, f := range []string{routingFile, xsubFile} {
		dst := filepath.Join(c.Xray.ConfDir, f)
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err == nil {
			if err := writeAtomic(dst, b); err != nil {
				return err
			}
		} else {
			_ = os.Remove(dst)
		}
	}
	_ = os.Remove(filepath.Join(dir, ".saved"))
	return restartXray(c)
}

// applyConfig генерирует конфиг, проверяет его копию через xray -test и только потом
// подменяет файлы и перезапускает Xray. Возвращает changed=false, если менять нечего.
// Вызывать под opMu.
func applyConfig(c *Config, nodes []Node, reason string) (changed bool, err error) {
	l, lerrs, err := readLists(c)
	if err != nil {
		return false, err
	}
	if len(lerrs) > 0 {
		return false, fmt.Errorf("ошибки в списках:\n%s", strings.Join(lerrs, "\n"))
	}
	env, err := scanEnv(c)
	if err != nil {
		return false, err
	}
	routing, xsub, err := generate(c, env, nodes, l)
	if err != nil {
		return false, err
	}
	rPath := filepath.Join(c.Xray.ConfDir, routingFile)
	xPath := filepath.Join(c.Xray.ConfDir, xsubFile)
	oldR, _ := os.ReadFile(rPath)
	oldX, _ := os.ReadFile(xPath)
	if bytes.Equal(oldR, routing) && bytes.Equal(oldX, xsub) {
		return false, nil
	}

	// Проверка во временной копии папки конфигов.
	tmp, err := os.MkdirTemp("", "xsub-test-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	files, _ := filepath.Glob(filepath.Join(c.Xray.ConfDir, "*.json"))
	for _, f := range files {
		base := filepath.Base(f)
		if base == routingFile || base == xsubFile {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return false, err
		}
		if err := os.WriteFile(filepath.Join(tmp, base), b, 0o600); err != nil {
			return false, err
		}
	}
	_ = os.WriteFile(filepath.Join(tmp, routingFile), routing, 0o600)
	_ = os.WriteFile(filepath.Join(tmp, xsubFile), xsub, 0o600)
	if err := xrayTest(c, tmp); err != nil {
		return false, err
	}

	if err := saveOriginals(c); err != nil {
		return false, fmt.Errorf("не удалось сохранить исходные конфиги: %v", err)
	}
	bdir := c.path("backup")
	if len(oldR) > 0 {
		_ = os.WriteFile(filepath.Join(bdir, routingFile), oldR, 0o600)
	}
	if len(oldX) > 0 {
		_ = os.WriteFile(filepath.Join(bdir, xsubFile), oldX, 0o600)
	}
	if err := writeAtomic(xPath, xsub); err != nil {
		return false, err
	}
	if err := writeAtomic(rPath, routing); err != nil {
		return false, err
	}
	lg.Printf("конфиг Xray обновлён (%s), узлов: %d — перезапускаю Xray", reason, len(nodes))
	if err := restartXray(c); err != nil {
		lg.Printf("ошибка перезапуска: %v — возвращаю прежний конфиг", err)
		restoreFiles(c, oldR, oldX)
		_ = restartXray(c)
		return false, err
	}
	return true, nil
}

func restoreFiles(c *Config, oldR, oldX []byte) {
	rPath := filepath.Join(c.Xray.ConfDir, routingFile)
	xPath := filepath.Join(c.Xray.ConfDir, xsubFile)
	if len(oldR) > 0 {
		_ = writeAtomic(rPath, oldR)
	}
	if len(oldX) > 0 {
		_ = writeAtomic(xPath, oldX)
	} else {
		_ = os.Remove(xPath)
	}
}

func writeAtomic(path string, b []byte) error { return writeAtomicMode(path, b, 0o644) }

func writeAtomicMode(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".xsub-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
