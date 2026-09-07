// Package credentials reads platform credentials from the probe's fixed
// mounted path (design.md D15 / Section 8.1: "read from a fixed mounted
// path `/etc/dbagent-probe/platform-credentials/` backed by a K8s Secret or
// Docker secret. Fixed key names: `username`, `password`, `ca.crt`
// (optional)."), and watches that path for changes so the probe can
// auto-retest connectivity when credentials appear/change (Section 8.4
// step 7: "K8s: probe watches the mount path -> on file appearance,
// auto-runs the connectivity test").
package credentials

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	UsernameFile = "username"
	PasswordFile = "password"
	CAFile       = "ca.crt"
)

type Credentials struct {
	Username    string
	Password    string
	CACertPEM   []byte
	HasUsername bool
	HasPassword bool
	HasCA       bool
}

// Read reads the conventional key files from mountPath. A missing mount
// directory or missing individual files is not an error -- the Has*
// flags report what's present (design.md Section 8.4 5b: "Absent -> report
// PENDING_CREDENTIALS + missing items").
func Read(mountPath string) (Credentials, error) {
	var c Credentials
	if username, err := os.ReadFile(filepath.Join(mountPath, UsernameFile)); err == nil {
		c.Username = string(username)
		c.HasUsername = true
	} else if !os.IsNotExist(err) {
		return c, err
	}
	if password, err := os.ReadFile(filepath.Join(mountPath, PasswordFile)); err == nil {
		c.Password = string(password)
		c.HasPassword = true
	} else if !os.IsNotExist(err) {
		return c, err
	}
	if ca, err := os.ReadFile(filepath.Join(mountPath, CAFile)); err == nil {
		c.CACertPEM = ca
		c.HasCA = true
	} else if !os.IsNotExist(err) {
		return c, err
	}
	return c, nil
}

// Missing returns the design.md Section 8.4 `missing` list
// (`["credentials", "tls_ca"]`-shaped) given whether HTTPS/TLS-CA
// resolution is required.
func (c Credentials) Missing(requireTLSCA bool, haveCAFromElsewhere bool) []string {
	var missing []string
	if !c.HasUsername || !c.HasPassword {
		missing = append(missing, "credentials")
	}
	if requireTLSCA && !c.HasCA && !haveCAFromElsewhere {
		missing = append(missing, "tls_ca")
	}
	return missing
}

// Watcher polls mountPath at interval and invokes onChange whenever the
// observed file set/mtimes change (kubelet refreshes mounted Secrets
// within minutes; polling is simpler and more portable here than an
// inotify-based watch, and the connectivity re-test this drives is cheap
// and idempotent).
type Watcher struct {
	MountPath string
	Interval  time.Duration
	OnChange  func()

	lastState string
}

func NewWatcher(mountPath string, interval time.Duration, onChange func()) *Watcher {
	return &Watcher{MountPath: mountPath, Interval: interval, OnChange: onChange}
}

// Start blocks, polling until ctx is cancelled. Call from a goroutine.
func (w *Watcher) Start(ctx context.Context) {
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	w.checkOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.checkOnce()
		}
	}
}

// checkOnce is split out from Start for deterministic unit testing
// without relying on a real timer/goroutine race.
func (w *Watcher) checkOnce() {
	state := fingerprint(w.MountPath)
	if state != w.lastState {
		changed := w.lastState != ""
		w.lastState = state
		if changed && w.OnChange != nil {
			w.OnChange()
		}
	}
}

// fingerprint returns a cheap change-detection signature (name+size+mtime
// per file) for the three conventional credential files.
func fingerprint(mountPath string) string {
	out := ""
	for _, name := range []string{UsernameFile, PasswordFile, CAFile} {
		info, err := os.Stat(filepath.Join(mountPath, name))
		if err != nil {
			out += name + ":absent;"
			continue
		}
		out += name + ":" + info.ModTime().String() + ":" + strconv.FormatInt(info.Size(), 10) + ";"
	}
	return out
}
