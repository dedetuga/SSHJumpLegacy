// sshjump (legacy / classic ACAP) — browser xterm.js <-> SSH bridge that runs
// as a classic ACAP on ARTPEC-4/5 (MIPS) cameras and acts as a small jump host
// to reach LAN devices over SSH. Auto-stops after idle.
//
// Transport: the classic ACAP web mechanism proxies /local/<app>/control.cgi to
// a Unix socket (/var/run/http/<app>/http) via Apache. We accept BOTH FastCGI
// and plain HTTP on that socket (first-byte sniff), and dispatch by ?op=.
//
// Logging: important events (startup, connect, session open/close, idle stop,
// errors) always go to SSHJUMP_LOG (default /tmp/sshjump.log) and stderr. Set
// SSHJUMP_DEBUG=1 for verbose tracing (every connection with a hex dump, every
// request/response, watchdog ticks). Secrets (passwords, keys) and terminal
// payloads are never logged; only their presence/size is.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// version is stamped at build time via -ldflags "-X main.version=..."; the
// default here is the fallback when built without that flag.
var version = "1.0.0"

// ---- configuration (overridable via environment) ---------------------------

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// defaultApp is the app/socket name used when SSHJUMP_APP is unset. It can be
// overridden at build time with -ldflags "-X main.defaultApp=<name>", which is
// how build.sh produces differently-named variants that don't collide on the
// /var/run/http/<name>/http socket with other apps built from this code.
var defaultApp = "sshjump"

var (
	appName     = env("SSHJUMP_APP", defaultApp)
	idleTimeout = parseDuration(env("SSHJUMP_IDLE_TIMEOUT", "30m"))
	socketPath  = env("SSHJUMP_SOCKET", "/var/run/http/"+env("SSHJUMP_APP", defaultApp)+"/http")
	tcpAddr     = os.Getenv("SSHJUMP_LISTEN") // if set, serve plain HTTP on TCP (debug)
	logPath     = env("SSHJUMP_LOG", "/tmp/"+env("SSHJUMP_APP", defaultApp)+".log")
)

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 30 * time.Minute
	}
	return d
}

// ---- logging ---------------------------------------------------------------

var (
	reqSeq  uint64
	connSeq uint64
	debug   = os.Getenv("SSHJUMP_DEBUG") == "1"
	sysLog  *syslog.Writer // Axis system log ("Log do app"); nil until initSyslog
)

// initSyslog connects to the local syslog with tag=appName so events show up in
// the camera's per-app system log (systemlog.cgi?appname=<app>). Best-effort.
func initSyslog() {
	if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, appName); err == nil {
		sysLog = w
	}
}

// emit writes to the local log (file + stderr) and, when connected, mirrors the
// line to the Axis system log at the given severity so it appears in "Log do app".
func emit(sev byte, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Print(msg)
	if sysLog == nil {
		return
	}
	switch sev {
	case 'E':
		_ = sysLog.Err(msg)
	case 'W':
		_ = sysLog.Warning(msg)
	case 'D':
		_ = sysLog.Debug(msg)
	default:
		_ = sysLog.Info(msg)
	}
}

// inf/warnf/errf log important events (always). dbg logs verbose tracing (only
// when SSHJUMP_DEBUG=1). All also go to the Axis system log when available.
func inf(format string, a ...interface{})   { emit('I', format, a...) }
func warnf(format string, a ...interface{}) { emit('W', format, a...) }
func errf(format string, a ...interface{})  { emit('E', format, a...) }
func dbg(format string, a ...interface{}) {
	if debug {
		emit('D', format, a...)
	}
}

// ---- activity tracking (drives the idle shutdown) --------------------------

type activity struct {
	mu   sync.Mutex
	last time.Time
	n    int
}

func (a *activity) touch() { a.mu.Lock(); a.last = time.Now(); a.mu.Unlock() }
func (a *activity) open()  { a.mu.Lock(); a.n++; a.last = time.Now(); a.mu.Unlock() }
func (a *activity) close() {
	a.mu.Lock()
	if a.n > 0 {
		a.n--
	}
	a.last = time.Now()
	a.mu.Unlock()
}
func (a *activity) idleFor() (time.Duration, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.last), a.n
}

var act = &activity{last: time.Now()}

// ---- connect request -------------------------------------------------------

type connectMsg struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	AuthType   string `json:"authType"`
	Password   string `json:"password"`
	Key        string `json:"key"`
	Passphrase string `json:"passphrase"`
	Cols       int    `json:"cols"`
	Rows       int    `json:"rows"`
}

func buildClientConfig(cm connectMsg, fp *string) (*ssh.ClientConfig, error) {
	var auths []ssh.AuthMethod
	switch cm.AuthType {
	case "key":
		var signer ssh.Signer
		var e error
		if cm.Passphrase != "" {
			signer, e = ssh.ParsePrivateKeyWithPassphrase([]byte(cm.Key), []byte(cm.Passphrase))
		} else {
			signer, e = ssh.ParsePrivateKey([]byte(cm.Key))
		}
		if e != nil {
			return nil, e
		}
		auths = append(auths, ssh.PublicKeys(signer))
	default:
		pw := cm.Password
		auths = append(auths,
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				ans := make([]string, len(qs))
				for i := range qs {
					ans[i] = pw
				}
				return ans, nil
			}),
		)
	}
	cfg := &ssh.ClientConfig{
		User: cm.User,
		Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if fp != nil {
				*fp = key.Type() + " " + ssh.FingerprintSHA256(key)
			}
			return nil
		},
		Timeout: 12 * time.Second,
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA,
			ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		},
	}
	cfg.Ciphers = append(cfg.Ciphers,
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
	)
	return cfg, nil
}

// ---- session ---------------------------------------------------------------

type session struct {
	id        string
	client    *ssh.Client
	sess      *ssh.Session
	stdin     io.WriteCloser
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		dbg("session %s: closing", s.id)
		close(s.closed)
		if s.sess != nil {
			_ = s.sess.Close()
		}
		if s.client != nil {
			_ = s.client.Close()
		}
		sessions.del(s.id)
		act.close()
		_, n := act.idleFor()
		inf("session %s closed (active sessions now %d)", s.id[:8], n)
	})
}

func (s *session) pump(name string, r io.Reader) {
	buf := make([]byte, 8192)
	var total int64
	for {
		n, e := r.Read(buf)
		if n > 0 {
			total += int64(n)
			act.touch()
			b := make([]byte, n)
			copy(b, buf[:n])
			select {
			case s.out <- b:
			case <-s.closed:
				dbg("session %s: %s pump stop (closed), %d bytes total", s.id, name, total)
				return
			}
		}
		if e != nil {
			dbg("session %s: %s pump EOF (%v), %d bytes total", s.id, name, e, total)
			return
		}
	}
}

type sessionRegistry struct {
	mu sync.Mutex
	m  map[string]*session
}

func (r *sessionRegistry) get(id string) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[id]
}
func (r *sessionRegistry) put(s *session) {
	r.mu.Lock()
	r.m[s.id] = s
	r.mu.Unlock()
}
func (r *sessionRegistry) del(id string) {
	r.mu.Lock()
	delete(r.m, id)
	r.mu.Unlock()
}

var sessions = &sessionRegistry{m: make(map[string]*session)}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- handlers (single endpoint, dispatched by ?op=) ------------------------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		dbg("connect: rejected method %s", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var cm connectMsg
	if err := json.NewDecoder(r.Body).Decode(&cm); err != nil {
		dbg("connect: bad JSON: %v", err)
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	dbg("connect: host=%s port=%d user=%q(len=%d) auth=%s pwLen=%d hasKey=%v cols=%d rows=%d",
		cm.Host, cm.Port, cm.User, len(cm.User), cm.AuthType, len(cm.Password), cm.Key != "", cm.Cols, cm.Rows)
	if cm.Host == "" || cm.User == "" {
		dbg("connect: missing host/user")
		writeJSON(w, 400, map[string]string{"error": "host and username are required"})
		return
	}
	if cm.Port == 0 {
		cm.Port = 22
	}
	if cm.Cols == 0 {
		cm.Cols = 80
	}
	if cm.Rows == 0 {
		cm.Rows = 24
	}

	var fp string
	cfg, err := buildClientConfig(cm, &fp)
	if err != nil {
		dbg("connect: key parse error: %v", err)
		writeJSON(w, 400, map[string]string{"error": "invalid private key: " + err.Error()})
		return
	}

	addr := net.JoinHostPort(cm.Host, strconv.Itoa(cm.Port))
	inf("connect: %s@%s dialing", cm.User, addr)
	t0 := time.Now()
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		errf("connect: %s@%s FAILED after %s: %v", cm.User, addr, time.Since(t0), err)
		writeJSON(w, 502, map[string]string{"error": "SSH connection failed: " + err.Error()})
		return
	}
	dbg("connect: ssh handshake ok in %s, hostkey=%s", time.Since(t0), fp)
	sess, err := client.NewSession()
	if err != nil {
		errf("connect: %s@%s NewSession failed: %v", cm.User, addr, err)
		client.Close()
		writeJSON(w, 502, map[string]string{"error": "session failed: " + err.Error()})
		return
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", cm.Rows, cm.Cols, modes); err != nil {
		errf("connect: %s@%s RequestPty failed: %v", cm.User, addr, err)
		sess.Close()
		client.Close()
		writeJSON(w, 502, map[string]string{"error": "PTY failed: " + err.Error()})
		return
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	stderr, _ := sess.StderrPipe()
	if err := sess.Shell(); err != nil {
		errf("connect: %s@%s Shell failed: %v", cm.User, addr, err)
		sess.Close()
		client.Close()
		writeJSON(w, 502, map[string]string{"error": "shell failed: " + err.Error()})
		return
	}

	s := &session{
		id:     newID(),
		client: client,
		sess:   sess,
		stdin:  stdin,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	sessions.put(s)
	act.open()
	inf("connect: session %s established %s@%s (hostkey %s)", s.id[:8], cm.User, addr, fp)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { s.pump("stdout", stdout); wg.Done() }()
	go func() { s.pump("stderr", stderr); wg.Done() }()
	go func() { wg.Wait(); s.close() }()

	writeJSON(w, 200, map[string]string{"id": s.id, "fingerprint": fp})
}

func pollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s := sessions.get(id)
	if s == nil {
		dbg("poll: unknown session %q -> 404", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	var chunks [][]byte
	var nbytes int
	select {
	case b := <-s.out:
		chunks = append(chunks, b)
		nbytes += len(b)
	case <-s.closed:
		for {
			select {
			case b := <-s.out:
				chunks = append(chunks, b)
				nbytes += len(b)
				continue
			default:
			}
			break
		}
		dbg("poll: session %s closed, flushing %d bytes", id, nbytes)
		w.Header().Set("X-Session-Closed", "1")
		w.Header().Set("Content-Type", "application/octet-stream")
		for _, b := range chunks {
			w.Write(b)
		}
		return
	case <-timer.C:
		w.WriteHeader(http.StatusNoContent)
		return
	}
	for {
		select {
		case b := <-s.out:
			chunks = append(chunks, b)
			nbytes += len(b)
			continue
		default:
		}
		break
	}
	dbg("poll: session %s delivering %d bytes", id, nbytes)
	w.Header().Set("Content-Type", "application/octet-stream")
	for _, b := range chunks {
		w.Write(b)
	}
}

func inputHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s := sessions.get(id)
	if s == nil {
		dbg("input: unknown session %q -> 404", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	act.touch()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(body) > 0 {
		_, _ = s.stdin.Write(body)
	}
	dbg("input: session %s wrote %d bytes", id, len(body))
	w.WriteHeader(http.StatusNoContent)
}

func resizeHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s := sessions.get(id)
	if s == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	if cols > 0 && rows > 0 {
		_ = s.sess.WindowChange(rows, cols)
	}
	dbg("resize: session %s -> %dx%d", id, cols, rows)
	w.WriteHeader(http.StatusNoContent)
}

func closeHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	dbg("close: session %q", id)
	if s := sessions.get(id); s != nil {
		s.close()
	}
	w.WriteHeader(http.StatusNoContent)
}

func healthHandler(w http.ResponseWriter) {
	idle, n := act.idleFor()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":          true,
		"sessions":    n,
		"idleSeconds": int(idle.Seconds()),
		"idleTimeout": idleTimeout.String(),
		"version":     version,
	})
}

func route(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Query().Get("op")
	switch op {
	case "connect":
		connectHandler(w, r)
	case "poll":
		pollHandler(w, r)
	case "input":
		inputHandler(w, r)
	case "resize":
		resizeHandler(w, r)
	case "close":
		closeHandler(w, r)
	case "health":
		healthHandler(w)
	default:
		dbg("route: unknown op %q (path=%q) -> 404", op, r.URL.Path)
		http.NotFound(w, r)
	}
}

// statusRecorder captures the response status + byte count for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }
func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	n, e := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, e
}

// tag wraps a handler, logging each request+response with the transport used.
func tag(proto string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddUint64(&reqSeq, 1)
		dbg("[req#%d] >>> proto=%s method=%s uri=%q op=%q remote=%s host=%s CL=%s CT=%q XFwd=%q auth=%v",
			n, proto, r.Method, r.RequestURI, r.URL.Query().Get("op"), r.RemoteAddr, r.Host,
			r.Header.Get("Content-Length"), r.Header.Get("Content-Type"),
			r.Header.Get("X-Forwarded-For"), r.Header.Get("Authorization") != "")
		sr := &statusRecorder{ResponseWriter: w}
		t0 := time.Now()
		h.ServeHTTP(sr, r)
		if sr.status == 0 {
			sr.status = 200
		}
		dbg("[req#%d] <<< status=%d bytes=%d dur=%s", n, sr.status, sr.bytes, time.Since(t0))
	})
}

// ---- idle watchdog ---------------------------------------------------------

func stopSelf() {
	warnf("idle for %s with no activity — auto-stopping %s", idleTimeout, appName)
	q := "/axis-cgi/applications/control.cgi?action=stop&package=" + appName
	_ = exec.Command("sh", "-c",
		"curl -s --max-time 5 'http://127.0.0.1"+q+"' >/dev/null 2>&1 || "+
			"curl -sk --max-time 5 'https://127.0.0.1"+q+"' >/dev/null 2>&1").Run()
	inf("watchdog: exit(0)")
	os.Exit(0)
}

func watchdog() {
	interval := 30 * time.Second
	if idleTimeout < interval {
		interval = idleTimeout
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for range tick.C {
		idle, n := act.idleFor()
		dbg("watchdog: idle=%s sessions=%d (timeout %s)", idle.Round(time.Second), n, idleTimeout)
		if idle >= idleTimeout {
			stopSelf()
			return
		}
	}
}

// ---- transport: one Unix socket, FastCGI *and* HTTP -----------------------

type peekConn struct {
	net.Conn
	first    []byte
	consumed bool
}

func (c *peekConn) Read(p []byte) (int, error) {
	if !c.consumed && len(c.first) > 0 {
		n := copy(p, c.first)
		c.first = c.first[n:]
		if len(c.first) == 0 {
			c.consumed = true
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

func serveUnixMux(path string, h http.Handler) error {
	_ = os.MkdirAll(filepath.Dir(path), 0777)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0666)

	fcgiL := &chanListener{ch: make(chan net.Conn), addr: ln.Addr(), done: make(chan struct{})}
	httpL := &chanListener{ch: make(chan net.Conn), addr: ln.Addr(), done: make(chan struct{})}
	go func() {
		if e := fcgi.Serve(fcgiL, tag("fcgi", h)); e != nil {
			dbg("fcgi.Serve returned: %v", e)
		}
	}()
	go func() {
		if e := http.Serve(httpL, tag("http", h)); e != nil {
			dbg("http.Serve returned: %v", e)
		}
	}()

	inf("listening on unix:%s (FastCGI + HTTP), idle timeout %s", path, idleTimeout)
	for {
		c, err := ln.Accept()
		if err != nil {
			dbg("accept error: %v", err)
			return err
		}
		go classify(c, fcgiL, httpL)
	}
}

func classify(c net.Conn, fcgiL, httpL *chanListener) {
	id := atomic.AddUint64(&connSeq, 1)
	dbg("[conn#%d] accepted from %v", id, c.RemoteAddr())
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, err := br.Peek(1)
	if err != nil || len(first) == 0 {
		_ = c.SetReadDeadline(time.Time{})
		dbg("[conn#%d] closed before any byte (err=%v)", id, err)
		_ = c.Close()
		return
	}
	// dump whatever arrived in the first packet (already buffered, no extra wait)
	n := br.Buffered()
	if n > 200 {
		n = 200
	}
	head, _ := br.Peek(n)
	_ = c.SetReadDeadline(time.Time{})
	dbg("[conn#%d] first %d bytes:\n%s", id, len(head), hexdump(head))

	b0 := head[0]
	wrapped := &bufferedConn{Conn: c, r: br}
	if b0 == 0x01 {
		dbg("[conn#%d] -> FastCGI (first byte 0x01)", id)
		fcgiL.ch <- wrapped
	} else {
		dbg("[conn#%d] -> HTTP (first byte 0x%02x %q)", id, b0, printable(b0))
		httpL.ch <- wrapped
	}
}

func printable(b byte) string {
	if b >= 0x20 && b < 0x7f {
		return string([]byte{b})
	}
	return "."
}

// hexdump renders bytes as offset + hex + ascii, xxd-style, for wire debugging.
func hexdump(b []byte) string {
	var sb []byte
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		row := b[i:end]
		line := []byte(strconv.FormatInt(int64(i), 16))
		for len(line) < 4 {
			line = append([]byte{'0'}, line...)
		}
		line = append(line, ' ', ' ')
		for j := 0; j < 16; j++ {
			if j < len(row) {
				line = append(line, hexByte(row[j])...)
				line = append(line, ' ')
			} else {
				line = append(line, ' ', ' ', ' ')
			}
		}
		line = append(line, ' ', '|')
		for _, x := range row {
			line = append(line, printable(x)[0])
		}
		line = append(line, '|', '\n')
		sb = append(sb, line...)
	}
	return string(sb)
}

func hexByte(b byte) []byte {
	const h = "0123456789abcdef"
	return []byte{h[b>>4], h[b&0xf]}
}

// bufferedConn serves reads from a bufio.Reader (which holds peeked bytes),
// delegating everything else to the underlying conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func main() {
	flags := log.LstdFlags | log.Lmsgprefix
	if debug {
		flags |= log.Lmicroseconds
	}
	log.SetFlags(flags)
	log.SetPrefix("[sshjump] ")
	if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}
	initSyslog()

	inf("==== sshjump %s starting (pid=%d go=%s %s/%s debug=%v) ====",
		version, os.Getpid(), runtime.Version(), runtime.GOOS, runtime.GOARCH, debug)
	inf("config: app=%s idleTimeout=%s socket=%s tcp=%q log=%s", appName, idleTimeout, socketPath, tcpAddr, logPath)
	for _, e := range os.Environ() {
		if len(e) >= 8 && e[:8] == "SSHJUMP_" {
			dbg("env: %s", e)
		}
	}

	go watchdog()

	if tcpAddr != "" {
		inf("listening on tcp:%s (HTTP debug)", tcpAddr)
		if err := http.ListenAndServe(tcpAddr, tag("http", http.HandlerFunc(route))); err != nil {
			log.Fatalf("server error: %v", err)
		}
		return
	}
	if err := serveUnixMux(socketPath, http.HandlerFunc(route)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
