package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
)

//go:embed web/*
var assets embed.FS

type user struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Phone    string `json:"phone"`
	Version  string `json:"version"`
}
type directory interface {
	Login(string, string) (string, user, error)
	Read(string) (user, error)
	Update(string, string, string) (user, error)
}
type session struct {
	GUID, CSRF string
	Expires    time.Time
}
type server struct {
	dir         directory
	origin      string
	mu          sync.Mutex
	sessions    map[string]session
	loginSlots  chan struct{}
	attempts    map[string]attempt
	phonePolicy *regexp.Regexp
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func reply(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
func failure(w http.ResponseWriter, code int, message string) {
	reply(w, code, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		failure(w, 415, "Send application/json.")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			failure(w, 413, "Request body too large.")
		} else {
			failure(w, 400, "Invalid request body.")
		}
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		failure(w, 400, "Invalid request body.")
		return false
	}
	return true
}
func (s *server) cookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{Name: "__Host-epm", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 900})
}
func (s *server) newSession(w http.ResponseWriter, old string, guid string) session {
	id := token()
	v := session{guid, token(), time.Now().Add(15 * time.Minute)}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, old)
	for key, value := range s.sessions {
		if time.Now().After(value.Expires) {
			delete(s.sessions, key)
		}
	}
	// shortcut: sessions live in one process; use a shared expiring store before scaling out.
	if len(s.sessions) >= 10000 {
		for key := range s.sessions {
			delete(s.sessions, key)
			break
		}
	}
	s.sessions[id] = v
	s.cookie(w, id)
	return v
}
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" {
			http.NotFound(w, r)
			return
		}
		files, _ := fs.Sub(assets, "web")
		http.FileServer(http.FS(files)).ServeHTTP(w, r)
		return
	}
	if r.ContentLength > 4096 {
		failure(w, 413, "Request body too large.")
		return
	}
	expected := map[string]string{"/api/me": "GET", "/api/login": "POST", "/api/me/phone": "PUT", "/api/logout": "POST"}[r.URL.Path]
	if expected == "" {
		failure(w, 404, "Not found.")
		return
	}
	if r.Method != expected {
		w.Header().Set("Allow", expected)
		failure(w, 405, "Method not allowed.")
		return
	}
	if r.Method != "GET" && r.Header.Get("Origin") != s.origin {
		failure(w, 403, "Invalid request origin. Reload the page.")
		return
	}
	id := ""
	if c, err := r.Cookie("__Host-epm"); err == nil {
		id = c.Value
	}
	s.mu.Lock()
	v, ok := s.sessions[id]
	if ok && time.Now().After(v.Expires) {
		delete(s.sessions, id)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		v = s.newSession(w, id, "")
		reply(w, 401, map[string]string{"error": "Please sign in to continue.", "csrfToken": v.CSRF})
		return
	}
	if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(v.CSRF)) != 1 {
		failure(w, 403, "Security check failed. Reload the page and try again.")
		return
	}
	if r.URL.Path == "/api/login" {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decode(w, r, &body) {
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if body.Username == "" || len(body.Username) > 256 || body.Password == "" || len(body.Password) > 1024 {
			failure(w, 400, "Enter your username and password.")
			return
		}
		select {
		case s.loginSlots <- struct{}{}:
			defer func() { <-s.loginSlots }()
		default:
			failure(w, 429, "Sign-in is busy. Please try again shortly.")
			return
		}
		key := throttleKey(strings.ToLower(body.Username))
		if !s.allowLogin(key, time.Now()) || !s.allowLogin("global", time.Now()) {
			w.Header().Set("Retry-After", "60")
			audit("login", "throttled", key)
			failure(w, 429, "Too many sign-in attempts. Try again later.")
			return
		}
		guid, u, err := s.dir.Login(body.Username, body.Password)
		if err != nil {
			audit("login", "denied", key)
			reply(w, 401, map[string]string{"error": "Unable to sign in. Check your credentials or try again later.", "csrfToken": v.CSRF})
			return
		}
		audit("login", "success", guid)
		v = s.newSession(w, id, guid)
		reply(w, 200, map[string]any{"user": u, "csrfToken": v.CSRF})
		return
	}
	if r.URL.Path == "/api/logout" {
		audit("logout", "success", v.GUID)
		v = s.newSession(w, id, "")
		reply(w, 200, map[string]string{"csrfToken": v.CSRF})
		return
	}
	if v.GUID == "" {
		reply(w, 401, map[string]string{"error": "Please sign in to continue.", "csrfToken": v.CSRF})
		return
	}
	var u user
	var err error
	if r.Method == "PUT" {
		var body struct {
			Phone   string `json:"phone"`
			Version string `json:"version"`
		}
		if !decode(w, r, &body) {
			return
		}
		body.Phone = strings.TrimSpace(body.Phone)
		if !validPhone(body.Phone) || (s.phonePolicy != nil && !s.phonePolicy.MatchString(body.Phone)) {
			failure(w, 422, "Enter a valid phone number with at least 3 digits.")
			return
		}
		if body.Version == "" {
			failure(w, 428, "Reload your profile before submitting.")
			return
		}
		u, err = s.dir.Update(v.GUID, body.Phone, body.Version)
		if errors.Is(err, errConflict) {
			audit("update", "conflict", v.GUID)
			failure(w, 409, "Your phone changed since you loaded it. Reload the page and review before submitting again.")
			return
		}
		if err != nil {
			audit("update", "unconfirmed", v.GUID)
		} else {
			audit("update", "success", v.GUID)
		}
	} else {
		u, err = s.dir.Read(v.GUID)
	}
	if err != nil {
		failure(w, 502, "The directory could not confirm the request. Your displayed number has not changed; reload before retrying.")
		return
	}
	reply(w, 200, map[string]any{"user": u, "csrfToken": v.CSRF})
}

var phonePattern = regexp.MustCompile(`^[+0-9(). -]{3,32}$`)

func validPhone(phone string) bool {
	count := 0
	for _, c := range phone {
		if c >= '0' && c <= '9' {
			count++
		}
	}
	return phonePattern.MatchString(phone) && count >= 3
}

type attempt struct {
	Count int
	Until time.Time
}

func throttleKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func audit(event, outcome, identity string) {
	log.Printf("audit event=%s outcome=%s actor=%s", event, outcome, throttleKey(identity)[:16])
}
func (s *server) allowLogin(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempts == nil {
		s.attempts = make(map[string]attempt)
	}
	for k, v := range s.attempts {
		if !now.Before(v.Until) {
			delete(s.attempts, k)
		}
	}
	v, exists := s.attempts[key]
	if !exists {
		if len(s.attempts) >= 10000 {
			return false
		}
		v.Until = now.Add(time.Minute)
	}
	limit := 5
	if key == "global" {
		limit = 30
	}
	if v.Count >= limit {
		return false
	}
	v.Count++
	s.attempts[key] = v
	return true
}
func required(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("Set %s", name)
	}
	return v
}
func main() {
	origin := required("PUBLIC_ORIGIN")
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		log.Fatal("PUBLIC_ORIGIN must be an HTTPS origin without trailing slash")
	}
	address := required("AD_URL")
	dc, err := url.Parse(address)
	if err != nil || dc.Scheme != "ldaps" || dc.Hostname() == "" || dc.User != nil || dc.Path != "" || dc.RawQuery != "" || dc.Fragment != "" {
		log.Fatal("AD_URL must be a single ldaps:// domain controller endpoint")
	}
	attribute := required("AD_PHONE_ATTRIBUTE")
	if attribute != "mobile" && attribute != "telephoneNumber" {
		log.Fatal("AD_PHONE_ATTRIBUTE must be mobile or telephoneNumber")
	}
	bases := strings.Split(required("AD_ALLOWED_OUS"), ";")
	if len(bases) > 4 {
		log.Fatal("Configure at most four disjoint OUs")
	}
	for i, base := range bases {
		bases[i] = strings.TrimSpace(base)
		if _, err := ldap.ParseDN(bases[i]); err != nil || bases[i] == "" {
			log.Fatal("Invalid AD_ALLOWED_OUS")
		}
	}
	policy, err := regexp.Compile("^(?:" + required("PHONE_PATTERN") + ")$")
	if err != nil {
		log.Fatal("Invalid PHONE_PATTERN")
	}
	a := activeDirectory{address: address, bindDN: required("AD_BIND_DN"), password: required("AD_BIND_PASSWORD"), attribute: attribute, bases: bases}
	s := &server{dir: a, origin: origin, sessions: make(map[string]session), loginSlots: make(chan struct{}, 8), phonePolicy: policy}
	h := &http.Server{Addr: "127.0.0.1:8080", Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := h.Shutdown(shutdown); err != nil {
			_ = h.Close()
		}
		close(done)
	}()
	log.Print("Listening on loopback behind HTTPS reverse proxy")
	if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("HTTP server stopped unexpectedly")
	}
	<-done
}
