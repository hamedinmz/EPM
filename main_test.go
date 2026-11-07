package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeDirectory struct {
	target string
	fail   bool
}

func (d *fakeDirectory) Login(string, string) (string, user, error) {
	return "alice-dn", user{Name: "Alice", Username: "alice", Phone: "123", Version: version("123")}, nil
}
func (d *fakeDirectory) Read(dn string) (user, error) {
	d.target = dn
	return user{Name: "Alice", Username: "alice", Phone: "123", Version: version("123")}, nil
}
func (d *fakeDirectory) Update(dn, phone, expected string) (user, error) {
	d.target = dn
	if d.fail {
		return user{}, errors.New("AD failure")
	}
	return user{Name: "Alice", Username: "alice", Phone: phone, Version: version(phone)}, nil
}
func TestAPI(t *testing.T) {
	d := &fakeDirectory{}
	s := &server{dir: d, origin: "https://example.test", sessions: map[string]session{"session": {GUID: "alice-dn", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}}, loginSlots: make(chan struct{}, 1)}
	call := func(method, path, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Origin", s.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: "__Host-epm", Value: "session"})
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/me", "", ""); w.Code != 200 || d.target != "alice-dn" {
		t.Fatalf("own profile: %d", w.Code)
	}
	for _, tc := range []struct {
		body, csrf string
		want       int
	}{
		{`{"phone":"456"}`, "", 403},
		{`{"phone":"456","username":"bob"}`, "csrf", 400},
		{`{"phone":"<script>"}`, "csrf", 422},
		{`{"phone":"456","version":"v"}`, "csrf", 200},
	} {
		if w := call("PUT", "/api/me/phone", tc.body, tc.csrf); w.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.body, w.Code, tc.want)
		}
	}
	if d.target != "alice-dn" {
		t.Fatal("update escaped session identity")
	}
	d.fail = true
	if w := call("PUT", "/api/me/phone", `{"phone":"789","version":"v"}`, "csrf"); w.Code != 502 {
		t.Fatal("AD failure reported as success")
	}
	s.sessions["session"] = session{GUID: "alice-dn", CSRF: "csrf", Expires: time.Now().Add(-time.Second)}
	w := call("GET", "/api/me", "", "")
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 401 || body["csrfToken"] == "" {
		t.Fatal("expired session did not bootstrap login")
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatal("unsafe session cookie")
	}
}
func TestPhone(t *testing.T) {
	for _, p := range []string{"123", "+1 (212) 555-0100"} {
		if !validPhone(p) {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"", "12", "+++", "123<script>", strings.Repeat("1", 33)} {
		if validPhone(p) {
			t.Fatal(p)
		}
	}
}

func TestLoginAndLogout(t *testing.T) {
	s := &server{dir: &fakeDirectory{}, origin: "https://example.test", sessions: map[string]session{}, loginSlots: make(chan struct{}, 1)}
	request := func(method, path, body, origin, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/api/me", "", "", "", nil)
	var bootstrap struct {
		CSRF string `json:"csrfToken"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &bootstrap)
	anon := w.Result().Cookies()[0]
	for _, tc := range []struct {
		origin, csrf, body string
		want               int
	}{
		{"https://evil.test", bootstrap.CSRF, `{"username":"alice","password":"secret"}`, 403},
		{s.origin, "", `{"username":"alice","password":"secret"}`, 403},
		{s.origin, bootstrap.CSRF, `{"username":"alice","password":""}`, 400},
		{s.origin, bootstrap.CSRF, `{"username":"` + strings.Repeat("a", 5000) + `","password":"secret"}`, 413},
	} {
		got := request("POST", "/api/login", tc.body, tc.origin, tc.csrf, anon)
		if got.Code != tc.want {
			t.Fatalf("login security got %d want %d", got.Code, tc.want)
		}
	}
	w = request("POST", "/api/login", `{"username":"alice","password":"secret"}`, s.origin, bootstrap.CSRF, anon)
	if w.Code != 200 {
		t.Fatalf("login %d", w.Code)
	}
	auth := w.Result().Cookies()[0]
	if auth.Value == anon.Value {
		t.Fatal("login did not rotate session")
	}
	var signedIn struct {
		CSRF string `json:"csrfToken"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &signedIn)
	if signedIn.CSRF == bootstrap.CSRF {
		t.Fatal("login did not rotate CSRF")
	}
	if _, ok := s.sessions[anon.Value]; ok {
		t.Fatal("old session valid")
	}
	w = request("POST", "/api/logout", "", s.origin, signedIn.CSRF, auth)
	if w.Code != 200 {
		t.Fatal("logout failed")
	}
	if _, ok := s.sessions[auth.Value]; ok {
		t.Fatal("logout retained session")
	}
	w = request("GET", "/api/me", "", "", "", auth)
	if w.Code != 401 {
		t.Fatal("logged out session reused")
	}
}
