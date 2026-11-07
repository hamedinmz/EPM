package main

import (
	"crypto/tls"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestConditionalChange(t *testing.T) {
	a := activeDirectory{attribute: "mobile"}
	m := a.change("<GUID=00112233445566778899aabbccddeeff>", "123", "456")
	if len(m.Changes) != 2 || m.Changes[0].Operation != ldap.DeleteAttribute || m.Changes[0].Modification.Vals[0] != "123" || m.Changes[1].Operation != ldap.AddAttribute {
		t.Fatal("must atomically delete expected value then add replacement")
	}
	m = a.change("guid", "", "456")
	if len(m.Changes) != 1 || m.Changes[0].Operation != ldap.AddAttribute {
		t.Fatal("unset value must use add, never replace")
	}
}
func TestThrottleBounded(t *testing.T) {
	s := &server{attempts: map[string]attempt{}}
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !s.allowLogin("key", now) {
			t.Fatal("early throttle")
		}
	}
	if s.allowLogin("key", now) {
		t.Fatal("unbounded login attempts")
	}
	if !s.allowLogin("key", now.Add(2*time.Minute)) {
		t.Fatal("window did not expire")
	}
}

func TestUntrustedTLS(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer endpoint.Close()
	a := activeDirectory{address: "ldaps" + strings.TrimPrefix(endpoint.URL, "https"), bindDN: "not-a-real-account", password: "not-a-real-secret"}
	c, err := a.connect()
	if err == nil {
		c.Close()
		t.Fatal("untrusted certificate accepted")
	}
	var verification *tls.CertificateVerificationError
	if !errors.As(err, &verification) {
		t.Fatalf("expected certificate verification failure, got %T", err)
	}
}
func TestConfiguredPolicy(t *testing.T) {
	s := &server{dir: &fakeDirectory{}, origin: "https://example.test", sessions: map[string]session{"s": {GUID: "guid", CSRF: "csrf", Expires: time.Now().Add(time.Minute)}}, phonePolicy: regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)}
	r := httptest.NewRequest("PUT", "/api/me/phone", strings.NewReader(`{"phone":"123","version":"v"}`))
	r.Header.Set("Origin", s.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", "csrf")
	r.AddCookie(&http.Cookie{Name: "__Host-epm", Value: "s"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 422 {
		t.Fatal("configured phone policy ignored")
	}
}
