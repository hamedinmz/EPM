package main

import (
	"os"
	"testing"
)

// Run only against a disposable AD employee with explicitly delegated permissions.
func TestADIntegration(t *testing.T) {
	if os.Getenv("AD_TEST_ENABLE") != "yes" {
		t.Skip("set AD_TEST_ENABLE=yes for live AD integration")
	}
	a := activeDirectory{address: required("AD_URL"), bindDN: required("AD_BIND_DN"), password: required("AD_BIND_PASSWORD"), attribute: required("AD_PHONE_ATTRIBUTE"), bases: []string{required("AD_TEST_OU")}}
	username, password := required("AD_TEST_USERNAME"), required("AD_TEST_PASSWORD")
	if _, _, err := a.Login(username, ""); err == nil {
		t.Fatal("empty password accepted")
	}
	if _, _, err := a.Login("*)(sAMAccountName=*)", password); err == nil {
		t.Fatal("filter injection accepted")
	}
	guid, u, err := a.Login(username, password)
	if err != nil {
		t.Fatal("test login failed; check configuration")
	}
	current, err := a.Read(guid)
	if err != nil || current.Username != u.Username {
		t.Fatal("GUID read failed")
	}
	if _, err = a.Update(guid, u.Phone, "stale-version"); err != errConflict {
		t.Fatal("stale edit accepted")
	}
	// Writing the same existing value exercises atomic modify and readback without changing the phone.
	if u.Phone == "" {
		t.Fatal("provision a nonempty phone on the test employee")
	}
	updated, err := a.Update(guid, u.Phone, u.Version)
	if err != nil || updated.Phone != u.Phone {
		t.Fatal("atomic modify/readback failed")
	}
	// A bad hostname/chain must fail before credentials can be sent.
	bad := a
	bad.address = required("AD_TEST_UNTRUSTED_URL")
	if c, err := bad.connect(); err == nil {
		c.Close()
		t.Fatal("untrusted LDAPS endpoint accepted")
	}
}
func TestGUIDFilter(t *testing.T) {
	f, err := guidFilter("00112233445566778899aabbccddeeff")
	if err != nil || f != `(objectGUID=\00\11\22\33\44\55\66\77\88\99\aa\bb\cc\dd\ee\ff)` {
		t.Fatal("wrong GUID byte order or escaping")
	}
	if _, err = guidFilter("bad"); err == nil {
		t.Fatal("invalid GUID accepted")
	}
	a := activeDirectory{attribute: "telephoneNumber"}
	if a.change("guid", "123", "456").Changes[0].Modification.Type != "telephoneNumber" {
		t.Fatal("wrong attribute")
	}
}
