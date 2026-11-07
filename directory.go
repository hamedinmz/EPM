package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type activeDirectory struct {
	address, bindDN, password, attribute string
	bases                                []string
}

const employeeFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

var errConflict = errors.New("concurrent modification")

func version(phone string) string {
	sum := sha256.Sum256([]byte(phone))
	return hex.EncodeToString(sum[:])
}
func (a activeDirectory) connect() (*ldap.Conn, error) {
	c, err := ldap.DialURL(a.address, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	if err != nil {
		return nil, err
	}
	c.SetTimeout(5 * time.Second)
	if err = c.Bind(a.bindDN, a.password); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
func (a activeDirectory) find(c *ldap.Conn, filter string) (*ldap.Entry, error) {
	var found *ldap.Entry
	for _, base := range a.bases {
		result, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, "(&"+employeeFilter+filter+")", []string{"displayName", "sAMAccountName", a.attribute, "objectGUID"}, nil))
		if err != nil {
			return nil, err
		}
		for _, e := range result.Entries {
			if found != nil {
				return nil, errors.New("ambiguous employee")
			}
			found = e
		}
	}
	if found == nil {
		return nil, errors.New("employee unavailable")
	}
	return found, nil
}
func (a activeDirectory) profile(e *ldap.Entry) user {
	phone := e.GetAttributeValue(a.attribute)
	return user{Name: e.GetAttributeValue("displayName"), Username: e.GetAttributeValue("sAMAccountName"), Phone: phone, Version: version(phone)}
}
func guidFilter(guid string) (string, error) {
	b, err := hex.DecodeString(guid)
	if err != nil || len(b) != 16 {
		return "", errors.New("invalid identity")
	}
	var escaped strings.Builder
	for _, v := range b {
		fmt.Fprintf(&escaped, "\\%02x", v)
	}
	return "(objectGUID=" + escaped.String() + ")", nil
}
func (a activeDirectory) Login(username, password string) (string, user, error) {
	if password == "" {
		return "", user{}, errors.New("empty password")
	}
	c, err := a.connect()
	if err != nil {
		return "", user{}, err
	}
	defer c.Close()
	escaped := ldap.EscapeFilter(username)
	e, err := a.find(c, "(|(sAMAccountName="+escaped+")(userPrincipalName="+escaped+"))")
	if err != nil {
		return "", user{}, err
	}
	guid := e.GetRawAttributeValue("objectGUID")
	if len(guid) != 16 {
		return "", user{}, errors.New("missing GUID")
	}
	if err = c.Bind(e.DN, password); err != nil {
		return "", user{}, err
	}
	return hex.EncodeToString(guid), a.profile(e), nil
}
func (a activeDirectory) Read(guid string) (user, error) {
	filter, err := guidFilter(guid)
	if err != nil {
		return user{}, err
	}
	c, err := a.connect()
	if err != nil {
		return user{}, err
	}
	defer c.Close()
	e, err := a.find(c, filter)
	if err != nil {
		return user{}, err
	}
	return a.profile(e), nil
}
func (a activeDirectory) change(target, old, phone string) *ldap.ModifyRequest {
	m := ldap.NewModifyRequest(target, nil)
	// Deleting the expected value and adding its replacement is one atomic LDAP modify.
	if old != "" {
		m.Delete(a.attribute, []string{old})
	}
	m.Add(a.attribute, []string{phone})
	return m
}
func (a activeDirectory) Update(guid, phone, expected string) (user, error) {
	filter, err := guidFilter(guid)
	if err != nil {
		return user{}, err
	}
	c, err := a.connect()
	if err != nil {
		return user{}, err
	}
	defer c.Close()
	e, err := a.find(c, filter)
	if err != nil {
		return user{}, err
	}
	old := e.GetAttributeValue(a.attribute)
	if version(old) != expected {
		return user{}, errConflict
	}
	// GUID binding prevents a renamed or reused DN from changing the update target.
	target := "<GUID=" + guid + ">"
	if err = c.Modify(a.change(target, old, phone)); err != nil {
		if ldap.IsErrorAnyOf(err, ldap.LDAPResultNoSuchAttribute, ldap.LDAPResultAttributeOrValueExists, ldap.LDAPResultConstraintViolation) {
			return user{}, errConflict
		}
		return user{}, err
	}
	e, err = a.find(c, filter)
	if err != nil {
		return user{}, err
	}
	u := a.profile(e)
	if u.Phone != phone {
		return user{}, errors.New("readback mismatch")
	}
	return u, nil
}
