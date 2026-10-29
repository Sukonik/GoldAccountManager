package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/sukonik/goldaccountmanager/packet"
)

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// Normalize puts a raw email address or phone number in the canonical form
// that Subject hashes. Equivalent inputs must normalize identically, or the
// same person would get different subjects.
//
// Emails are lowercased and must be plain ASCII addresses of the form
// local@domain. Names, comments, quoted local parts, IP-literal domains and
// non-ASCII addresses are rejected: a confirmation channel needs one
// unambiguous address, and a small strict check is easier to trust than a
// general parser on untrusted input. Phone numbers must already be international (leading
// "+" and country code); spaces, dashes, dots and parentheses are removed.
func Normalize(kind packet.Kind, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch kind {
	case packet.KindEmail:
		return normalizeEmail(raw)
	case packet.KindPhone:
		cleaned := strings.Map(func(r rune) rune {
			if strings.ContainsRune(" -.()", r) {
				return -1
			}
			return r
		}, raw)
		if !e164.MatchString(cleaned) {
			return "", errors.New("phone number must include the country code, like +15555550123")
		}
		return cleaned, nil
	}
	return "", errors.New("unsupported kind")
}

// Subject returns the keyed hash that identifies a confirmed target inside one
// app. appSecret must be at least 32 bytes and kept private to the server.
// normalized must come from Normalize.
//
// The result is stable for one (app, kind, target), and unrelated across apps.
// It can be used to look the target up for recovery without storing it.
func Subject(appSecret []byte, appID string, kind packet.Kind, normalized string) (string, error) {
	if len(appSecret) < 32 {
		return "", errors.New("app secret must be at least 32 bytes")
	}
	m := hmac.New(sha256.New, appSecret)
	for _, part := range []string{"gold-subject-v1", appID, string(kind), normalized} {
		m.Write([]byte(part))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil)), nil
}

const localChars = "abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+/=?^_`{|}~.-"

func normalizeEmail(raw string) (string, error) {
	errBad := errors.New("not a valid email address")
	raw = strings.ToLower(raw)
	if len(raw) > 254 {
		return "", errBad
	}
	at := strings.LastIndexByte(raw, '@')
	if at < 1 {
		return "", errBad
	}
	local, domain := raw[:at], raw[at+1:]
	if len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", errBad
	}
	for _, r := range local {
		if !strings.ContainsRune(localChars, r) {
			return "", errBad
		}
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", errBad
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errBad
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", errBad
			}
		}
	}
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return "", errBad // an all-numeric last label looks like an IP address
	}
	return raw, nil
}
