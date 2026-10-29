package packet

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func mustNew(t *testing.T, app string) *Packet {
	t.Helper()
	p, err := New(app, "Test", AppInfo{Name: "Demo", Version: "0.0.1"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	p := mustNew(t, "demo-app")
	p.Payload = json.RawMessage(`{"theme":"dark","n":3}`)
	data, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, warns, err := Parse(data, ParseOptions{ExpectAppID: "demo-app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if got.PacketID != p.PacketID || got.AppID != "demo-app" || got.RevisionID != p.RevisionID {
		t.Fatalf("identity changed: %+v", got)
	}
	if !bytes.Contains(got.Payload, []byte(`"theme"`)) {
		t.Fatalf("payload lost: %s", got.Payload)
	}
	if got.CreatedAt != "2026-10-29T12:00:00.000Z" {
		t.Fatalf("createdAt = %s", got.CreatedAt)
	}
}

func TestChecksumDetectsEdit(t *testing.T) {
	t.Parallel()
	data, _ := mustNew(t, "demo-app").Marshal()
	edited := bytes.Replace(data, []byte(`"Test"`), []byte(`"Edited"`), 1)
	_, warns, err := Parse(edited, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || warns[0].Code != WarnChecksumMismatch {
		t.Fatalf("want checksum_mismatch, got %v", warns)
	}
}

func TestNoChecksumWarns(t *testing.T) {
	t.Parallel()
	p := mustNew(t, "demo-app")
	b, _ := json.Marshal(p)
	_, warns, err := Parse(b, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || warns[0].Code != WarnNoChecksum {
		t.Fatalf("want no_checksum, got %v", warns)
	}
}

func TestAppIsolation(t *testing.T) {
	t.Parallel()
	data, _ := mustNew(t, "legal-app").Marshal()
	_, _, err := Parse(data, ParseOptions{ExpectAppID: "dating-app"})
	if code(err) != CodeAppMismatch {
		t.Fatalf("want app_mismatch, got %v", err)
	}
}

func TestRejectsHostileInput(t *testing.T) {
	t.Parallel()
	valid, _ := mustNew(t, "demo-app").Marshal()
	deep := strings.Repeat(`{"a":`, MaxPayloadDepth+2) + `1` + strings.Repeat(`}`, MaxPayloadDepth+2)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"not json", []byte(`nope`), CodeBadJSON},
		{"array", []byte(`[]`), CodeNotPacket},
		{"wrong format", []byte(`{"format":"payout-packet"}`), CodeNotPacket},
		{"no version", []byte(`{"format":"gold-packet"}`), CodeBadVersion},
		{"fractional version", []byte(`{"format":"gold-packet","schemaVersion":1.5}`), CodeBadVersion},
		{"future version", []byte(`{"format":"gold-packet","schemaVersion":2}`), CodeFutureVersion},
		{"too large", bytes.Repeat([]byte(" "), MaxBytes+1), CodeTooLarge},
		{"bad app id", bytes.Replace(valid, []byte(`"demo-app"`), []byte(`"Bad App!"`), 1), CodeBadValue},
		{"bad packet id", bytes.Replace(valid, []byte(`"pk_`), []byte(`"xx_`), 1), CodeBadValue},
		{"payload not object", bytes.Replace(valid, []byte(`"payload": {}`), []byte(`"payload": [1]`), 1), CodeBadPayload},
		{"payload too deep", bytes.Replace(valid, []byte(`"payload": {}`), []byte(`"payload": `+deep), 1), CodeBadPayload},
		{"bad date", bytes.Replace(valid, []byte(`"savedAt": "2026`), []byte(`"savedAt": "soon 2026`), 1), CodeBadValue},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(tc.data, ParseOptions{})
			if code(err) != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}

func TestUnknownFieldsDropped(t *testing.T) {
	t.Parallel()
	var m map[string]any
	data, _ := mustNew(t, "demo-app").Marshal()
	_ = json.Unmarshal(data, &m)
	m["evil"] = "<script>"
	b, _ := json.Marshal(m)
	p, _, err := Parse(b, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := p.Marshal()
	if bytes.Contains(out, []byte("evil")) {
		t.Fatal("unknown field survived a parse")
	}
}

func TestPayloadValidatorRebuilds(t *testing.T) {
	t.Parallel()
	p := mustNew(t, "demo-app")
	p.Payload = json.RawMessage(`{"theme":"dark","junk":1}`)
	data, _ := p.Marshal()
	got, _, err := Parse(data, ParseOptions{ValidatePayload: func(json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"theme":"dark"}`), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got.Payload, []byte("junk")) {
		t.Fatal("validator output not used")
	}
	_, _, err = Parse(data, ParseOptions{ValidatePayload: func(json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("theme must be light or dark")
	}})
	if code(err) != CodeBadPayload {
		t.Fatalf("want bad_payload, got %v", err)
	}
}

func TestNameIsCleaned(t *testing.T) {
	t.Parallel()
	p, _ := New("demo-app", "  Bad\x00Name\n"+strings.Repeat("x", 200), AppInfo{}, t0)
	if strings.ContainsAny(p.Name, "\x00\n") || len([]rune(p.Name)) > MaxName {
		t.Fatalf("name not cleaned: %q", p.Name)
	}
}

func TestAttestationValidation(t *testing.T) {
	t.Parallel()
	good := Attestation{
		Kind: KindEmail, Method: MethodEmailLink, Subject: strings.Repeat("a", 64),
		IssuedAt: "2026-10-29T12:00:00.000Z", KeyID: "k1", Signature: strings.Repeat("A", 86),
	}
	cases := map[string]func(*Attestation){
		"kind":      func(a *Attestation) { a.Kind = "ssn" },
		"method":    func(a *Attestation) { a.Method = "carrier-pigeon" },
		"subject":   func(a *Attestation) { a.Subject = "+15555550123" },
		"keyId":     func(a *Attestation) { a.KeyID = "Bad Key" },
		"signature": func(a *Attestation) { a.Signature = "short" },
		"issuedAt":  func(a *Attestation) { a.IssuedAt = "yesterday" },
		"expiresAt": func(a *Attestation) { a.ExpiresAt = "tomorrow" },
	}
	for field, mutate := range cases {
		a := good
		mutate(&a)
		p := mustNew(t, "demo-app")
		p.Attestations = []Attestation{a}
		data, _ := p.Marshal()
		if _, _, err := Parse(data, ParseOptions{}); code(err) != CodeBadValue {
			t.Errorf("%s: want bad_value, got %v", field, err)
		}
	}
	p := mustNew(t, "demo-app")
	p.Attestations = []Attestation{good}
	data, _ := p.Marshal()
	if _, _, err := Parse(data, ParseOptions{}); err != nil {
		t.Fatalf("good attestation rejected: %v", err)
	}
	p.Attestations = make([]Attestation, MaxAttestations+1)
	for i := range p.Attestations {
		p.Attestations[i] = good
	}
	data, _ = p.Marshal()
	if _, _, err := Parse(data, ParseOptions{}); code(err) != CodeTooMany {
		t.Fatalf("want too_many, got %v", err)
	}
}

func TestCompareRevisions(t *testing.T) {
	t.Parallel()
	a := mustNew(t, "demo-app")
	b := NextRevision(a, t0.Add(time.Hour))
	c := NextRevision(a, t0.Add(2*time.Hour)) // a second child of a: diverges from b
	other := mustNew(t, "demo-app")

	tests := []struct {
		name         string
		local, other *Packet
		want         Relation
	}{
		{"identical", a, a, Identical},
		{"newer", a, b, IncomingNewer},
		{"older", b, a, IncomingOlder},
		{"diverged", b, c, Diverged},
		{"different", a, other, DifferentPacket},
	}
	for _, tc := range tests {
		if got := Compare(tc.local, tc.other); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	if b.ParentRevisionID == nil || *b.ParentRevisionID != a.RevisionID {
		t.Error("parent not recorded")
	}
	if len(a.Lineage) != 1 {
		t.Error("NextRevision modified its input")
	}
}

func TestLineageCapped(t *testing.T) {
	t.Parallel()
	p := mustNew(t, "demo-app")
	for range MaxLineage + 20 {
		p = NextRevision(p, t0)
	}
	if len(p.Lineage) != MaxLineage || p.Lineage[len(p.Lineage)-1] != p.RevisionID {
		t.Fatalf("lineage len %d, last ok: %v", len(p.Lineage), p.Lineage[len(p.Lineage)-1] == p.RevisionID)
	}
}

func TestSeparateCopy(t *testing.T) {
	t.Parallel()
	a := mustNew(t, "demo-app")
	a.Attestations = []Attestation{{Kind: KindDevice}}
	cp := AsSeparateCopy(a, " (copy)", t0)
	if cp.PacketID == a.PacketID || cp.Origin == nil || cp.Origin.PacketID != a.PacketID {
		t.Fatalf("copy identity wrong: %+v", cp)
	}
	if len(cp.Attestations) != 0 {
		t.Fatal("attestations must not carry to a copy")
	}
	if Compare(a, cp) != DifferentPacket {
		t.Fatal("copy should be a different packet")
	}
}

func TestNewIDShape(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 1000 {
		id := NewID("pk")
		if !idRE["pk"].MatchString(id) || len(id) != 16 {
			t.Fatalf("bad id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestEmptyLineageIsRepaired(t *testing.T) {
	t.Parallel()
	var m map[string]any
	data, _ := mustNew(t, "demo-app").Marshal()
	_ = json.Unmarshal(data, &m)
	m["lineage"] = []any{}
	b, _ := json.Marshal(m)
	p, _, err := Parse(b, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Lineage) != 1 || p.Lineage[0] != p.RevisionID {
		t.Fatalf("lineage not repaired: %v", p.Lineage)
	}
}

// Found by fuzzing: encoding/json matches "AppId" to appId, which other
// readers do not. Parsers must not disagree about what a file says.
func TestKeyCaseIsStrict(t *testing.T) {
	t.Parallel()
	data, _ := mustNew(t, "demo-app").Marshal()
	for _, swap := range [][2]string{{`"appId"`, `"AppId"`}, {`"payload"`, `"PAYLOAD"`}, {`"alg"`, `"Alg"`}} {
		b := bytes.Replace(data, []byte(swap[0]), []byte(swap[1]), 1)
		if _, _, err := Parse(b, ParseOptions{}); code(err) != CodeBadValue {
			t.Errorf("%s: want bad_value, got %v", swap[1], err)
		}
	}
}

func FuzzParse(f *testing.F) {
	valid, _ := New("demo-app", "x", AppInfo{}, t0)
	data, _ := valid.Marshal()
	f.Add(data)
	f.Add([]byte(`{"format":"gold-packet","schemaVersion":1}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, in []byte) {
		p, _, err := Parse(in, ParseOptions{})
		if err == nil && p == nil {
			t.Fatal("nil packet without error")
		}
	})
}
