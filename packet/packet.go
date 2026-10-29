package packet

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Envelope constants.
const (
	Format        = "gold-packet"
	SchemaVersion = 1
	FileExtension = ".gold"
)

// Limits bound everything a parser will accept.
const (
	MaxBytes        = 5 * 1024 * 1024
	MaxPayloadBytes = 4 * 1024 * 1024
	MaxPayloadDepth = 32
	MaxLineage      = 200
	MaxName         = 80
	MaxAttestations = 8
)

const timeLayout = "2006-01-02T15:04:05.000Z"

// Kind says what an attestation binds to the packet.
type Kind string

// Attestation kinds.
const (
	KindEmail  Kind = "email"
	KindPhone  Kind = "phone"
	KindDevice Kind = "device"
)

// Method says how the subject was confirmed. It is signed, so an app can
// require, say, a passkey for one action and accept an email link for another.
type Method string

// Confirmation methods. See docs/verification.md for the ladder.
const (
	MethodGoogle     Method = "google"
	MethodEmailLink  Method = "email-link"
	MethodEmailReply Method = "email-reply"
	MethodTelegram   Method = "telegram"
	MethodWhatsApp   Method = "whatsapp"
	MethodSMS        Method = "sms"
	MethodPasskey    Method = "passkey"
)

var (
	validKinds   = map[Kind]bool{KindEmail: true, KindPhone: true, KindDevice: true}
	validMethods = map[Method]bool{MethodGoogle: true, MethodEmailLink: true, MethodEmailReply: true, MethodTelegram: true, MethodWhatsApp: true, MethodSMS: true, MethodPasskey: true}

	subjectRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyIDRE   = regexp.MustCompile(`^[0-9a-z-]{1,32}$`)
	sigRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,200}$`)
)

// AppInfo records which build wrote the file.
type AppInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Origin is present when a packet was opened as a separate copy.
type Origin struct {
	PacketID   string `json:"packetId"`
	RevisionID string `json:"revisionId"`
	Relation   string `json:"relation"`
}

// Attestation is a server-signed statement that this packet's key is bound to
// a confirmed email, phone or device. Subject is a keyed hash, never the
// address or number itself. See package verify for creating and checking them.
type Attestation struct {
	Kind      Kind   `json:"kind"`
	Method    Method `json:"method"`
	Subject   string `json:"subject"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// Packet is a parsed, validated packet.
type Packet struct {
	Format           string          `json:"format"`
	SchemaVersion    int             `json:"schemaVersion"`
	AppID            string          `json:"appId"`
	PacketID         string          `json:"packetId"`
	Name             string          `json:"name"`
	RevisionID       string          `json:"revisionId"`
	ParentRevisionID *string         `json:"parentRevisionId"`
	Lineage          []string        `json:"lineage"`
	CreatedAt        string          `json:"createdAt"`
	SavedAt          string          `json:"savedAt"`
	App              AppInfo         `json:"app"`
	Origin           *Origin         `json:"origin,omitempty"`
	Payload          json.RawMessage `json:"payload"`
	Attestations     []Attestation   `json:"attestations"`
}

// Checksum is the integrity block written by Marshal.
type Checksum struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// file is the on-disk shape: the packet's fields plus the checksum.
type file struct {
	Packet
	Checksum Checksum `json:"checksum"`
}

// New creates an empty packet for appID. appID names the app's isolated
// account space: a packet only opens in the app it was made for.
func New(appID, name string, app AppInfo, now time.Time) (*Packet, error) {
	if !appIDRE.MatchString(appID) {
		return nil, bad(CodeBadValue, "appId", "app id must be 2-40 characters: lowercase letters, digits and hyphens, starting with a letter or digit")
	}
	rev := NewID("rv")
	ts := stamp(now)
	return &Packet{
		Format: Format, SchemaVersion: SchemaVersion,
		AppID: appID, PacketID: NewID("pk"), Name: cleanName(name, "My account"),
		RevisionID: rev, Lineage: []string{rev},
		CreatedAt: ts, SavedAt: ts, App: app,
		Payload: json.RawMessage(`{}`), Attestations: []Attestation{},
	}, nil
}

func stamp(t time.Time) string { return t.UTC().Truncate(time.Millisecond).Format(timeLayout) }

// cleanName removes control characters, trims space and caps the length.
func cleanName(s, fallback string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > MaxName {
		s = string([]rune(s)[:MaxName])
	}
	if s == "" {
		return fallback
	}
	return s
}

// Marshal serializes the packet with an integrity checksum. The checksum
// detects accidental damage only. It is not a signature.
func (p *Packet) Marshal() ([]byte, error) {
	cp := *p
	if cp.Lineage == nil {
		cp.Lineage = []string{cp.RevisionID}
	}
	if cp.Attestations == nil {
		cp.Attestations = []Attestation{}
	}
	if len(cp.Payload) == 0 {
		cp.Payload = json.RawMessage(`{}`)
	}
	sum, err := ChecksumOf(cp)
	if err != nil {
		return nil, err
	}
	out, err := marshalIndent(file{Packet: cp, Checksum: Checksum{Alg: "sha-256", Value: sum}})
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ParseOptions tune Parse. The zero value is valid.
type ParseOptions struct {
	// ExpectAppID, when set, rejects packets made for another app. Set it in
	// every real app: it is what keeps accounts isolated per app.
	ExpectAppID string
	// ValidatePayload, when set, rebuilds the payload from whitelisted fields
	// (return the sanitized JSON) or rejects it. The payload is application
	// data, so only the application can say what is valid.
	ValidatePayload func(json.RawMessage) (json.RawMessage, error)
}

// Parse reads a packet file. It never panics on hostile input. On success it
// returns the packet rebuilt from whitelisted fields, plus any warnings.
func Parse(data []byte, opt ParseOptions) (*Packet, []Warning, error) {
	if len(data) > MaxBytes {
		return nil, nil, bad(CodeTooLarge, "", "this file is too large to be a packet")
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, nil, bad(CodeBadJSON, "", "this file is not valid packet data (it could not be read as JSON)")
	}
	obj, ok := generic.(map[string]any)
	if !ok || obj["format"] != Format {
		return nil, nil, bad(CodeNotPacket, "", "this file is not a Gold packet")
	}
	ver, ok := obj["schemaVersion"].(float64)
	if !ok || ver < 1 || ver != float64(int(ver)) {
		return nil, nil, bad(CodeBadVersion, "schemaVersion", "this packet has no valid version number")
	}
	if int(ver) > SchemaVersion {
		return nil, nil, bad(CodeFutureVersion, "schemaVersion", "this packet was saved by a newer version (format %d; this build reads up to %d). Nothing was changed", int(ver), SchemaVersion)
	}

	if err := checkKeyCase(obj); err != nil {
		return nil, nil, err
	}

	var raw Packet
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, bad(CodeBadType, "", "a field has the wrong type")
	}
	p, err := validate(&raw, opt)
	if err != nil {
		return nil, nil, err
	}

	var warnings []Warning
	if cs, ok := obj["checksum"].(map[string]any); ok {
		delete(obj, "checksum")
		alg, _ := cs["alg"].(string)
		val, _ := cs["value"].(string)
		want, cerr := ChecksumOf(obj)
		if alg == "sha-256" && cerr == nil && !strings.EqualFold(val, want) {
			warnings = append(warnings, Warning{Code: WarnChecksumMismatch, Message: "The file changed after it was saved. That can mean accidental damage or a deliberate edit. Check the summary before opening it."})
		}
	} else {
		warnings = append(warnings, Warning{Code: WarnNoChecksum, Message: "This file has no integrity check."})
	}
	return p, warnings, nil
}

func validate(raw *Packet, opt ParseOptions) (*Packet, error) {
	if !appIDRE.MatchString(raw.AppID) {
		return nil, bad(CodeBadValue, "appId", "invalid app id")
	}
	if opt.ExpectAppID != "" && raw.AppID != opt.ExpectAppID {
		return nil, bad(CodeAppMismatch, "appId", "this packet belongs to a different app")
	}
	if !idRE["pk"].MatchString(raw.PacketID) {
		return nil, bad(CodeBadValue, "packetId", "invalid packet id")
	}
	if !idRE["rv"].MatchString(raw.RevisionID) {
		return nil, bad(CodeBadValue, "revisionId", "invalid revision id")
	}
	var parent *string
	if raw.ParentRevisionID != nil {
		if !idRE["rv"].MatchString(*raw.ParentRevisionID) {
			return nil, bad(CodeBadValue, "parentRevisionId", "invalid revision id")
		}
		v := *raw.ParentRevisionID
		parent = &v
	}

	lineage := raw.Lineage
	if lineage == nil {
		lineage = []string{raw.RevisionID}
	}
	for i, id := range lineage {
		if !idRE["rv"].MatchString(id) {
			return nil, bad(CodeBadValue, "lineage", "invalid revision id at position %d", i)
		}
	}
	if len(lineage) > MaxLineage {
		lineage = lineage[len(lineage)-MaxLineage:]
	}
	if len(lineage) == 0 || lineage[len(lineage)-1] != raw.RevisionID {
		lineage = append(append([]string(nil), lineage...), raw.RevisionID)
		if len(lineage) > MaxLineage {
			lineage = lineage[len(lineage)-MaxLineage:]
		}
	}
	lineage = append([]string(nil), lineage...)

	for _, d := range []struct{ path, v string }{{"createdAt", raw.CreatedAt}, {"savedAt", raw.SavedAt}} {
		if _, err := time.Parse(time.RFC3339Nano, d.v); err != nil {
			return nil, bad(CodeBadValue, d.path, "must be an ISO 8601 date and time")
		}
	}

	payload, err := validatePayload(raw.Payload, opt)
	if err != nil {
		return nil, err
	}

	if len(raw.Attestations) > MaxAttestations {
		return nil, bad(CodeTooMany, "attestations", "too many attestations (max %d)", MaxAttestations)
	}
	atts := make([]Attestation, 0, len(raw.Attestations))
	for i, a := range raw.Attestations {
		if err := validateAttestation(a); err != nil {
			err.Path = "attestations[" + strconv.Itoa(i) + "]." + err.Path
			return nil, err
		}
		atts = append(atts, a)
	}

	p := &Packet{
		Format: Format, SchemaVersion: SchemaVersion,
		AppID: raw.AppID, PacketID: raw.PacketID, Name: cleanName(raw.Name, "My account"),
		RevisionID: raw.RevisionID, ParentRevisionID: parent, Lineage: lineage,
		CreatedAt: raw.CreatedAt, SavedAt: raw.SavedAt,
		App:     AppInfo{Name: cleanName(raw.App.Name, ""), Version: truncate(cleanName(raw.App.Version, ""), 20)},
		Payload: payload, Attestations: atts,
	}
	if raw.Origin != nil {
		if !idRE["pk"].MatchString(raw.Origin.PacketID) || !idRE["rv"].MatchString(raw.Origin.RevisionID) {
			return nil, bad(CodeBadValue, "origin", "invalid origin ids")
		}
		p.Origin = &Origin{PacketID: raw.Origin.PacketID, RevisionID: raw.Origin.RevisionID, Relation: "copy"}
	}
	return p, nil
}

func validatePayload(payload json.RawMessage, opt ParseOptions) (json.RawMessage, error) {
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if len(payload) > MaxPayloadBytes {
		return nil, bad(CodeTooLarge, "payload", "payload is too large")
	}
	var generic any
	if err := json.Unmarshal(payload, &generic); err != nil {
		return nil, bad(CodeBadPayload, "payload", "payload is not valid JSON")
	}
	if _, ok := generic.(map[string]any); !ok {
		return nil, bad(CodeBadPayload, "payload", "payload must be an object")
	}
	if depth(generic) > MaxPayloadDepth {
		return nil, bad(CodeBadPayload, "payload", "payload is nested too deeply (max %d)", MaxPayloadDepth)
	}
	if opt.ValidatePayload != nil {
		out, err := opt.ValidatePayload(payload)
		if err != nil {
			return nil, bad(CodeBadPayload, "payload", "%v", err)
		}
		return out, nil
	}
	return append(json.RawMessage(nil), payload...), nil
}

func depth(v any) int {
	switch t := v.(type) {
	case map[string]any:
		m := 0
		for _, e := range t {
			if d := depth(e); d > m {
				m = d
			}
		}
		return m + 1
	case []any:
		m := 0
		for _, e := range t {
			if d := depth(e); d > m {
				m = d
			}
		}
		return m + 1
	}
	return 0
}

func validateAttestation(a Attestation) *Error {
	switch {
	case !validKinds[a.Kind]:
		return bad(CodeBadValue, "kind", "unknown attestation kind")
	case !validMethods[a.Method]:
		return bad(CodeBadValue, "method", "unknown confirmation method")
	case !subjectRE.MatchString(a.Subject):
		return bad(CodeBadValue, "subject", "subject must be a 64-character hex hash")
	case !keyIDRE.MatchString(a.KeyID):
		return bad(CodeBadValue, "keyId", "invalid key id")
	case !sigRE.MatchString(a.Signature):
		return bad(CodeBadValue, "signature", "invalid signature encoding")
	}
	if _, err := time.Parse(time.RFC3339Nano, a.IssuedAt); err != nil {
		return bad(CodeBadValue, "issuedAt", "must be an ISO 8601 date and time")
	}
	if a.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, a.ExpiresAt); err != nil {
			return bad(CodeBadValue, "expiresAt", "must be an ISO 8601 date and time")
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// knownKeys lists every field name at each level of the envelope.
var knownKeys = map[string][]string{
	"": {
		"format", "schemaVersion", "appId", "packetId", "name", "revisionId", "parentRevisionId", "lineage",
		"createdAt", "savedAt", "app", "origin", "payload", "attestations", "checksum",
	},
	"app":         {"name", "version"},
	"origin":      {"packetId", "revisionId", "relation"},
	"attestation": {"kind", "method", "subject", "issuedAt", "expiresAt", "keyId", "signature"},
	"checksum":    {"alg", "value"},
}

// checkKeyCase rejects field names that differ from a known name only by
// case. encoding/json matches names case-insensitively, but other readers
// (including the JavaScript one) do not, and two readers disagreeing about
// what a file says is how smuggling attacks work. Payload contents are the
// application's own and are not checked here.
func checkKeyCase(obj map[string]any) *Error {
	check := func(level, path string, m map[string]any) *Error {
		for k := range m {
			for _, known := range knownKeys[level] {
				if k != known && strings.EqualFold(k, known) {
					return bad(CodeBadValue, path+k, "field names are case-sensitive: use %q", known)
				}
			}
		}
		return nil
	}
	if err := check("", "", obj); err != nil {
		return err
	}
	for _, level := range []string{"app", "origin", "checksum"} {
		if m, ok := obj[level].(map[string]any); ok {
			if err := check(level, level+".", m); err != nil {
				return err
			}
		}
	}
	if list, ok := obj["attestations"].([]any); ok {
		for i, e := range list {
			if m, ok := e.(map[string]any); ok {
				if err := check("attestation", "attestations["+strconv.Itoa(i)+"].", m); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// IsPacketID reports whether s has the shape of a packet id.
func IsPacketID(s string) bool { return idRE["pk"].MatchString(s) }

// IsAppID reports whether s is a valid app id.
func IsAppID(s string) bool { return appIDRE.MatchString(s) }
