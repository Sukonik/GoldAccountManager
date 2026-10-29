package verify_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
	"github.com/sukonik/goldaccountmanager/verify"
)

// Confirm an email once, sign an attestation, and check it later without
// sending anything again.
func Example() {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

	// Server side: a signing key and a per-app secret. Keep both private.
	seed := sha256.Sum256([]byte("example signing key"))
	signer, _ := verify.NewSigner("k1", ed25519.NewKeyFromSeed(seed[:]))
	appSecret := sha256.Sum256([]byte("example app secret"))

	// The user's packet, for one app.
	p, _ := packet.New("notes-demo", "Sam's notes", packet.AppInfo{Name: "Notes Demo", Version: "0.1.0"}, now)

	// A confirmation channel succeeded for sam@example.com. Store the hash,
	// never the address.
	email, _ := verify.Normalize(packet.KindEmail, "Sam@Example.com")
	subject, _ := verify.Subject(appSecret[:], p.AppID, packet.KindEmail, email)
	att, _ := signer.Attest(
		p.AppID, p.PacketID,
		packet.KindEmail, packet.MethodEmailReply,
		subject, now, now.AddDate(1, 0, 0),
	)
	p.Attestations = append(p.Attestations, att)

	// Later, an app checks the packet against the published public key.
	checker := verify.NewChecker(map[string]ed25519.PublicKey{"k1": signer.PublicKey()})
	results := checker.Check(p, now.AddDate(0, 6, 0))
	fmt.Println(results[0].Status, verify.Has(results, packet.KindEmail))
	// Output: valid true
}

func ExampleChecker_Check_otherPacket() {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	seed := sha256.Sum256([]byte("example signing key"))
	signer, _ := verify.NewSigner("k1", ed25519.NewKeyFromSeed(seed[:]))
	checker := verify.NewChecker(map[string]ed25519.PublicKey{"k1": signer.PublicKey()})

	mine, _ := packet.New("notes-demo", "Mine", packet.AppInfo{}, now)
	theirs, _ := packet.New("notes-demo", "Theirs", packet.AppInfo{}, now)
	att, _ := signer.Attest(
		mine.AppID, mine.PacketID,
		packet.KindEmail, packet.MethodGoogle,
		hex.EncodeToString(make([]byte, 32)), now, time.Time{},
	)

	// Copying an attestation onto someone else's packet does not work.
	theirs.Attestations = []packet.Attestation{att}
	fmt.Println(checker.Check(theirs, now)[0].Status)
	// Output: bad-signature
}

// The packets shown in the docs are real files. This keeps them valid, and
// keeps the published demo key and the examples in step.
func TestSiteExamples(t *testing.T) {
	t.Parallel()
	read := func(name string) *packet.Packet {
		t.Helper()
		data, err := os.ReadFile("../site/examples/" + name) //nolint:gosec // fixed test file names
		if err != nil {
			t.Fatal(err)
		}
		p, warns, err := packet.Parse(data, packet.ParseOptions{ExpectAppID: "notes-demo"})
		if err != nil || len(warns) != 0 {
			t.Fatalf("%s: err=%v warnings=%v", name, err, warns)
		}
		return p
	}
	basic, attested := read("basic.gold"), read("attested.gold")

	if got := packet.Compare(basic, attested); got != packet.IncomingNewer {
		t.Errorf("attested.gold should be a newer revision of basic.gold, got %s", got)
	}

	pub, _ := hex.DecodeString("d1453fa8f6676733f93eec7b0e7b6f1b58e4ac770270c261455a2296bd7b9cec")
	checker := verify.NewChecker(map[string]ed25519.PublicKey{"docs-demo-1": pub})
	results := checker.Check(attested, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if len(results) != 1 || results[0].Status != verify.Valid {
		t.Fatalf("docs attestation does not verify: %+v", results)
	}
	// Past its expiry date the same attestation is reported as expired.
	late := checker.Check(attested, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	if late[0].Status != verify.Expired {
		t.Errorf("want expired, got %s", late[0].Status)
	}
}
