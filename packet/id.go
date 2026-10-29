package packet

import (
	"crypto/rand"
	"fmt"
	"regexp"
)

const b32 = "0123456789abcdefghjkmnpqrstvwxyz"

// NewID returns prefix + "_" + 13 random base-32 characters (65 bits) from
// crypto/rand. It is an identity label, not a password and not proof of
// anything.
func NewID(prefix string) string {
	var raw [13]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand failing means the platform has no secure randomness.
		panic(fmt.Sprintf("packet: no secure random source: %v", err))
	}
	out := make([]byte, 13)
	for i, b := range raw {
		out[i] = b32[b&31] // 256 is a multiple of 32, so this is unbiased
	}
	return prefix + "_" + string(out)
}

var (
	idRE    = map[string]*regexp.Regexp{"pk": regexp.MustCompile(`^pk_[0-9a-z]{8,32}$`), "rv": regexp.MustCompile(`^rv_[0-9a-z]{8,32}$`)}
	appIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)
)
