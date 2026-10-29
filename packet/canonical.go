package packet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// CanonicalJSON returns the canonical form of v: object keys sorted, no
// whitespace, strings and numbers written exactly as ECMAScript's
// JSON.stringify writes them. It matches payout-lab's canonicalJson, which is
// what makes checksums comparable across the two implementations.
//
// v may be any value encoding/json can marshal. It is round-tripped through
// JSON first, so numbers follow float64 semantics, as in JavaScript.
func CanonicalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := writeCanonical(&sb, generic); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ChecksumOf returns the lowercase hex SHA-256 of the canonical JSON of v.
func ChecksumOf(v any) (string, error) {
	c, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:]), nil
}

func writeCanonical(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return fmt.Errorf("cannot canonicalize non-finite number")
		}
		sb.WriteString(formatNumber(t))
	case string:
		writeString(sb, t)
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, k)
			sb.WriteByte(':')
			if err := writeCanonical(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", v)
	}
	return nil
}

// writeString writes s the way JSON.stringify does: only ", \ and control
// characters are escaped. Notably < > & and U+2028/2029 are left alone, unlike
// encoding/json's default output.
func writeString(sb *strings.Builder, s string) {
	const hexd = "0123456789abcdef"
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteByte(hexd[r>>4])
				sb.WriteByte(hexd[r&0xf])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// formatNumber implements ECMAScript Number::toString(10) for finite values.
func formatNumber(f float64) string {
	if f == 0 {
		return "0" // also covers -0
	}
	neg := f < 0
	if neg {
		f = -f
	}
	// Shortest round-trip digits, as "d.ddde±XX".
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp + 1 // position of the decimal point relative to digits

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		x := n - 1
		sign := "+"
		if x < 0 {
			sign = "-"
			x = -x
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(x)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(x)
		}
	}
	if neg {
		return "-" + out
	}
	return out
}
