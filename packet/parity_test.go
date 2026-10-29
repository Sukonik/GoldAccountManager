package packet

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// parityFile holds cases shared with the JavaScript reader. The Go reader is
// the reference: if a case fails here, fix the case. If it fails in
// site/tests/packet.test.mjs, fix the JavaScript.
type parityFile struct {
	Canonical []struct {
		Input string `json:"input"`
		Canon string `json:"canon"`
		Sum   string `json:"sum"`
	} `json:"canonical"`
	Parse []parityCase `json:"parse"`
}

type parityCase struct {
	Name      string           `json:"name"`
	Ops       []map[string]any `json:"ops"`
	Raw       *string          `json:"raw"`
	BOM       bool             `json:"bom"`
	ExpectApp string           `json:"expectApp"`
	Expect    struct {
		OK       bool     `json:"ok"`
		Code     string   `json:"code"`
		Warnings []string `json:"warnings"`
	} `json:"expect"`
}

func loadParity(t *testing.T) (parityFile, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f parityFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	baseText, err := os.ReadFile("../site/examples/attested.gold")
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(baseText, &base); err != nil {
		t.Fatal(err)
	}
	return f, base
}

func TestParityCanonical(t *testing.T) {
	t.Parallel()
	f, _ := loadParity(t)
	if len(f.Canonical) == 0 {
		t.Fatal("no canonical vectors")
	}
	for _, v := range f.Canonical {
		var in any
		if err := json.Unmarshal([]byte(v.Input), &in); err != nil {
			t.Fatal(err)
		}
		got, err := CanonicalJSON(in)
		if err != nil || got != v.Canon {
			t.Errorf("canonical(%s)\n got: %s\nwant: %s (%v)", v.Input, got, v.Canon, err)
		}
		if sum, _ := ChecksumOf(in); sum != v.Sum {
			t.Errorf("checksum(%s) = %s, want %s", v.Input, sum, v.Sum)
		}
	}
}

func TestParityParse(t *testing.T) {
	t.Parallel()
	f, base := loadParity(t)
	if len(f.Parse) < 50 {
		t.Fatalf("only %d parse cases", len(f.Parse))
	}
	for _, c := range f.Parse {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			var text []byte
			if c.Raw != nil {
				text = []byte(*c.Raw)
			} else {
				doc := deepCopy(base).(map[string]any)
				for _, op := range c.Ops {
					if err := applyOp(doc, op); err != nil {
						t.Fatalf("bad case: %v", err)
					}
				}
				var err error
				text, err = json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
			}
			if c.BOM {
				text = append([]byte{0xEF, 0xBB, 0xBF}, text...)
			}
			p, warns, err := Parse(text, ParseOptions{ExpectAppID: c.ExpectApp})
			if c.Expect.OK {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				if p == nil {
					t.Fatal("nil packet")
				}
				var got []string
				for _, w := range warns {
					got = append(got, w.Code)
				}
				if strings.Join(got, ",") != strings.Join(c.Expect.Warnings, ",") {
					t.Fatalf("warnings = %v, want %v", got, c.Expect.Warnings)
				}
				return
			}
			if code(err) != c.Expect.Code {
				t.Fatalf("want %s, got %v", c.Expect.Code, err)
			}
		})
	}
}

func deepCopy(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// resolve walks a dotted path ("attestations.0.kind") to the container that
// holds the last element, and returns it with that last key.
func resolve(root any, path string) (container any, key string, err error) {
	parts := strings.Split(path, ".")
	cur := root
	for _, p := range parts[:len(parts)-1] {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[p]
		case []any:
			i, e := strconv.Atoi(p)
			if e != nil || i >= len(c) {
				return nil, "", fmt.Errorf("bad index %q in %q", p, path)
			}
			cur = c[i]
		default:
			return nil, "", fmt.Errorf("cannot walk %q in %q", p, path)
		}
	}
	return cur, parts[len(parts)-1], nil
}

func expand(v any) any {
	if m, ok := v.(map[string]any); ok {
		if n, ok := m["$deep"].(float64); ok {
			var out any = float64(1)
			for range int(n) {
				out = map[string]any{"a": out}
			}
			return out
		}
	}
	return v
}

func applyOp(doc map[string]any, op map[string]any) error {
	switch {
	case op["set"] != nil:
		c, k, err := resolve(doc, op["set"].(string))
		if err != nil {
			return err
		}
		return assign(c, k, expand(op["value"]))
	case op["delete"] != nil:
		c, k, err := resolve(doc, op["delete"].(string))
		if err != nil {
			return err
		}
		if m, ok := c.(map[string]any); ok {
			delete(m, k)
			return nil
		}
		return fmt.Errorf("delete needs an object parent")
	case op["rename"] != nil:
		c, k, err := resolve(doc, op["rename"].(string))
		if err != nil {
			return err
		}
		m, ok := c.(map[string]any)
		if !ok {
			return fmt.Errorf("rename needs an object parent")
		}
		m[op["to"].(string)] = m[k]
		delete(m, k)
		return nil
	case op["repeat"] != nil:
		c, k, err := resolve(doc, op["repeat"].(string))
		if err != nil {
			return err
		}
		var item any
		switch cc := c.(type) {
		case []any:
			i, _ := strconv.Atoi(k)
			item = cc[i]
		default:
			return fmt.Errorf("repeat needs an array element")
		}
		list := make([]any, int(op["times"].(float64)))
		for i := range list {
			list[i] = deepCopy(item)
		}
		doc[op["into"].(string)] = list
		return nil
	}
	return fmt.Errorf("unknown op %v", op)
}

func assign(container any, key string, value any) error {
	switch c := container.(type) {
	case map[string]any:
		c[key] = value
		return nil
	case []any:
		i, err := strconv.Atoi(key)
		if err != nil || i >= len(c) {
			return fmt.Errorf("bad index %q", key)
		}
		c[i] = value
		return nil
	}
	return fmt.Errorf("cannot assign into %T", container)
}
