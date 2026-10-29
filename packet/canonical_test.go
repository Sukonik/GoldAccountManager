package packet

import (
	"encoding/json"
	"testing"
)

// Vectors produced by payout-lab's js/core/packet.js (canonicalJson and
// checksumOf) under Node 22. If these fail, checksums stop matching the
// JavaScript implementation.
var jsVectors = []struct {
	name  string
	input string
	canon string
	sum   string
}{
	{
		"numbers",
		`{"b":1,"a":[1,2.5,-0,1e21,1e-7,0.000001,123456789012345680000,1.0,0.1],"s":"x"}`,
		`{"a":[1,2.5,0,1e+21,1e-7,0.000001,123456789012345680000,1,0.1],"b":1,"s":"x"}`,
		"3362096e6edc99bad0b9586283180991516c7d7631dc0ffefce2b70d1ca54fc7",
	},
	{
		"strings",
		`{"z":"quote\" back\\ nl\n tab\t ctl\u0001 <tag> &   é 😀 del\u007f","n":null,"t":true,"f":false,"o":{}}`,
		"{\"f\":false,\"n\":null,\"o\":{},\"t\":true,\"z\":\"quote\\\" back\\\\ nl\\n tab\\t ctl\\u0001 <tag> &   é 😀 del\u007f\"}",
		"876a1454aca9825b5648413eed95cea56f6becc7abe557f9356935f2de277243",
	},
	{
		"nested",
		`{"nested":{"b":[{"y":2,"x":1}],"a":{}},"e":[],"big":9007199254740993,"neg":-1.5e-9}`,
		`{"big":9007199254740992,"e":[],"neg":-1.5e-9,"nested":{"a":{},"b":[{"x":1,"y":2}]}}`,
		"48016b4e0714f4443559f6e93ea273562c2e0b51509504c736be7e3958e47b05",
	},
}

func TestCanonicalMatchesJavaScript(t *testing.T) {
	t.Parallel()
	for _, v := range jsVectors {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			var in any
			if err := json.Unmarshal([]byte(v.input), &in); err != nil {
				t.Fatal(err)
			}
			got, err := CanonicalJSON(in)
			if err != nil {
				t.Fatal(err)
			}
			if got != v.canon {
				t.Errorf("canonical mismatch\n got: %s\nwant: %s", got, v.canon)
			}
			sum, err := ChecksumOf(in)
			if err != nil {
				t.Fatal(err)
			}
			if sum != v.sum {
				t.Errorf("checksum = %s, want %s", sum, v.sum)
			}
		})
	}
}

func TestFormatNumber(t *testing.T) {
	t.Parallel()
	cases := map[float64]string{
		0: "0", 1: "1", -1: "-1", 1.5: "1.5", 100: "100", 0.1: "0.1",
		1e21: "1e+21", 1e20: "100000000000000000000", 1e-6: "0.000001", 1e-7: "1e-7",
		123456789: "123456789", 1.2345e-8: "1.2345e-8", 5e-324: "5e-324",
	}
	for in, want := range cases {
		if got := formatNumber(in); got != want {
			t.Errorf("formatNumber(%v) = %q, want %q", in, got, want)
		}
	}
}
