package packet_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
)

// Create a packet for one app, save it, and open it again the way an app
// would: pinned to its own app id, with the payload checked field by field.
func Example() {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

	p, _ := packet.New("notes-demo", "Sam's notes", packet.AppInfo{Name: "Notes Demo", Version: "0.1.0"}, now)
	p.Payload = json.RawMessage(`{"theme":"dark"}`)
	file, _ := p.Marshal() // write this to disk: it is the user's account

	opened, warnings, err := packet.Parse(file, packet.ParseOptions{
		ExpectAppID: "notes-demo",
		ValidatePayload: func(raw json.RawMessage) (json.RawMessage, error) {
			var v struct {
				Theme string `json:"theme"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, err
			}
			if v.Theme != "light" && v.Theme != "dark" {
				return nil, fmt.Errorf("theme must be light or dark")
			}
			return json.Marshal(v) // rebuilt from whitelisted fields only
		},
	})
	fmt.Println(opened.Name, len(warnings), err)
	// Output: Sam's notes 0 <nil>
}

// Two copies of the same packet are compared by revision history, never by
// "last write wins".
func ExampleCompare() {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	original, _ := packet.New("notes-demo", "Notes", packet.AppInfo{}, now)

	onPhone := packet.NextRevision(original, now.Add(time.Hour))
	onLaptop := packet.NextRevision(original, now.Add(2*time.Hour))

	fmt.Println(packet.Compare(original, onPhone))
	fmt.Println(packet.Compare(onPhone, original))
	fmt.Println(packet.Compare(onPhone, onLaptop)) // both changed: offer a separate copy
	// Output:
	// incoming-newer
	// incoming-older
	// diverged
}
