package packet

import (
	"encoding/json"
	"slices"
	"time"
)

// Relation describes how an incoming packet relates to the copy already held.
type Relation string

// Relations returned by Compare. Same names as payout-lab.
const (
	DifferentPacket Relation = "different-packet"
	Identical       Relation = "identical"
	IncomingNewer   Relation = "incoming-newer"
	IncomingOlder   Relation = "incoming-older"
	Diverged        Relation = "diverged"
)

// Compare classifies incoming against local using revision lineage. There is
// no silent last-write-wins: a Diverged pair means both sides changed, and the
// caller should offer a separate copy.
func Compare(local, incoming *Packet) Relation {
	switch {
	case local.PacketID != incoming.PacketID:
		return DifferentPacket
	case local.RevisionID == incoming.RevisionID:
		return Identical
	case slices.Contains(incoming.Lineage, local.RevisionID):
		return IncomingNewer
	case slices.Contains(local.Lineage, incoming.RevisionID):
		return IncomingOlder
	}
	return Diverged
}

// NextRevision returns the next revision of p: a new revision id whose parent
// is p's current one. p is not modified.
func NextRevision(p *Packet, now time.Time) *Packet {
	n := clone(p)
	parent := p.RevisionID
	n.RevisionID = NewID("rv")
	n.ParentRevisionID = &parent
	n.Lineage = append(n.Lineage, n.RevisionID)
	if len(n.Lineage) > MaxLineage {
		n.Lineage = n.Lineage[len(n.Lineage)-MaxLineage:]
	}
	n.SavedAt = stamp(now)
	return n
}

// AsSeparateCopy returns p as a brand-new packet that remembers where it came
// from. Attestations are dropped: they were issued for the original packet id
// and would not verify on the copy.
func AsSeparateCopy(p *Packet, suffix string, now time.Time) *Packet {
	n := clone(p)
	rev := NewID("rv")
	ts := stamp(now)
	n.Origin = &Origin{PacketID: p.PacketID, RevisionID: p.RevisionID, Relation: "copy"}
	n.PacketID = NewID("pk")
	n.Name = cleanName(p.Name+suffix, p.Name)
	n.RevisionID, n.ParentRevisionID, n.Lineage = rev, nil, []string{rev}
	n.CreatedAt, n.SavedAt = ts, ts
	n.Attestations = []Attestation{}
	return n
}

func clone(p *Packet) *Packet {
	n := *p
	n.Lineage = append([]string(nil), p.Lineage...)
	n.Payload = append(json.RawMessage(nil), p.Payload...)
	n.Attestations = append([]Attestation{}, p.Attestations...)
	if p.ParentRevisionID != nil {
		v := *p.ParentRevisionID
		n.ParentRevisionID = &v
	}
	if p.Origin != nil {
		o := *p.Origin
		n.Origin = &o
	}
	return &n
}
