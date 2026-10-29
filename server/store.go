package server

import "sync"

// AdmitResult says whether a confirmed address was admitted to an app.
type AdmitResult struct {
	Admitted bool // the address is (now) a member
	New      bool // it was not a member before
}

// Store remembers which confirmed addresses belong to each app, for quotas. It
// holds only keyed hashes (see verify.Subject), never addresses.
type Store interface {
	// Admit adds subject to the app unless the app already has limit members and
	// subject is not one of them. A limit of zero means no limit. Existing members
	// are always admitted, so a full app never locks out its own users.
	Admit(appID, subject string, limit int) (AdmitResult, error)
	// Waitlist records subject as waiting for space in the app.
	Waitlist(appID, subject string) error
	// Members returns how many addresses the app has.
	Members(appID string) (int, error)
}

// MemoryStore is a Store that keeps everything in memory. Quotas and waitlists
// are lost when the process restarts, so it suits demos and tests. A durable
// store arrives with a later phase.
type MemoryStore struct {
	mu       sync.Mutex
	members  map[string]map[string]struct{}
	waitlist map[string]map[string]struct{}
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{members: map[string]map[string]struct{}{}, waitlist: map[string]map[string]struct{}{}}
}

// Admit implements Store.
func (s *MemoryStore) Admit(appID, subject string, limit int) (AdmitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.members[appID]
	if set == nil {
		set = map[string]struct{}{}
		s.members[appID] = set
	}
	if _, ok := set[subject]; ok {
		return AdmitResult{Admitted: true}, nil
	}
	if limit > 0 && len(set) >= limit {
		return AdmitResult{}, nil
	}
	set[subject] = struct{}{}
	return AdmitResult{Admitted: true, New: true}, nil
}

// Waitlist implements Store.
func (s *MemoryStore) Waitlist(appID, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waitlist[appID] == nil {
		s.waitlist[appID] = map[string]struct{}{}
	}
	s.waitlist[appID][subject] = struct{}{}
	return nil
}

// Members implements Store.
func (s *MemoryStore) Members(appID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.members[appID]), nil
}

// Waiting returns how many addresses are on the app's waitlist. For tests and
// the demo.
func (s *MemoryStore) Waiting(appID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waitlist[appID])
}
