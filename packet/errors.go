package packet

import "fmt"

// Error codes returned by Parse. They are stable and safe to show to users or
// to switch on.
const (
	CodeNotPacket     = "not_packet"
	CodeBadJSON       = "bad_json"
	CodeBadType       = "bad_type"
	CodeBadVersion    = "bad_version"
	CodeFutureVersion = "future_version"
	CodeTooLarge      = "too_large"
	CodeTooMany       = "too_many"
	CodeBadValue      = "bad_value"
	CodeAppMismatch   = "app_mismatch"
	CodeBadPayload    = "bad_payload"
)

// Error describes why a file was rejected. Path names the offending field when
// one is known.
type Error struct {
	Code    string
	Message string
	Path    string
}

func (e *Error) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Path)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func bad(code, path, format string, args ...any) *Error {
	return &Error{Code: code, Path: path, Message: fmt.Sprintf(format, args...)}
}

// Warning is a non-fatal finding. The packet opened, but the caller should
// show the message before trusting the content.
type Warning struct {
	Code    string
	Message string
}

// Warning codes.
const (
	WarnChecksumMismatch = "checksum_mismatch"
	WarnNoChecksum       = "no_checksum"
)
