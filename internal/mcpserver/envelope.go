package mcpserver

import (
	"encoding/json"
	"strings"
)

// The markers delimiting vault-resident content in tool output.
//
// They are deliberately unusual: the point is that a marker never appears by
// accident in ordinary text, so its presence is a reliable boundary signal.
const (
	untrustedOpen  = "<<UNTRUSTED-VAULT-DATA>>"
	untrustedClose = "<</UNTRUSTED-VAULT-DATA>>"
	// neutralised replaces a marker the content itself contained.
	neutralisedMarker = "[delimiter removed]"
)

// Untrusted is vault-resident free text: a description, tag, certificate
// subject, or audit detail.
//
// Such text is written by users, who on a shared vault need not be the person
// running the agent. Marshalling delimits it so a model can tell data the
// tool retrieved from instructions the operator gave. That does not make the
// text safe -- nothing does -- but it marks the boundary, which is what lets
// the content be treated as inert.
type Untrusted string

// Wrap marks text as untrusted vault content.
//
// Any delimiter the content itself contains is neutralised first. Without
// that step the envelope would be decoration: an attacker who writes the
// closing marker into a tag would make everything after it appear to sit
// outside the untrusted region, which is precisely the boundary being
// established.
func Wrap(text string) Untrusted {
	if text == "" {
		// Wrapping nothing must not manufacture a delimiter pair for a model
		// to reason about.
		return ""
	}
	cleaned := strings.ReplaceAll(text, untrustedOpen, neutralisedMarker)
	cleaned = strings.ReplaceAll(cleaned, untrustedClose, neutralisedMarker)
	return Untrusted(cleaned)
}

// WrapAll marks every element of texts as untrusted. A nil slice stays nil.
func WrapAll(texts []string) []Untrusted {
	if texts == nil {
		return nil
	}
	wrapped := make([]Untrusted, 0, len(texts))
	for _, text := range texts {
		wrapped = append(wrapped, Wrap(text))
	}
	return wrapped
}

// Text returns the content without its delimiters.
func (u Untrusted) Text() string { return string(u) }

// MarshalJSON renders the content between its delimiters.
//
// It marshals to a plain JSON string rather than an object, which keeps the
// inferred output schema simple and keeps the marker adjacent to the text it
// applies to.
func (u Untrusted) MarshalJSON() ([]byte, error) {
	if u == "" {
		return json.Marshal("")
	}
	return json.Marshal(untrustedOpen + string(u) + untrustedClose)
}
