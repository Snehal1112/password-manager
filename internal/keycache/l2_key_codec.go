// internal/keycache/l2_key_codec.go
package keycache

import (
	"strconv"
	"strings"

	"github.com/google/uuid"

	"rocketvault/internal/cachekit"
)

// keyCacheKeyCodec turns a keyCacheKey into "<uuid>:<version>" and back.
// FromWire reports ok=false (never an error) for anything malformed, per
// cachekit.KeyCodec's contract -- Range/InvalidateAll must skip such
// entries silently, not fail.
func keyCacheKeyCodec() cachekit.KeyCodec[keyCacheKey] {
	return cachekit.KeyCodec[keyCacheKey]{
		ToWire: func(k keyCacheKey) string {
			return k.ID.String() + ":" + strconv.Itoa(k.Version)
		},
		FromWire: func(w string) (keyCacheKey, bool) {
			idx := strings.LastIndex(w, ":")
			if idx < 0 {
				return keyCacheKey{}, false
			}
			id, err := uuid.Parse(w[:idx])
			if err != nil {
				return keyCacheKey{}, false
			}
			version, err := strconv.Atoi(w[idx+1:])
			if err != nil {
				return keyCacheKey{}, false
			}
			return keyCacheKey{ID: id, Version: version}, true
		},
	}
}
