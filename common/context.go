package common

// contextKey is an unexported type for context keys to prevent collisions
// across packages that might share the same underlying int type.
type contextKey struct{ name string }

// String makes contextKey implement Stringer for debugging.
func (k *contextKey) String() string { return "rocketvault/" + k.name }

// Context keys using pointer identity — guaranteed unique per variable.
var (
	DBKey               = &contextKey{"db"}
	DBClassKey          = &contextKey{"db_class"}
	LogKey              = &contextKey{"log"}
	UserIDKey           = &contextKey{"user_id"}
	UsernameKey         = &contextKey{"username"}
	RoleKey             = &contextKey{"role"}
	VaultIDKey          = &contextKey{"vault_id"}
	TokenKey            = &contextKey{"token"}
	ClaimsKey           = &contextKey{"claims"}
	RequestIDKey        = &contextKey{"request_id"}
	ContentTypeKey      = &contextKey{"content_type"}
	APIVersionKey       = &contextKey{"api_version"}
	ServiceContainerKey = &contextKey{"service_container"}
	OutputFormatterKey  = &contextKey{"output_formatter"}
)
