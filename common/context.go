package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
	ServiceContainerKey = &contextKey{"service_container"}
	OutputFormatterKey  = &contextKey{"output_formatter"}
	// RemoteTargetKey holds the *cliclient.Target a remote-capable command
	// is running against, when a remote target resolved. Absent in local
	// mode. Typed as `any` here (common must not import internal/cliclient)
	// -- callers assert to *cliclient.Target.
	RemoteTargetKey = &contextKey{"remote_target"}
	// RemoteHTTPClientKey holds the *http.Client configured with this
	// invocation's TLS trust options, for remote-capable commands to reuse
	// rather than building their own. Absent in local mode.
	RemoteHTTPClientKey = &contextKey{"remote_http_client"}
	// RemoteClientKey carries the *vaultapi.Client a remote-mode command uses
	// for every API call. It replaces reading TokenKey and RemoteHTTPClientKey
	// separately: the client owns the token source and the transport. Typed as
	// `any` here (common must not import internal/vaultapi) -- callers assert
	// to *vaultapi.Client.
	RemoteClientKey = &contextKey{"remote_client"}
)

// contextsFilePath sits alongside the sessions/ directory, at
// ~/.rocketvault/contexts.json.
func contextsFilePath() string {
	return filepath.Join(filepath.Dir(SessionBaseDir), "contexts.json")
}

// Context is a named pointer to a remote RocketVault server. It holds no
// credentials — those live in the session cache, keyed by
// SanitizeServerKey(Server).
type Context struct {
	Server   string `json:"server"`
	Username string `json:"username,omitempty"`
	Vault    string `json:"vault,omitempty"`
}

type contextStore struct {
	Current  string             `json:"current,omitempty"`
	Contexts map[string]Context `json:"contexts"`
}

func loadContextStore() (*contextStore, error) {
	data, err := os.ReadFile(contextsFilePath())
	if os.IsNotExist(err) {
		return &contextStore{Contexts: map[string]Context{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read contexts file: %w", err)
	}
	var store contextStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse contexts file: %w", err)
	}
	if store.Contexts == nil {
		store.Contexts = map[string]Context{}
	}
	return &store, nil
}

func saveContextStore(store *contextStore) error {
	if err := os.MkdirAll(filepath.Dir(contextsFilePath()), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal contexts: %w", err)
	}
	if err := os.WriteFile(contextsFilePath(), data, 0600); err != nil {
		return fmt.Errorf("failed to write contexts file: %w", err)
	}
	return nil
}

// AddContext creates or overwrites a named context.
func AddContext(name string, ctx Context) error {
	store, err := loadContextStore()
	if err != nil {
		return err
	}
	store.Contexts[name] = ctx
	return saveContextStore(store)
}

// ListContexts returns all saved contexts and the name of the current one
// ("" if none is set).
func ListContexts() (map[string]Context, string, error) {
	store, err := loadContextStore()
	if err != nil {
		return nil, "", err
	}
	return store.Contexts, store.Current, nil
}

// UseContext marks name as current. Returns an error if name doesn't exist.
func UseContext(name string) error {
	store, err := loadContextStore()
	if err != nil {
		return err
	}
	if _, ok := store.Contexts[name]; !ok {
		return fmt.Errorf("context %q not found", name)
	}
	store.Current = name
	return saveContextStore(store)
}

// CurrentContext returns the current context and its name. Returns
// (nil, "", nil) if no context is set as current, or if the current
// pointer references a context that no longer exists.
func CurrentContext() (*Context, string, error) {
	store, err := loadContextStore()
	if err != nil {
		return nil, "", err
	}
	if store.Current == "" {
		return nil, "", nil
	}
	ctx, ok := store.Contexts[store.Current]
	if !ok {
		return nil, "", nil
	}
	return &ctx, store.Current, nil
}

// UnsetCurrentContext clears the current-context pointer, putting the CLI
// back in local mode, without deleting any saved context -- unlike
// RemoveContext, which does both. A no-op (not an error) if no context is
// currently set.
func UnsetCurrentContext() error {
	store, err := loadContextStore()
	if err != nil {
		return err
	}
	if store.Current == "" {
		return nil
	}
	store.Current = ""
	return saveContextStore(store)
}

// RemoveContext deletes a named context. If it was the current context, the
// current pointer is cleared too. Removing a non-existent context is not an
// error.
func RemoveContext(name string) error {
	store, err := loadContextStore()
	if err != nil {
		return err
	}
	delete(store.Contexts, name)
	if store.Current == name {
		store.Current = ""
	}
	return saveContextStore(store)
}
