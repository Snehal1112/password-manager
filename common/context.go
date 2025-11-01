package common

// ContextKey is a custom type for context keys to avoid key collisions.
type ContextKey int

const (
	// DBKey is the key used to store the database connection in the context.
	DBKey ContextKey = iota
	// DBClassKey is the key used to store the database class in the context.
	DBClassKey
	// LogKey is the key used to store the logger in the context.
	LogKey
	// UserIDKey is the key used to store the user ID in the context.
	UserIDKey
	// UsernameKey is the key used to store the username in the context.
	UsernameKey
	// RoleKey is the key used to store the user role in the context.
	RoleKey
	// TokenKey is the key used to store the authentication token in the context.
	TokenKey
	// ClaimsKey is the key used to store the authentication claims in the context.
	ClaimsKey
	// RequestIDKey is the key used to store the request ID in the context.
	RequestIDKey
	// ContentTypeKey is the key used to store the content type in the context.
	ContentTypeKey
	// APIVersionKey is the key used to store the API version in the context.
	APIVersionKey
	// ServiceContainerKey is the key used to store the service container in the context.
	ServiceContainerKey
)

// String returns the string representation of the ContextKey.
// This is useful for debugging and logging purposes.
// It returns the string value of the ContextKey.
//
// Example usage:
//
//	var ctx context.Context
//	ctx = context.WithValue(context.Background(), common.UserIDKey, "userID")
//	fmt.Println(ctx.Value(common.UserIDKey)) // Output: userID
// func (k ContextKey) String() string {
// 	return string(k)
// }
