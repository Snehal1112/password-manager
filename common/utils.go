package common

import (
	"bytes"
	"encoding/base32"
	"encoding/json"

	"github.com/google/uuid"
)

var encoding = base32.NewEncoding("ybndrfg8ejkmcpqxot1uwisza345h769")

// AppError represents a structured error with detailed information.
// It includes fields for user-friendly messages, internal debugging details,
// request identification, HTTP status codes, and OAuth-specific errors.
type AppError struct {
	ID            string `json:"id"`
	Message       string `json:"message"`               // Message to be display to the end user without debugging information
	DetailedError string `json:"detailed_error"`        // Internal error string to help the developer
	RequestID     string `json:"request_id,omitempty"`  // The RequestId that's also set in the header
	StatusCode    int    `json:"status_code,omitempty"` // The http status code
	Where         string `json:"-"`                     // The function where it happened in the form of Struct.Func
	IsOAuth       bool   `json:"is_oauth,omitempty"`    // Whether the error is OAuth specific
	params        map[string]interface{}
}

// NewID generates a new unique identifier string using base32 encoding.
// It creates a random UUID, encodes it using base32, and removes the '==' padding
// to return a 26-character string.
func NewID() string {
	var b bytes.Buffer
	encoder := base32.NewEncoder(encoding, &b)
	encoder.Write(uuid.New().NodeID())
	encoder.Close()
	b.Truncate(26) // removes the '==' padding
	return b.String()
}

// TranslateFunc is a function type that defines the signature for translation functions.
// It takes a translationID, which is a string representing the key for the translation,
// and a variadic number of arguments that can be used within the translation string.
// It returns the translated string.
type TranslateFunc func(translationID string, args ...interface{}) string

// NewAppError creates a new instance of AppError with the provided details.
// Parameters:
//   - where: A string indicating where the error occurred.
//   - ID: A string representing the error ID.
//   - params: A map containing additional parameters related to the error.
//   - details: A string providing detailed information about the error.
//   - status: An integer representing the HTTP status code associated with the error.
//
// Returns:
//   - A pointer to an AppError instance populated with the provided details.
func NewAppError(where string, ID string, params map[string]interface{}, details string, status int) *AppError {
	return &AppError{
		ID:            ID,
		params:        params,
		Message:       ID,
		Where:         where,
		DetailedError: details,
		StatusCode:    status,
		IsOAuth:       false,
	}
}

// Translate translates the error message using the provided TranslateFunc.
// If the error has parameters, they will be passed to the TranslateFunc.
//
// Parameters:
//   - T: A function that takes an error ID and optional parameters, and returns a translated message.
//
// Example usage:
//
//	err := &AppError{ID: "error_id", params: []interface{}{"param1", "param2"}}
//	err.Translate(myTranslateFunc)
func (er *AppError) Translate(T TranslateFunc) {
	if er.params == nil {
		er.Message = T(er.ID)
	} else {
		er.Message = T(er.ID, er.params)
	}
}

// ToJSON converts the AppError instance to a JSON string with indentation.
// If the marshalling process encounters an error, it returns an empty string.
//
// Returns:
//
//	string: The JSON representation of the AppError instance or an empty string if an error occurs.
func (er *AppError) ToJSON() string {
	b, err := json.MarshalIndent(er, "", "    ")
	if err != nil {
		return ""
	}

	return string(b)
}
