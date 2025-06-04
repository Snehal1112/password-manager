package api

import (
	"net/http"

	"password-manager/app"
	"password-manager/common"
)

// handler represents an HTTP handler with additional context and configuration.
// It includes the following fields:
//   - app: A reference to the application instance.
//   - handleFunc: The function to handle the HTTP request, which takes a Context,
//     an http.ResponseWriter, and an http.Request as parameters.
//   - requireSession: A boolean indicating whether a session is required for the handler.
//   - trustRequester: A boolean indicating whether the requester is trusted.
//   - requireMfa: A boolean indicating whether multi-factor authentication is required.
type handler struct {
	app            *app.App
	handleFunc     func(*Context, http.ResponseWriter, *http.Request)
	requireSession bool
	trustRequester bool
	requireMfa     bool
}

// Context holds the contextual information for a request in the vault-service application.
// It includes references to the application instance, translation function, error details,
// request ID, IP address, and request path.
type Context struct {
	App       *app.App
	T         common.TranslateFunc
	Err       *common.AppError
	RequestID string
	IPAddress string
	Path      string
	//Session       *model.Session
}

// APIHandler wraps a given handler function with additional context and returns an http.Handler.
// The provided handler function takes a custom Context, an http.ResponseWriter, and an http.Request as parameters.
// This method initializes a handler with default settings for session, requester trust, and MFA requirements.
//
// Parameters:
//
//	h - A function that takes a *Context, http.ResponseWriter, and *http.Request.
//
// Returns:
//
//	An http.Handler that can be used to handle HTTP requests.
func (api *API) APIHandler(h func(*Context, http.ResponseWriter, *http.Request)) http.Handler {
	return &handler{
		app:            api.App,
		handleFunc:     h,
		requireSession: false,
		trustRequester: false,
		requireMfa:     false,
	}
}

// APISessionRequired is a middleware that ensures the request has a valid session.
// It wraps the provided handler function and checks for session validity, requiring
// multi-factor authentication (MFA) and not trusting the requester by default.
//
// Parameters:
//
//	h - The handler function to be wrapped, which takes a Context, http.ResponseWriter,
//	    and *http.Request as arguments.
//
// Returns:
//
//	An http.Handler that enforces session requirements before calling the provided handler.
func (api *API) APISessionRequired(h func(*Context, http.ResponseWriter, *http.Request)) http.Handler {
	return &handler{
		app:            api.App,
		handleFunc:     h,
		requireSession: true,
		trustRequester: false,
		requireMfa:     true,
	}
}

// ServeHTTP handles incoming HTTP requests, creates a new context for each request,
// and processes the request using the appropriate handler function. It sets the
// request ID and content type headers if there is no error in the context. If an
// error occurs, it delegates error handling to the handleError function.
//
// Parameters:
//   - w: http.ResponseWriter to write the HTTP response.
//   - r: *http.Request representing the incoming HTTP request.
func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Create a new context for the request
	c := &Context{
		App:       h.app,
		T:         common.T,
		RequestID: common.NewID(),
		IPAddress: common.GetIPAddress(r),
		Path:      r.URL.Path,
	}

	// TODO: check Authorization headers.

	// If there is no error in the context, set the headers and call the handler function
	if c.Err == nil {
		// Set the request ID and content type headers
		w.Header().Set(common.HeaderRequestID, c.RequestID)
		w.Header().Set("Content-Type", "application/json")

		h.handleFunc(c, w, r)
	}

	// If there is an error in the context, handle it
	if c.Err != nil {
		h.handleError(c, w, r)
	}
}

// handleError handles errors by translating the error message, setting the request ID and URL path,
// and writing the error response to the HTTP response writer with the appropriate status code and JSON format.
//
// Parameters:
//   - c: The context containing the error and request information.
//   - w: The HTTP response writer to write the error response to.
//   - r: The HTTP request containing the URL path.
func (h handler) handleError(c *Context, w http.ResponseWriter, r *http.Request) {
	c.Err.Translate(c.T)
	c.Err.RequestID = c.RequestID
	c.Err.Where = r.URL.Path

	w.WriteHeader(c.Err.StatusCode)
	w.Write([]byte(c.Err.ToJSON()))
}
