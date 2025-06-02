package api

import (
	"github.com/gorilla/mux"

	"password-manager/app"
	"password-manager/internal/logging"
)

// Options is a function type that takes a pointer to an API instance.
// It is used to apply various configuration options to the API.
type Options func(a *API)

// WithAPP is an option function that sets the provided app.App instance
// to the API. It returns an Options function that assigns the given
// app.App to the API's App field.
//
// Parameters:
//
//	app - a pointer to an app.App instance to be set in the API.
//
// Returns:
//
//	An Options function that sets the provided app.App instance to the API.
func WithAPP(app *app.App) Options {
	return func(a *API) {
		a.App = app
	}
}

// WithBasePath sets the base path for the API.
// It takes a string parameter basePath which specifies the base path to be set.
// It returns an Options function that modifies the basePath field of the API struct.
func WithBasePath(basePath string) Options {
	return func(a *API) {
		a.basePath = basePath
	}
}

// WithRouter sets the root router for the API.
// It takes a *mux.Router as an argument and returns an Options function
// that assigns the provided router to the API's rootRouter field.
//
// Example usage:
//
//	router := mux.NewRouter()
//	api := &API{}
//	option := WithRouter(router)
//	option(api)
//
// Parameters:
//
//	root (*mux.Router): The root router to be used by the API.
//
// Returns:
//
//	Options: A function that sets the root router of the API.
func WithRouter(root *mux.Router) Options {
	return func(a *API) {
		a.rootRouter = root
	}
}

// WithLogger sets the logger for the API.
// It takes a logrus.FieldLogger as an argument and returns an Options function
// that assigns the provided logger to the API instance.
func WithLogger(logger *logging.Logger) Options {
	return func(a *API) {
		a.Logger = logger
	}
}
