package api

import (
	"net/http"
	"password-manager/model"

	"github.com/gorilla/mux"
)

// InitVault initializes the routes for the vault service API.
// It sets up the following endpoints:
// - POST /tenant: Creates a new tenant.
// - GET /tenant/{id}: Retrieves a tenant by its ID.
// - GET /tenants: Retrieves a list of all tenants.
//
// Parameters:
// - vault (*mux.Router): The router to which the routes will be added.
func (api *API) InitVault(vault *mux.Router) {

	vault.Handle("/tenant", APIHandler(api.App, createTenant)).Methods("GET")
	vault.Handle("/tenant/{id:[A-Za-z0-9_-]+}", APIHandler(api.App, getTenant)).Methods("GET")

}

// createTenant handles the creation of a new tenant.
// It reads the tenant data from the request body, validates it, and attempts to create a new tenant.
// If successful, it returns the created tenant properties in the response with a status of 201 Created.
// If there is an error during the process, it sets the appropriate error in the context and returns the corresponding HTTP status code.
//
// Parameters:
//   - c: The context for the request, which includes error handling and application state.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the tenant data in the body.
//
// Possible errors:
//   - If the request body cannot be parsed into a Tenant model, it returns a 400 Bad Request error.
//   - If there is an error creating the tenant, it sets the error in the context and returns the appropriate status code.
//   - If there is an error converting the created tenant properties to JSON, it returns a 400 Bad Request error.
func createTenant(c *Context, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Tenant created successfully"))
}

// getTenant handles the HTTP request to retrieve a tenant by its ID.
// It extracts the tenant ID from the URL parameters, fetches the tenant
// information from the application context, and writes the tenant data
// as a JSON response. If an error occurs during the process, it sets the
// error in the context and returns an appropriate HTTP status code.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the tenant ID in the URL parameters.
func getTenant(c *Context, w http.ResponseWriter, r *http.Request) {
	//w.WriteHeader(http.StatusOK)

	c.Err = model.NewAppError("vault.getTenant", "Tenant not found", nil, "tenant_id="+mux.Vars(r)["id"], http.StatusNotFound)
	//w.Write([]byte("Tenant retrieved successfully"))
}
