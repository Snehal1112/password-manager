package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// ApiParams holds all URL path variables and query parameters for a request.
// Populated once per request by ApiParamsFromRequest and stored on Context.Params.
type ApiParams struct {
	// Path variables — populated from mux route patterns
	UserID           string
	SecretID         string
	KeyID            string
	CertificateID    string
	PolicyID         string
	ServiceAccountID string
	SessionID        string
	PrincipalID      string
	VaultName        string
	AssignmentID     string
	Version          int // {version} parsed to int; 0 if absent

	// Pagination
	Page    int // default: 0, floor: 0
	PerPage int // default: 60, max: 200

	// Filters
	Tags      []string // ?tags=a,b split on comma
	Permanent bool     // ?permanent=true
}

// ApiParamsFromRequest parses mux route variables and query string into ApiParams.
func ApiParamsFromRequest(r *http.Request) *ApiParams {
	vars := mux.Vars(r)
	p := &ApiParams{
		UserID:           vars["user_id"],
		SecretID:         vars["secret_id"],
		KeyID:            vars["key_id"],
		CertificateID:    vars["certificate_id"],
		PolicyID:         vars["policy_id"],
		ServiceAccountID: vars["service_account_id"],
		SessionID:        vars["session_id"],
		PrincipalID:      vars["principal_id"],
		VaultName:        vars["vault_name"],
		AssignmentID:     vars["assignment_id"],
	}

	if v, err := strconv.Atoi(vars["version"]); err == nil {
		p.Version = v
	}

	q := r.URL.Query()

	if page, err := strconv.Atoi(q.Get("page")); err == nil && page >= 0 {
		p.Page = page
	}

	perPage := 60
	if pp, err := strconv.Atoi(q.Get("per_page")); err == nil && pp > 0 {
		perPage = pp
	}
	if perPage > 200 {
		perPage = 200
	}
	p.PerPage = perPage

	if tagsParam := q.Get("tags"); tagsParam != "" {
		p.Tags = strings.Split(tagsParam, ",")
	}

	p.Permanent = q.Get("permanent") == "true"

	return p
}
