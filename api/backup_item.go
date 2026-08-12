package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"rocketvault/internal/backup"
)

// InitBackupItem registers per-item backup and restore routes onto the existing
// Secrets, Keys, and Certificates subrouters.
func (api *API) InitBackupItem() {
	s := api.BaseRoutes.Secrets
	k := api.BaseRoutes.Keys
	c := api.BaseRoutes.Certificates

	// Secret backup / restore.
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}/backup",
		ApiSessionRequired(api.App, backupSecretHandler)).Methods("POST")
	s.Handle("/restore",
		ApiSessionRequired(api.App, restoreSecretHandler)).Methods("POST")

	// Key backup / restore.
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/backup",
		ApiSessionRequired(api.App, backupKeyHandler)).Methods("POST")
	k.Handle("/restore",
		ApiSessionRequired(api.App, restoreKeyHandler)).Methods("POST")

	// Certificate backup / restore.
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/backup",
		ApiSessionRequired(api.App, backupCertificateHandler)).Methods("POST")
	c.Handle("/restore",
		ApiSessionRequired(api.App, restoreCertificateHandler)).Methods("POST")
}

// itemBackupSvc is a helper that retrieves the ItemBackupService from the
// container. It sets an internal error on the context when unavailable.
func itemBackupSvc(c *Context) *backup.ItemBackupService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetItemBackupService()
}

// getUserID extracts and parses the caller's user ID from JWT claims.
// It sets an appropriate error on the context when the ID is missing or invalid.
func getUserID(c *Context) (uuid.UUID, bool) {
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return uuid.Nil, false
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return uuid.Nil, false
	}
	return userID, true
}

// restoreRequest is the JSON body expected by all restore endpoints.
type restoreRequest struct {
	Blob string `json:"blob"`
}

// backupSecretHandler creates a backup blob for a secret and returns it.
func backupSecretHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	blob, err := svc.BackupSecret(r.Context(), secretID, userID)
	if err != nil {
		if errors.Is(err, backup.ErrForbidden) {
			c.SetPermissionError("backup_secret")
		} else {
			c.SetNotFound("secret")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"blob": blob}) //nolint:errcheck
}

// restoreSecretHandler decodes a backup blob and re-inserts the secret.
func restoreSecretHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Blob == "" {
		c.SetInvalidParam("blob")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	if err := svc.RestoreSecret(r.Context(), req.Blob, userID, uuid.New()); err != nil {
		switch {
		case errors.Is(err, backup.ErrForbidden):
			c.SetPermissionError("cannot restore: forbidden")
		case errors.Is(err, backup.ErrInvalidBlob):
			c.SetInvalidParam("blob")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}

// backupKeyHandler creates a backup blob for a key and returns it.
func backupKeyHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	blob, err := svc.BackupKey(r.Context(), keyID, userID)
	if err != nil {
		if errors.Is(err, backup.ErrForbidden) {
			c.SetPermissionError("backup_key")
		} else {
			c.SetNotFound("key")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"blob": blob}) //nolint:errcheck
}

// restoreKeyHandler decodes a backup blob and re-inserts the key.
func restoreKeyHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Blob == "" {
		c.SetInvalidParam("blob")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	if err := svc.RestoreKey(r.Context(), req.Blob, userID, uuid.New()); err != nil {
		switch {
		case errors.Is(err, backup.ErrForbidden):
			c.SetPermissionError("cannot restore: forbidden")
		case errors.Is(err, backup.ErrInvalidBlob):
			c.SetInvalidParam("blob")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}

// backupCertificateHandler creates a backup blob for a certificate and returns it.
func backupCertificateHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	blob, err := svc.BackupCertificate(r.Context(), certID, userID)
	if err != nil {
		if errors.Is(err, backup.ErrForbidden) {
			c.SetPermissionError("backup_certificate")
		} else {
			c.SetNotFound("certificate")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"blob": blob}) //nolint:errcheck
}

// restoreCertificateHandler decodes a backup blob and re-inserts the certificate.
func restoreCertificateHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Blob == "" {
		c.SetInvalidParam("blob")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	if err := svc.RestoreCertificate(r.Context(), req.Blob, userID, uuid.New()); err != nil {
		switch {
		case errors.Is(err, backup.ErrForbidden):
			c.SetPermissionError("cannot restore: forbidden")
		case errors.Is(err, backup.ErrInvalidBlob):
			c.SetInvalidParam("blob")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}
