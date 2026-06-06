package model

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAssignRoleRequestFromJson(t *testing.T) {
	body := `{"principal":"alice","principal_type":"user","role":"secrets-user"}`
	req, err := AssignRoleRequestFromJson(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.Principal != "alice" || req.Role != "secrets-user" || req.PrincipalType != "user" {
		t.Fatalf("unexpected: %+v", req)
	}
}

func TestRoleAssignmentResponseToJson(t *testing.T) {
	resp := RoleAssignmentResponse{ID: uuid.New().String(), Role: "secrets-user"}
	if !strings.Contains(resp.ToJson(), "secrets-user") {
		t.Fatalf("ToJson missing role: %s", resp.ToJson())
	}
}
