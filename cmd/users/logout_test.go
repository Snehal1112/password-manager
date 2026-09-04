package users

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

func TestRunLogout_ExplicitUsername_DeletesThatSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	require.NoError(t, common.SaveSession(&common.SessionCache{Username: "admin", Token: "tok", ExpiresAt: time.Now().Add(time.Hour)}))

	require.NoError(t, runLogout(common.LocalServerKey, "admin"))

	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached)
}

func TestRunLogout_NoUsername_DeletesCurrentSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	require.NoError(t, common.SaveSession(&common.SessionCache{Username: "user14", Token: "tok", ExpiresAt: time.Now().Add(time.Hour)}))

	require.NoError(t, runLogout(common.LocalServerKey, ""))

	cached, err := common.LoadSession("user14")
	require.NoError(t, err)
	assert.Nil(t, cached)
}

func TestRunLogout_NoUsernameNoCurrentSession_NoError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()

	assert.NoError(t, runLogout(common.LocalServerKey, ""))
}
