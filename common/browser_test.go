package common

import (
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenBrowser_UsesPlatformCommand(t *testing.T) {
	var gotName string
	var gotArgs []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = args
		// Re-exec the current test binary with a flag that matches no test —
		// a real, always-present executable so Start() succeeds on every OS.
		return exec.Command(os.Args[0], "-test.run=TestOpenBrowser_NoSuchTest")
	}
	t.Cleanup(func() { execCommand = exec.Command })

	err := OpenBrowser("http://127.0.0.1:9999/callback")
	assert.NoError(t, err)

	switch runtime.GOOS {
	case "darwin":
		assert.Equal(t, "open", gotName)
		assert.Equal(t, []string{"http://127.0.0.1:9999/callback"}, gotArgs)
	case "windows":
		assert.Equal(t, "rundll32", gotName)
		assert.Equal(t, []string{"url.dll,FileProtocolHandler", "http://127.0.0.1:9999/callback"}, gotArgs)
	default:
		assert.Equal(t, "xdg-open", gotName)
		assert.Equal(t, []string{"http://127.0.0.1:9999/callback"}, gotArgs)
	}
}

func TestOpenBrowser_StartFailure_ReturnsError(t *testing.T) {
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("/nonexistent/binary-that-does-not-exist")
	}
	t.Cleanup(func() { execCommand = exec.Command })

	err := OpenBrowser("http://127.0.0.1:9999/callback")
	assert.Error(t, err)
}
