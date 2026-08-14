package common

import (
	"fmt"
	"os/exec"
	"runtime"
)

// execCommand is exec.Command by default; overridable in tests.
var execCommand = exec.Command

// OpenBrowser attempts to open url in the user's default system browser.
// A failure to open (e.g. a headless environment with no display) is
// returned to the caller so it can fall back to printing the URL instead —
// no caller in this codebase treats it as fatal.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = execCommand("open", url)
	case "windows":
		cmd = execCommand("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = execCommand("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}
	return nil
}
