package cliclient

import "fmt"

// RequireLocal returns an error if a remote target is configured, for
// commands with no server-side HTTP route to call: backup create/restore,
// master-key rotate, vaults purge/recover (see the design doc's Command
// Support Matrix). commandName is used in the error message, e.g.
// "master-key rotate". Returns nil in local mode.
func RequireLocal(serverFlag, commandName string) error {
	target, err := ResolveTarget(serverFlag)
	if err != nil {
		return err
	}
	if target != nil {
		return fmt.Errorf(
			"%s is a local-only operation and cannot target a remote server; "+
				"unset --server / ROCKETVAULT_ADDR / the active context to run it "+
				"against this machine's own instance",
			commandName,
		)
	}
	return nil
}
