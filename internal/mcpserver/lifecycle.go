package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

// errorResult builds a failed tool result.
//
// Failures are results rather than Go errors on purpose. The SDK's own
// documentation on IsError notes that a protocol-level error means "the LLM
// would not be able to see that an error occurred and self-correct".
func errorResult(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
	}
}

// withLifecycle wraps a handler with a rate-limit check, a deadline, a
// correlation id and panic recovery. register applies it to every tool, so no
// tool can opt out.
func withLifecycle[In, Out any](s *Server, tier Tier, name string, h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (result *mcp.CallToolResult, out Out, err error) {
		// The limit is checked before the handler, before the vault guard,
		// and before any network call, so a refused call costs nothing.
		if !s.limits.allow(tier) {
			var zero Out
			s.logger.Warn("tool call refused by rate limit", "tool", name, "tier", tier.String())
			return errorResult(
				"%s was refused by the rate limit for %s operations; wait before retrying",
				name, tier.String()), zero, nil
		}

		ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		defer cancel()

		correlationID := uuid.NewString()
		ctx = vaultapi.WithCorrelationID(ctx, correlationID)

		// A panic must not escape. The SDK runs handlers on the session's
		// goroutine, so an unrecovered panic would kill the process -- and
		// for a stdio server that means the host's session dies
		// mid-conversation with no diagnostic.
		defer func() {
			if recovered := recover(); recovered != nil {
				var zero Out
				// The panic value can carry anything, including a secret, so
				// it is logged but never returned to the model.
				s.logger.Error("tool panicked",
					"tool", name,
					"correlation_id", correlationID,
					"panic", fmt.Sprint(recovered))
				result, out, err = errorResult("%s failed with an internal error", name), zero, nil
			}
		}()

		started := time.Now()
		result, out, err = h(ctx, req, in)

		// A handler that returned because its deadline expired should say so
		// in terms the model can act on.
		if err != nil && ctx.Err() != nil {
			var zero Out
			result, out, err = errorResult("%s timed out after %s", name, s.cfg.RequestTimeout), zero, nil
		}

		// One line per call, on stderr. Arguments are deliberately absent:
		// they can carry a secret value.
		outcome := "ok"
		if err != nil || (result != nil && result.IsError) {
			outcome = "error"
		}
		s.logger.Info("tool call",
			"tool", name,
			"outcome", outcome,
			"correlation_id", correlationID,
			"duration_ms", time.Since(started).Milliseconds(),
			"vault", s.cfg.Vault)

		return result, out, err
	}
}
