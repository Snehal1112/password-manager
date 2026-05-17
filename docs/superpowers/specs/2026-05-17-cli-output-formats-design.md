# CLI Output Formats — Design Spec

**Date**: 2026-05-17
**Status**: Approved
**Scope**: All `list` and `get` commands across secrets, keys, users, and certificates

---

## Problem

CLI output is inconsistent and not scriptable:

- `secrets list` / `secrets get` → JSON via `json.MarshalIndent` (hardcoded)
- `keys list` / `keys get` → ad-hoc `fmt.Printf("- ID=%s, ...")` text
- `users list` / `users get` → same ad-hoc text
- `certificates list` / `certificates get` → same ad-hoc text

There is no `--output` flag. Format is baked into each command. Users cannot switch between human-readable and machine-readable output.

---

## Goal

Add a single `--output` flag (values: `table`, `json`, `yaml`, default: `table`) that works uniformly across all `list` and `get` commands, with zero impact on domain types.

---

## Architecture

The solution spans three layers, each with a single responsibility:

```
cmd/ (delivery layer)
  └── reads --output from context
  └── translates domain structs → [][]string rows
  └── calls formatter.Write(os.Stdout, headers, rows)

internal/formatter/ (infrastructure layer)
  └── Formatter interface
  └── tableFormatter, jsonFormatter, yamlFormatter implementations
  └── New(format) factory

internal/domain/ (domain layer)
  └── untouched — no formatting concerns
```

This mirrors the existing `internal/logging` pattern: infrastructure package, consumed by delivery, invisible to domain.

### Strict import boundary

`internal/formatter/` is a **CLI-only** infrastructure package. It must never be imported by:

- `api/` — the REST layer writes directly to `http.ResponseWriter` via `json.NewEncoder` and is unaffected by this feature
- `internal/services/` — business logic has no formatting concern
- `internal/domain/` — domain types must remain format-agnostic

The two delivery layers remain completely independent:

```
api/     → http.ResponseWriter (json.NewEncoder) — REST, always JSON, unchanged
cmd/     → internal/formatter/ → os.Stdout      — CLI only, --output controlled
```

No changes to `api/` are required or permitted as part of this feature.

---

## Section 1 — The Formatter Package (`internal/formatter/`)

### Package location

`internal/formatter/` — alongside `internal/logging`, `internal/validation`, and other infrastructure packages. No dependency on `internal/domain`.

### Public API

```go
// Format is the output format type.
type Format string

const (
    FormatTable Format = "table"
    FormatJSON  Format = "json"
    FormatYAML  Format = "yaml"
)

// Formatter renders tabular data in a given format.
type Formatter interface {
    Write(w io.Writer, headers []string, rows [][]string) error
}

// New returns a Formatter for the given format string.
// Returns an error if the format is not recognised.
func New(format Format) (Formatter, error)
```

### Implementations

**`tableFormatter`**
- Uses `text/tabwriter` from stdlib — no new dependency.
- Pre-scans all rows to compute max column widths.
- Output: padded header row, `---` separator line, then data rows.
- Example:
  ```
  ID                                    NAME       TYPE   CREATED
  ----                                  ----       ----   -------
  3f2a...                               my-key     RSA    2026-01-01T00:00:00Z
  ```

**`jsonFormatter`**
- Zips `headers` and each `row` into `map[string]string`.
- Marshals the slice with `json.MarshalIndent`.
- Output is a JSON array, one object per row.

**`yamlFormatter`**
- Same `[]map[string]string` construction as JSON.
- Marshals with `gopkg.in/yaml.v3` (already in `go.mod`).

### Files

```
internal/formatter/
  formatter.go       — Format type, Formatter interface, New() factory
  table.go           — tableFormatter implementation
  json.go            — jsonFormatter implementation
  yaml.go            — yamlFormatter implementation
  formatter_test.go  — unit tests for all three formatters
```

---

## Section 2 — Flag and Context Wiring

### Flag definition (`cmd/root.go`)

One persistent flag on `rootCmd`, defined in `init()`:

```go
rootCmd.PersistentFlags().String("output", "table", "Output format: table, json, yaml")
```

### Context key (`common/context.go`)

One new key added alongside existing keys:

```go
OutputFormatterKey = &contextKey{"output_formatter"}
```

### `persistentPreRun` (`cmd/root.go`)

After the service container is constructed, read the flag and store the formatter in context:

```go
outputFlag, _ := cmd.Flags().GetString("output")
fmtr, err := formatter.New(formatter.Format(outputFlag))
if err != nil {
    return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
}
ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
cmd.SetContext(ctx)
```

This is consistent with how `ServiceContainerKey` and `LogKey` are already wired. No globals.

---

## Section 3 — Per-Command Changes

### Pattern

Every affected command replaces its current output logic with:

```go
fmtr := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if err := fmtr.Write(os.Stdout, headers, rows); err != nil {
    return fmt.Errorf("failed to write output: %w", err)
}
```

The command's only job is building `headers` and `rows` from its domain structs. That translation stays in `cmd/` — correct for the delivery layer.

### Commands affected (10 files)

| Command | File |
|---|---|
| `secrets list` | `cmd/secrets/list.go` |
| `secrets get` | `cmd/secrets/get.go` |
| `keys list` | `cmd/keys/list.go` |
| `keys get` | `cmd/keys/get.go` |
| `users list` | `cmd/users/list.go` |
| `users get` | `cmd/users/get.go` |
| `certificates list` | `cmd/certificates/list.go` |
| `certificates get` | `cmd/certificates/get.go` |
| `keys create` | `cmd/keys/create.go` (prints created key) |
| `certificates create` | `cmd/certificates/create.go` (prints created cert) |

### Column definitions per resource

**Secrets list**: `ID`, `Name`, `Version`, `Enabled`, `Tags`, `Created`
**Secrets get**: same columns plus `ContentType`, `Expires`, `NotBefore`
**Keys list/get**: `ID`, `Name`, `Type`, `Revoked`, `Tags`, `Created`
**Users list/get**: `ID`, `Username`, `Role`, `Created`
**Certificates list/get**: `ID`, `Name`, `Tags`, `Expires`, `AutoRenew`, `Created`

### Breaking change

`secrets list` and `secrets get` currently default to JSON output. After this change they default to `table`. Scripts relying on the current JSON output must pass `--output json` explicitly. This is intentional — consistency across all commands takes priority.

---

## Section 4 — Table Rendering Detail

### Width calculation

```
for each column index c:
    width[c] = max(len(headers[c]), max over rows of len(row[c]))
```

All rows are already in memory (returned from service calls) so buffering is not a concern.

### Separator line

Each column separator is `strings.Repeat("-", width[c])`, padded to the same width. Keeps the table scannable without a heavy border character set.

### `text/tabwriter` usage

`tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)` — minimum cell width 0, padding 2 spaces, space pad character. This gives clean elastic columns without needing a third-party table library.

### No color / no terminal detection

Out of scope for this iteration. Plain text output works correctly when piped to files or other commands.

---

## Dependencies

| Dependency | Status |
|---|---|
| `text/tabwriter` | stdlib — already available |
| `encoding/json` | stdlib — already used |
| `gopkg.in/yaml.v3` | already in `go.mod` |

Zero new dependencies required.

---

## Testing

- **`internal/formatter/formatter_test.go`**: Unit tests for all three formatters. Covers: empty rows, single row, multi-row, header-only, special characters in values.
- **Existing command tests**: No changes required — tests use mock service containers and do not assert on stdout format. Format output is tested at the formatter layer.

---

## Out of Scope

- Color / terminal detection
- Column selection flags (`--columns id,name`)
- Paging / scrolling
- CSV format (can be added later by implementing `Formatter`)
- `watch` mode

---

## Implementation Order

1. `internal/formatter/` package (all four files + tests)
2. `common/context.go` — add `OutputFormatterKey`
3. `cmd/root.go` — add flag + wiring in `persistentPreRun`
4. `cmd/secrets/list.go`, `cmd/secrets/get.go`
5. `cmd/keys/list.go`, `cmd/keys/get.go`, `cmd/keys/create.go`
6. `cmd/users/list.go`, `cmd/users/get.go`
7. `cmd/certificates/list.go`, `cmd/certificates/get.go`, `cmd/certificates/create.go`
8. Build verification: `go build ./...` and `go test ./...`
