# CLI Output Formats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--output table|json|yaml` flag (default: `table`) to all CLI `list` and `get` commands, with a shared `internal/formatter/` package — leaving the REST API layer entirely unchanged.

**Architecture:** A new `internal/formatter/` infrastructure package exposes a `Formatter` interface with three implementations (table, JSON, YAML). The `--output` flag is defined once on the root Cobra command; `persistentPreRun` constructs the formatter and stores it in context under `common.OutputFormatterKey`. Each affected `cmd/` file reads the formatter from context, builds `headers []string` and `rows [][]string` from its domain structs, and calls `formatter.Write`. The `api/` layer is untouched.

**Tech Stack:** Go 1.24, `text/tabwriter` (stdlib), `encoding/json` (stdlib), `gopkg.in/yaml.v3` (already in go.mod), `github.com/spf13/cobra`

---

## File Map

**Create:**
- `internal/formatter/formatter.go` — `Format` type, `Formatter` interface, `New()` factory
- `internal/formatter/table.go` — `tableFormatter` using `text/tabwriter`
- `internal/formatter/json.go` — `jsonFormatter` using `encoding/json`
- `internal/formatter/yaml.go` — `yamlFormatter` using `gopkg.in/yaml.v3`
- `internal/formatter/formatter_test.go` — unit tests for all three formatters

**Modify:**
- `common/context.go` — add `OutputFormatterKey`
- `cmd/root.go` — add `--output` flag in `init()`, wire formatter in `persistentPreRun`
- `cmd/secrets/list.go` — replace `json.MarshalIndent` with formatter
- `cmd/secrets/get.go` — replace `json.MarshalIndent` / `log.Println` with formatter
- `cmd/secrets/create.go` — replace `logrus` info-only output with formatter confirmation row
- `cmd/keys/list.go` — replace `fmt.Printf` loop with formatter
- `cmd/keys/get.go` — replace `fmt.Printf` with formatter
- `cmd/keys/create.go` — replace `log.WithFields` info-only output with formatter confirmation row
- `cmd/users/list.go` — replace `fmt.Printf` loop with formatter
- `cmd/users/get.go` — replace `fmt.Printf` with formatter
- `cmd/certificates/list.go` — replace `fmt.Printf` loop with formatter
- `cmd/certificates/get.go` — replace `fmt.Printf` with formatter
- `cmd/certificates/create.go` — replace `fmt.Printf` with formatter

---

## Task 1: Create the formatter package — interface and factory

**Files:**
- Create: `internal/formatter/formatter.go`

- [ ] **Step 1: Create `internal/formatter/formatter.go`**

```go
package formatter

import "io"

// Format is the CLI output format type.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

// Formatter renders tabular data to a writer.
type Formatter interface {
	Write(w io.Writer, headers []string, rows [][]string) error
}

// New returns a Formatter for the given format.
// Returns an error if the format is not recognised.
func New(f Format) (Formatter, error) {
	switch f {
	case FormatTable:
		return &tableFormatter{}, nil
	case FormatJSON:
		return &jsonFormatter{}, nil
	case FormatYAML:
		return &yamlFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported output format %q: must be table, json, or yaml", f)
	}
}
```

Add the missing `fmt` import — the full file:

```go
package formatter

import (
	"fmt"
	"io"
)

// Format is the CLI output format type.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

// Formatter renders tabular data to a writer.
type Formatter interface {
	Write(w io.Writer, headers []string, rows [][]string) error
}

// New returns a Formatter for the given format.
// Returns an error if the format is not recognised.
func New(f Format) (Formatter, error) {
	switch f {
	case FormatTable:
		return &tableFormatter{}, nil
	case FormatJSON:
		return &jsonFormatter{}, nil
	case FormatYAML:
		return &yamlFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported output format %q: must be table, json, or yaml", f)
	}
}
```

- [ ] **Step 2: Verify it compiles (stubs needed first — create empty struct files)**

Create `internal/formatter/table.go`:
```go
package formatter

import "io"

type tableFormatter struct{}

func (f *tableFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	return nil
}
```

Create `internal/formatter/json.go`:
```go
package formatter

import "io"

type jsonFormatter struct{}

func (f *jsonFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	return nil
}
```

Create `internal/formatter/yaml.go`:
```go
package formatter

import "io"

type yamlFormatter struct{}

func (f *yamlFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	return nil
}
```

- [ ] **Step 3: Run build check**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./internal/formatter/...
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add internal/formatter/formatter.go internal/formatter/table.go internal/formatter/json.go internal/formatter/yaml.go
git commit -m "feat(formatter): add formatter interface and stub implementations"
```

---

## Task 2: Implement tableFormatter

**Files:**
- Modify: `internal/formatter/table.go`

- [ ] **Step 1: Write the failing test**

Create `internal/formatter/formatter_test.go`:

```go
package formatter

import (
	"bytes"
	"strings"
	"testing"
)

func TestTableFormatter_Empty(t *testing.T) {
	f := &tableFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"ID", "Name"}, [][]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ID") || !strings.Contains(out, "Name") {
		t.Errorf("expected headers in output, got: %q", out)
	}
}

func TestTableFormatter_MultiRow(t *testing.T) {
	f := &tableFormatter{}
	var buf bytes.Buffer
	headers := []string{"ID", "Name", "Type"}
	rows := [][]string{
		{"abc-123", "my-key", "RSA"},
		{"def-456", "other-key", "ECDSA"},
	}
	err := f.Write(&buf, headers, rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ID", "Name", "Type", "abc-123", "my-key", "RSA", "def-456", "other-key", "ECDSA"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestTableFormatter_SeparatorLine(t *testing.T) {
	f := &tableFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"ID"}, [][]string{{"val"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 3 {
		t.Errorf("expected at least 3 lines (header, separator, data), got %d:\n%s", len(lines), buf.String())
	}
}
```

- [ ] **Step 2: Run test to confirm failure**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/formatter/... -run TestTable -v
```

Expected: FAIL — `TestTableFormatter_SeparatorLine` fails (stub returns nil, writes nothing).

- [ ] **Step 3: Implement tableFormatter**

Replace `internal/formatter/table.go` with:

```go
package formatter

import (
	"io"
	"strings"
	"text/tabwriter"
)

type tableFormatter struct{}

func (f *tableFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Write header row.
	fmt.Fprintln(tw, strings.Join(headers, "\t"))

	// Write separator — dashes matching each header width.
	seps := make([]string, len(headers))
	for i, h := range headers {
		maxLen := len(h)
		for _, row := range rows {
			if i < len(row) && len(row[i]) > maxLen {
				maxLen = len(row[i])
			}
		}
		seps[i] = strings.Repeat("-", maxLen)
	}
	fmt.Fprintln(tw, strings.Join(seps, "\t"))

	// Write data rows.
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}

	return tw.Flush()
}
```

Add the `fmt` import — full file:

```go
package formatter

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

type tableFormatter struct{}

func (f *tableFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintln(tw, strings.Join(headers, "\t"))

	seps := make([]string, len(headers))
	for i, h := range headers {
		maxLen := len(h)
		for _, row := range rows {
			if i < len(row) && len(row[i]) > maxLen {
				maxLen = len(row[i])
			}
		}
		seps[i] = strings.Repeat("-", maxLen)
	}
	fmt.Fprintln(tw, strings.Join(seps, "\t"))

	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}

	return tw.Flush()
}
```

- [ ] **Step 4: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/formatter/... -run TestTable -v
```

Expected: all three `TestTable*` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/formatter/table.go internal/formatter/formatter_test.go
git commit -m "feat(formatter): implement tableFormatter with tabwriter"
```

---

## Task 3: Implement jsonFormatter

**Files:**
- Modify: `internal/formatter/json.go`
- Modify: `internal/formatter/formatter_test.go`

- [ ] **Step 1: Add JSON tests to formatter_test.go**

Append to `internal/formatter/formatter_test.go`:

```go
func TestJSONFormatter_Output(t *testing.T) {
	f := &jsonFormatter{}
	var buf bytes.Buffer
	headers := []string{"id", "name"}
	rows := [][]string{
		{"abc-123", "my-key"},
		{"def-456", "other-key"},
	}
	err := f.Write(&buf, headers, rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`"id"`, `"abc-123"`, `"name"`, `"other-key"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in JSON output, got:\n%s", want, out)
		}
	}
}

func TestJSONFormatter_Empty(t *testing.T) {
	f := &jsonFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"id"}, [][]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("expected [] for empty rows, got: %q", buf.String())
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/formatter/... -run TestJSON -v
```

Expected: FAIL — stub returns nil without writing.

- [ ] **Step 3: Implement jsonFormatter**

Replace `internal/formatter/json.go` with:

```go
package formatter

import (
	"encoding/json"
	"io"
)

type jsonFormatter struct{}

func (f *jsonFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	result := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		obj := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(row) {
				obj[h] = row[i]
			}
		}
		result = append(result, obj)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
```

- [ ] **Step 4: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/formatter/... -run TestJSON -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/formatter/json.go internal/formatter/formatter_test.go
git commit -m "feat(formatter): implement jsonFormatter"
```

---

## Task 4: Implement yamlFormatter

**Files:**
- Modify: `internal/formatter/yaml.go`
- Modify: `internal/formatter/formatter_test.go`

- [ ] **Step 1: Add YAML tests**

Append to `internal/formatter/formatter_test.go`:

```go
func TestYAMLFormatter_Output(t *testing.T) {
	f := &yamlFormatter{}
	var buf bytes.Buffer
	headers := []string{"id", "name"}
	rows := [][]string{
		{"abc-123", "my-key"},
	}
	err := f.Write(&buf, headers, rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"id:", "abc-123", "name:", "my-key"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in YAML output, got:\n%s", want, out)
		}
	}
}

func TestYAMLFormatter_Empty(t *testing.T) {
	f := &yamlFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"id"}, [][]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if out != "[]" && out != "{}" && out != "" {
		t.Errorf("unexpected output for empty rows: %q", out)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/formatter/... -run TestYAML -v
```

Expected: FAIL.

- [ ] **Step 3: Implement yamlFormatter**

Replace `internal/formatter/yaml.go` with:

```go
package formatter

import (
	"io"

	"gopkg.in/yaml.v3"
)

type yamlFormatter struct{}

func (f *yamlFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	result := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		obj := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(row) {
				obj[h] = row[i]
			}
		}
		result = append(result, obj)
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(result); err != nil {
		return err
	}
	return enc.Close()
}
```

- [ ] **Step 4: Run all formatter tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/formatter/... -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/formatter/yaml.go internal/formatter/formatter_test.go
git commit -m "feat(formatter): implement yamlFormatter"
```

---

## Task 5: Add `New()` factory test, wire context key, and root flag

**Files:**
- Modify: `internal/formatter/formatter_test.go`
- Modify: `common/context.go`
- Modify: `cmd/root.go`

- [ ] **Step 1: Add factory tests**

Append to `internal/formatter/formatter_test.go`:

```go
func TestNew_ValidFormats(t *testing.T) {
	for _, f := range []Format{FormatTable, FormatJSON, FormatYAML} {
		got, err := New(f)
		if err != nil {
			t.Errorf("New(%q) unexpected error: %v", f, err)
		}
		if got == nil {
			t.Errorf("New(%q) returned nil formatter", f)
		}
	}
}

func TestNew_InvalidFormat(t *testing.T) {
	_, err := New("csv")
	if err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}
```

- [ ] **Step 2: Run factory tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/formatter/... -run TestNew -v
```

Expected: PASS.

- [ ] **Step 3: Add OutputFormatterKey to `common/context.go`**

Open `common/context.go`. Add one line to the existing `var` block:

```go
OutputFormatterKey  = &contextKey{"output_formatter"}
```

The full var block becomes:

```go
var (
	DBKey               = &contextKey{"db"}
	DBClassKey          = &contextKey{"db_class"}
	LogKey              = &contextKey{"log"}
	UserIDKey           = &contextKey{"user_id"}
	UsernameKey         = &contextKey{"username"}
	RoleKey             = &contextKey{"role"}
	TokenKey            = &contextKey{"token"}
	ClaimsKey           = &contextKey{"claims"}
	RequestIDKey        = &contextKey{"request_id"}
	ContentTypeKey      = &contextKey{"content_type"}
	APIVersionKey       = &contextKey{"api_version"}
	ServiceContainerKey = &contextKey{"service_container"}
	OutputFormatterKey  = &contextKey{"output_formatter"}
)
```

- [ ] **Step 4: Add `--output` flag in `cmd/root.go` `init()`**

In `cmd/root.go`, inside the `init()` function, add after the existing persistent flags:

```go
rootCmd.PersistentFlags().String("output", "table", "Output format: table, json, yaml")
```

- [ ] **Step 5: Wire the formatter in `persistentPreRun` in `cmd/root.go`**

In `persistentPreRun`, find the block that sets `common.ServiceContainerKey` in context:

```go
ctx = context.WithValue(ctx, common.ServiceContainerKey, serviceContainer)
cmd.SetContext(ctx)
```

Add the formatter wiring immediately after:

```go
outputFlag, _ := cmd.Flags().GetString("output")
fmtr, err := formatter.New(formatter.Format(outputFlag))
if err != nil {
	return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
}
ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
cmd.SetContext(ctx)
```

Add the import at the top of `cmd/root.go`:

```go
"rocketvault/internal/formatter"
```

- [ ] **Step 6: Build check**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./...
```

Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/formatter/formatter_test.go common/context.go cmd/root.go
git commit -m "feat(cli): add --output flag and wire formatter into context"
```

---

## Task 6: Update `cmd/secrets/list.go` and `cmd/secrets/get.go`

**Files:**
- Modify: `cmd/secrets/list.go`
- Modify: `cmd/secrets/get.go`

- [ ] **Step 1: Update `cmd/secrets/list.go`**

Replace the entire `Run` func body output block (the `json.MarshalIndent` + `fmt.Println`) with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
	return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Name", "Version", "Enabled", "Tags", "Created"}
rows := make([][]string, len(secretsList))
for i, s := range secretsList {
	rows[i] = []string{
		s.ID.String(),
		s.Name,
		strconv.Itoa(s.Version),
		strconv.FormatBool(s.Enabled),
		strings.Join(s.Tags, ","),
		s.CreatedAt.Format(time.RFC3339),
	}
}
return fmtr.Write(os.Stdout, headers, rows)
```

The command signature must change from `Run` to `RunE` (returns error). Update the struct field and add the `return nil` at the end of non-output paths. Add imports:

```go
"fmt"
"os"
"strconv"
"strings"
"time"

"rocketvault/internal/formatter"
```

Remove the now-unused `"encoding/json"` import.

- [ ] **Step 2: Update `cmd/secrets/get.go`**

Replace the output block (the `json.MarshalIndent` + `log.Println`) with:

```go
fmtr, ok := cmd.Context().Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
	return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Name", "Version", "Enabled", "ContentType", "Tags", "Expires", "NotBefore", "Created"}
row := []string{
	secret.ID.String(),
	secret.Name,
	strconv.Itoa(secret.Version),
	strconv.FormatBool(secret.Enabled),
	secret.ContentType,
	strings.Join(secret.Tags, ","),
	formatOptionalTime(secret.ExpiresAt),
	formatOptionalTime(secret.NotBefore),
	secret.CreatedAt.Format(time.RFC3339),
}
return fmtr.Write(os.Stdout, headers, [][]string{row})
```

Add a package-level helper at the bottom of `cmd/secrets/get.go` (also used in list):

```go
func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
```

Change `Run` to `RunE`. Add imports: `"fmt"`, `"os"`, `"strconv"`, `"strings"`, `"time"`, `"rocketvault/internal/formatter"`. Remove `"encoding/json"` and `"log"`.

- [ ] **Step 3: Build check**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/secrets/...
```

Expected: no errors.

- [ ] **Step 4: Run existing tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/secrets/... -v
```

Expected: all existing tests PASS (they use mock containers and do not assert on stdout format).

- [ ] **Step 5: Commit**

```bash
git add cmd/secrets/list.go cmd/secrets/get.go
git commit -m "feat(cli/secrets): use --output formatter for list and get"
```

---

## Task 7: Update `cmd/secrets/create.go`

**Files:**
- Modify: `cmd/secrets/create.go`

- [ ] **Step 1: Update `cmd/secrets/create.go`**

After the successful `CreateSecret` call, replace the `logrus.WithFields(...).Info(...)` block with formatter output. The create command prints a single confirmation row.

Replace:
```go
logrus.WithFields(logrus.Fields{
    "user_id":   userID.String(),
    "secret_id": secret.ID.String(),
    "name":      name,
}).Info("Secret created successfully")
```

With:
```go
fmtr, ok := cmd.Context().Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    logrus.Error("Output formatter not available in context")
    os.Exit(1)
    return
}
headers := []string{"ID", "Name", "Version", "Enabled", "Created"}
row := []string{
    secret.ID.String(),
    secret.Name,
    strconv.Itoa(secret.Version),
    strconv.FormatBool(secret.Enabled),
    secret.CreatedAt.Format(time.RFC3339),
}
if err := fmtr.Write(os.Stdout, headers, [][]string{row}); err != nil {
    logrus.WithError(err).Error("Failed to write output")
    os.Exit(1)
}
```

Add imports: `"strconv"`, `"time"`, `"rocketvault/internal/formatter"`. Keep `"github.com/sirupsen/logrus"` and `"os"` (already present).

Note: `create.go` uses `Run` (not `RunE`) — keep as-is to avoid changing the error-handling style of a command not currently targeted for refactor.

- [ ] **Step 2: Build check**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/secrets/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add cmd/secrets/create.go
git commit -m "feat(cli/secrets): use --output formatter for create confirmation"
```

---

## Task 8: Update `cmd/keys/list.go`, `cmd/keys/get.go`, `cmd/keys/create.go`

**Files:**
- Modify: `cmd/keys/list.go`
- Modify: `cmd/keys/get.go`
- Modify: `cmd/keys/create.go`

- [ ] **Step 1: Update `cmd/keys/list.go`**

Replace the `fmt.Println("Keys:")` + `fmt.Printf` loop with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Name", "Type", "Revoked", "Tags", "Created"}
rows := make([][]string, len(keys))
for i, k := range keys {
    rows[i] = []string{
        k.ID.String(),
        k.Name,
        k.Type,
        strconv.FormatBool(k.Revoked),
        strings.Join(k.Tags, ","),
        k.CreatedAt.Format(time.RFC3339),
    }
}
return fmtr.Write(os.Stdout, headers, rows)
```

Add imports: `"os"`, `"strconv"`, `"rocketvault/internal/formatter"`. Keep `"fmt"`, `"strings"`, `"time"` (already present).

- [ ] **Step 2: Update `cmd/keys/get.go`**

Replace the `fmt.Printf("Key: ID=%s, ...")` line with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Name", "Type", "Revoked", "Tags", "Created"}
row := []string{
    key.ID.String(),
    key.Name,
    key.Type,
    strconv.FormatBool(key.Revoked),
    strings.Join(key.Tags, ","),
    key.CreatedAt.Format(time.RFC3339),
}
return fmtr.Write(os.Stdout, headers, [][]string{row})
```

Add imports: `"os"`, `"strconv"`, `"rocketvault/internal/formatter"`.

- [ ] **Step 3: Update `cmd/keys/create.go`**

Replace the `log.WithFields(logrus.Fields{...}).Info("Key created successfully")` block with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}
headers := []string{"ID", "Name", "Type", "Tags", "Created"}
row := []string{
    result.KeyID.String(),
    result.Name,
    result.Type,
    strings.Join(result.Tags, ","),
    result.CreatedAt.Format(time.RFC3339),
}
return fmtr.Write(os.Stdout, headers, [][]string{row})
```

Add imports: `"os"`, `"strconv"`, `"rocketvault/internal/formatter"`. Remove `"github.com/sirupsen/logrus"` if no longer used.

- [ ] **Step 4: Build and test**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/keys/... && go test ./cmd/keys/... -v
```

Expected: build succeeds, all existing tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/keys/list.go cmd/keys/get.go cmd/keys/create.go
git commit -m "feat(cli/keys): use --output formatter for list, get, and create"
```

---

## Task 9: Update `cmd/users/list.go` and `cmd/users/get.go`

**Files:**
- Modify: `cmd/users/list.go`
- Modify: `cmd/users/get.go`

- [ ] **Step 1: Update `cmd/users/list.go`**

Replace the `fmt.Println("Users:")` + `fmt.Printf` loop with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Username", "Role", "Created"}
rows := make([][]string, len(users))
for i, u := range users {
    rows[i] = []string{
        u.ID.String(),
        u.Username,
        u.Role,
        u.CreatedAt.Format(time.RFC3339),
    }
}
return fmtr.Write(os.Stdout, headers, rows)
```

Add imports: `"os"`, `"rocketvault/internal/formatter"`. Keep `"fmt"`, `"time"` (already present).

- [ ] **Step 2: Update `cmd/users/get.go`**

Replace the `fmt.Printf("User: ID=%s, ...")` line with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Username", "Role", "Created"}
row := []string{
    user.ID.String(),
    user.Username,
    user.Role,
    user.CreatedAt.Format(time.RFC3339),
}
return fmtr.Write(os.Stdout, headers, [][]string{row})
```

Add imports: `"os"`, `"rocketvault/internal/formatter"`.

- [ ] **Step 3: Build and test**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/users/... && go test ./cmd/users/... -v
```

Expected: build succeeds, all existing tests PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/users/list.go cmd/users/get.go
git commit -m "feat(cli/users): use --output formatter for list and get"
```

---

## Task 10: Update `cmd/certificates/list.go`, `cmd/certificates/get.go`, `cmd/certificates/create.go`

**Files:**
- Modify: `cmd/certificates/list.go`
- Modify: `cmd/certificates/get.go`
- Modify: `cmd/certificates/create.go`

- [ ] **Step 1: Update `cmd/certificates/list.go`**

Replace the `fmt.Println("Certificates:")` + `fmt.Printf` loop with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Name", "Tags", "Expires", "AutoRenew", "Created"}
rows := make([][]string, len(certs))
for i, c := range certs {
    rows[i] = []string{
        c.ID.String(),
        c.Name,
        strings.Join(c.Tags, ","),
        formatOptionalTime(c.ExpiresAt),
        strconv.FormatBool(c.AutoRenew),
        c.CreatedAt.Format(time.RFC3339),
    }
}
return fmtr.Write(os.Stdout, headers, rows)
```

Add a package-level helper at the bottom of the file:

```go
func formatOptionalTime(t *time.Time) string {
    if t == nil {
        return ""
    }
    return t.Format(time.RFC3339)
}
```

Add imports: `"os"`, `"strconv"`, `"rocketvault/internal/formatter"`. Keep `"fmt"`, `"strings"`, `"time"` (already present).

- [ ] **Step 2: Update `cmd/certificates/get.go`**

Replace the `fmt.Printf("Certificate: ...")` block with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}

headers := []string{"ID", "Name", "Tags", "Expires", "AutoRenew", "Created"}
row := []string{
    cert.ID.String(),
    cert.Name,
    strings.Join(cert.Tags, ","),
    formatOptionalTime(cert.ExpiresAt),
    strconv.FormatBool(cert.AutoRenew),
    cert.CreatedAt.Format(time.RFC3339),
}
return fmtr.Write(os.Stdout, headers, [][]string{row})
```

Add imports: `"os"`, `"strconv"`, `"rocketvault/internal/formatter"`. Remove the `"fmt"` direct print usage (keep `fmt` for `fmt.Errorf`).

Note: `formatOptionalTime` is defined in `list.go` in the same package — no need to redefine it.

- [ ] **Step 3: Update `cmd/certificates/create.go`**

Replace the `fmt.Printf("Certificate created successfully, ID: %s\n", result.CertID)` line with:

```go
fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
if !ok {
    return fmt.Errorf("output formatter not available in context")
}
headers := []string{"ID", "Name", "Created"}
row := []string{
    result.CertID.String(),
    result.Name,
    result.CreatedAt.Format(time.RFC3339),
}
return fmtr.Write(os.Stdout, headers, [][]string{row})
```

Add imports: `"os"`, `"rocketvault/internal/formatter"`.

- [ ] **Step 4: Build and test**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/certificates/... && go test ./cmd/certificates/... -v
```

Expected: build succeeds, all existing tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/certificates/list.go cmd/certificates/get.go cmd/certificates/create.go
git commit -m "feat(cli/certs): use --output formatter for list, get, and create"
```

---

## Task 11: Full build and regression verification

**Files:** none (verification only)

- [ ] **Step 1: Full build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./...
```

Expected: no errors.

- [ ] **Step 2: Full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... -v 2>&1 | tail -40
```

Expected: all tests PASS. Look specifically for any FAIL lines.

- [ ] **Step 3: Verify API layer untouched**

```bash
grep -r "internal/formatter" /home/numericlabs/data/rocket/rocketvault/api/
```

Expected: no output — the `api/` package must have zero imports of `internal/formatter`.

- [ ] **Step 4: Verify domain layer untouched**

```bash
grep -r "internal/formatter" /home/numericlabs/data/rocket/rocketvault/internal/domain/ \
  /home/numericlabs/data/rocket/rocketvault/internal/services/
```

Expected: no output.

- [ ] **Step 5: Final commit if any cleanup needed, otherwise tag complete**

```bash
git log --oneline -10
```

Review the commit trail. All formatter commits should be present cleanly.
