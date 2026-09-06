package vaultcli

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/formatter"
)

type renderable struct {
	ID      uuid.UUID
	Name    string
	Version int
	Enabled bool
	Tags    []string
	Expires *time.Time
	Created time.Time
}

func renderableCols() []Column[renderable] {
	return []Column[renderable]{
		Col("ID", func(r renderable) string { return CellUUID(r.ID) }),
		Col("Name", func(r renderable) string { return r.Name }),
		Col("Version", func(r renderable) string { return CellInt(r.Version) }),
		Col("Enabled", func(r renderable) string { return CellBool(r.Enabled) }),
		Col("Tags", func(r renderable) string { return CellCSV(r.Tags) }),
		Col("Expires", func(r renderable) string { return CellOptTime(r.Expires) }),
		Col("Created", func(r renderable) string { return CellTime(r.Created) }),
	}
}

func TestRender_SingleItem(t *testing.T) {
	t.Parallel()

	f, err := formatter.New(formatter.FormatJSON)
	require.NoError(t, err)

	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	item := renderable{
		ID: uuid.New(), Name: "db-password", Version: 3, Enabled: true,
		Tags: []string{"prod", "db"}, Created: created,
	}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, f, renderableCols(), item))

	out := buf.String()
	assert.Contains(t, out, "db-password")
	assert.Contains(t, out, `"Version": "3"`)
	assert.Contains(t, out, `"Enabled": "true"`)
	assert.Contains(t, out, `"Tags": "prod,db"`)
	assert.Contains(t, out, "2026-09-06T12:00:00Z")
	// A nil *time.Time renders as empty, not as a zero time.
	assert.Contains(t, out, `"Expires": ""`)
	assert.NotContains(t, out, "0001-01-01")
}

func TestRender_ManyItems_ShareOneColumnSet(t *testing.T) {
	t.Parallel()

	f, err := formatter.New(formatter.FormatTable)
	require.NoError(t, err)

	items := []renderable{
		{ID: uuid.New(), Name: "first", Created: time.Now()},
		{ID: uuid.New(), Name: "second", Created: time.Now()},
	}

	var buf bytes.Buffer
	require.NoError(t, Render(&buf, f, renderableCols(), items...))

	out := buf.String()
	assert.Contains(t, out, "first")
	assert.Contains(t, out, "second")
	// The header row appears exactly once regardless of item count.
	assert.Equal(t, 1, bytes.Count([]byte(out), []byte("Version")))
}

func TestRender_NoItems_StillWritesHeaders(t *testing.T) {
	t.Parallel()

	f, err := formatter.New(formatter.FormatTable)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, Render[renderable](&buf, f, renderableCols()))

	assert.Contains(t, buf.String(), "Name")
}

// Header order is the column order, and each cell lands under its own header.
func TestRender_CellsAlignWithHeaders(t *testing.T) {
	t.Parallel()

	var gotHeaders []string
	var gotRows [][]string
	f := captureFormatter{headers: &gotHeaders, rows: &gotRows}

	item := renderable{ID: uuid.New(), Name: "n", Version: 7}
	require.NoError(t, Render(&bytes.Buffer{}, f, renderableCols(), item))

	require.Len(t, gotRows, 1)
	require.Equal(t, len(gotHeaders), len(gotRows[0]))
	assert.Equal(t, []string{"ID", "Name", "Version", "Enabled", "Tags", "Expires", "Created"}, gotHeaders)
	assert.Equal(t, "n", gotRows[0][1])
	assert.Equal(t, "7", gotRows[0][2])
}

type captureFormatter struct {
	headers *[]string
	rows    *[][]string
}

func (c captureFormatter) Write(_ io.Writer, headers []string, rows [][]string) error {
	*c.headers = headers
	*c.rows = rows
	return nil
}
