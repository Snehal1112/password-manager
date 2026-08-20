package backup

// Test-only aliases. This file is compiled only under `go test`, so these
// export nothing to production consumers.

type ExportedBlobVersions = blobVersions

var (
	ExportedEncodeBlob = encodeBlob
	ExportedDecodeBlob = decodeBlob
)
