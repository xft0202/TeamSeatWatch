package target

import (
	"encoding/csv"
	"errors"
	"io"
	"strings"
)

const maxImportRows = 10000

type ImportRow struct {
	Line              int
	Identifier        string
	DisplayLabel      string
	Password          string
	TOTPSecret        string
	RecoverySecret    string
	PlatformSubjectID string
	Existing          bool
}

// ParseImport accepts one explicit CSV shape. Like the reference line import,
// it skips blank/comment rows, reports the physical line, and fails atomically.
func ParseImport(content string) ([]ImportRow, error) {
	reader := csv.NewReader(strings.NewReader(content))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, errors.New("CSV header is required")
	}
	expected := []string{"identifier", "display_label", "password", "totp_secret", "recovery_secret", "platform_subject_id"}
	if len(header) != len(expected) {
		return nil, errors.New("CSV header is invalid")
	}
	for i := range expected {
		if strings.TrimSpace(strings.ToLower(header[i])) != expected[i] {
			return nil, errors.New("CSV header is invalid")
		}
	}
	rows := make([]ImportRow, 0)
	seen := make(map[string]struct{})
	for {
		fields, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || len(fields) != len(expected) {
			return nil, errors.New("CSV row is invalid")
		}
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if fields[0] == "" || strings.HasPrefix(fields[0], "#") {
			continue
		}
		physicalLine, _ := reader.FieldPos(0)
		identifier := strings.ToLower(fields[0])
		if identifier == "" || fields[2] == "" {
			return nil, errors.New("identifier and password are required")
		}
		if _, exists := seen[identifier]; exists {
			return nil, errors.New("duplicate identifier in import")
		}
		seen[identifier] = struct{}{}
		label := fields[1]
		if label == "" {
			label = identifier
		}
		rows = append(rows, ImportRow{
			Line: physicalLine, Identifier: identifier, DisplayLabel: label, Password: fields[2],
			TOTPSecret: fields[3], RecoverySecret: fields[4], PlatformSubjectID: fields[5],
		})
		if len(rows) > maxImportRows {
			return nil, errors.New("import exceeds 10000 rows")
		}
	}
	if len(rows) == 0 {
		return nil, errors.New("CSV contains no target accounts")
	}
	return rows, nil
}
