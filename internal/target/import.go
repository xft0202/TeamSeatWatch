package target

import (
	"errors"
	"strconv"
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

// ParseImport accepts one account per line in the operator's own format:
//
//	email----password----2fa
//
// Later fields are optional; extra fields are ignored. Blank rows and rows
// starting with # are skipped. A malformed row fails the whole import so the
// owner never ends up with a half-imported list.
func ParseImport(content string) ([]ImportRow, error) {
	rows := make([]ImportRow, 0)
	seen := make(map[string]struct{})
	physicalLine := 0
	for _, rawLine := range strings.Split(content, "\n") {
		physicalLine++
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "----")
		if len(parts) < 3 {
			return nil, errors.New("line " + strconv.Itoa(physicalLine) + ": expected email----password----2fa")
		}
		identifier := strings.ToLower(strings.TrimSpace(parts[0]))
		password := strings.TrimSpace(parts[1])
		totp := strings.TrimSpace(parts[2])
		if identifier == "" || password == "" {
			return nil, errors.New("line " + strconv.Itoa(physicalLine) + ": email and password are required")
		}
		if _, exists := seen[identifier]; exists {
			return nil, errors.New("line " + strconv.Itoa(physicalLine) + ": duplicate account in import")
		}
		seen[identifier] = struct{}{}

		label := identifier
		recovery, subject := "", ""
		if len(parts) > 3 {
			label = defaultString(strings.TrimSpace(parts[3]), identifier)
		}
		if len(parts) > 4 {
			recovery = strings.TrimSpace(parts[4])
		}
		if len(parts) > 5 {
			subject = strings.TrimSpace(parts[5])
		}
		rows = append(rows, ImportRow{
			Line: physicalLine, Identifier: identifier, DisplayLabel: label, Password: password,
			TOTPSecret: totp, RecoverySecret: recovery, PlatformSubjectID: subject,
		})
		if len(rows) > maxImportRows {
			return nil, errors.New("import exceeds 10000 rows")
		}
	}
	if len(rows) == 0 {
		return nil, errors.New("no target accounts found in import")
	}
	return rows, nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
