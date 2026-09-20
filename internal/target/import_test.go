package target

import (
	"strings"
	"testing"
)

func TestParseImportSkipsBlanksAndMarksPhysicalLines(t *testing.T) {
	password := strings.Repeat("x", 8)
	content := "identifier,display_label,password,totp_secret,recovery_secret,platform_subject_id\n\nuser@example.com,User," + password + ",,,subject-1\n# comment,,,,,\n"
	rows, err := ParseImport(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Line != 3 || rows[0].Identifier != "user@example.com" || rows[0].Password != password {
		t.Fatalf("unexpected rows: %#v", rows)
	}
}

func TestParseImportRejectsDuplicateIdentifiersBeforePersistence(t *testing.T) {
	password := strings.Repeat("x", 8)
	content := "identifier,display_label,password,totp_secret,recovery_secret,platform_subject_id\nuser@example.com,One," + password + ",,,,\nUSER@example.com,Two," + password + ",,,,\n"
	_, err := ParseImport(content)
	if err == nil {
		t.Fatal("expected duplicate identifier error")
	}
}
