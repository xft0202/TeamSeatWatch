// Package batchzip builds the immutable same-object Team OAuth customer archive.
package batchzip

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/thirtydayoauth"
)

var ErrIncomplete = errors.New("batch delivery materials incomplete")

type Account struct {
	Identifier, Password, TOTP, Subject string
	OAuth                               platform.DeliveryCredentialSet
	IssuedAt, FirstOK                   time.Time
	ExpiresAt                           time.Time
}

// Build writes all accounts or returns no bytes. Qualification and source
// binding are checked by the caller in its transaction; credentials and text
// are independently checked here before any archive entry is created.
func Build(now time.Time, workspace string, accounts []Account) ([]byte, error) {
	var b bytes.Buffer
	if err := Write(&b, now, workspace, accounts); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func Filename(now time.Time) string {
	return "Apophis-TeamSeatWatch-" + now.UTC().Format("2006-01-02-15-04-05") + ".zip"
}

// Write allows archive failures to be tested at the same production boundary.
func Write(dst io.Writer, now time.Time, workspace string, accounts []Account) error {
	if workspace == "" || len(accounts) == 0 || len(accounts) > 999 {
		return ErrIncomplete
	}
	entries := make([]map[string]any, 0, len(accounts))
	seen := map[string]bool{}
	var materials strings.Builder
	for _, a := range accounts {
		if a.Identifier == "" || a.Password == "" || seen[a.Identifier] || !target.CompleteTOTP(a.TOTP) {
			return ErrIncomplete
		}
		for _, value := range []string{a.Identifier, a.Password, a.TOTP} {
			if strings.ContainsAny(value, "\r\n\x00") || strings.Contains(value, "----") {
				return ErrIncomplete
			}
		}
		seen[a.Identifier] = true
		expiry, err := platform.ValidateRotationCandidateOAuth(a.OAuth, workspace, a.Subject, a.IssuedAt)
		if err != nil || !expiry.UTC().Truncate(time.Microsecond).Equal(a.ExpiresAt) || !expiry.After(now.Add(time.Minute)) {
			return ErrIncomplete
		}
		claims := thirtydayoauth.DecodeIDToken(a.OAuth.IDToken)
		if claims.AccountID != workspace || claims.UserID != a.Subject || claims.PlanType != "team" && claims.PlanType != "business" || claims.Email != "" && !strings.EqualFold(claims.Email, a.Identifier) {
			return ErrIncomplete
		}
		entry, err := thirtydayoauth.BuildSub2APIAt(now, thirtydayoauth.BuildInput{Email: a.Identifier, WorkspaceID: workspace, RefreshToken: a.OAuth.RefreshToken, AccessToken: a.OAuth.AccessToken, IDToken: a.OAuth.IDToken, ExpiresIn: a.OAuth.ExpiresIn, ExpiresAt: a.ExpiresAt.Unix(), IssuedAt: a.IssuedAt, FirstOK: a.FirstOK, EmptyModelMapping: true})
		if err != nil {
			return ErrIncomplete
		}
		entries = append(entries, entry)
		materials.WriteString(a.Identifier + "----" + a.Password + "----" + a.TOTP + "\n")
	}
	// Batch envelope and 100-account technical partition are sourced from the
	// reference Team exporter. Product filenames/omission of IDs are intentional.
	exported := now.UTC().Truncate(time.Second).Format(time.RFC3339)
	bundle := func(items []map[string]any) ([]byte, error) {
		return json.MarshalIndent(struct {
			ExportedAt string           `json:"exported_at"`
			Proxies    []any            `json:"proxies"`
			Accounts   []map[string]any `json:"accounts"`
		}{exported, []any{}, items}, "", "  ")
	}
	zw := zip.NewWriter(dst)
	write := func(name string, data []byte) error {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetModTime(now.UTC().Truncate(time.Second))
		w, e := zw.CreateHeader(header)
		if e != nil {
			return e
		}
		_, e = w.Write(data)
		return e
	}
	if err := write("account-materials.txt", []byte(materials.String())); err != nil {
		return err
	}
	data, err := bundle(entries)
	if err != nil {
		return err
	}
	if err = write("sub2api_all.json", append(data, '\n')); err != nil {
		return err
	}
	if len(entries) > 100 {
		for start := 0; start < len(entries); start += 100 {
			end := min(start+100, len(entries))
			data, err = bundle(entries[start:end])
			if err != nil {
				return err
			}
			if err = write(fmt.Sprintf("split/sub2api_%03d_%03d.json", start+1, end), append(data, '\n')); err != nil {
				return err
			}
		}
	}
	return zw.Close()
}
