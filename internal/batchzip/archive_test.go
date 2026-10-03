package batchzip

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"io"
	"strings"
	"testing"
	"time"
)

func account(now time.Time, index int) Account {
	identifier := fmt.Sprintf("child%d@example.test", index)
	claims, _ := json.Marshal(map[string]any{"exp": now.Add(time.Hour).Unix(), "email": identifier, "scope": platform.CodexScope, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "platform-space", "chatgpt_user_id": "subject", "chatgpt_plan_type": "team", "organizations": []any{map[string]any{"id": "org"}}}})
	token := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".mock"
	return Account{Identifier: identifier, Password: "password", TOTP: "JBSWY3DPEHPK3PXP", Subject: "subject", IssuedAt: now, FirstOK: now, ExpiresAt: now.Add(time.Hour), OAuth: platform.DeliveryCredentialSet{AccessToken: token, RefreshToken: "refresh", IDToken: token, WorkspaceID: "platform-space", PlatformSubjectID: "subject", ExpiresIn: 3600, Scope: platform.CodexScope}}
}
func files(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	out := map[string][]byte{}
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		out[f.Name], e = io.ReadAll(r)
		_ = r.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	return out
}
func TestArchiveExactWholeBatchAndTechnicalPartitions(t *testing.T) {
	now := time.Date(2026, 10, 3, 9, 8, 7, 0, time.UTC)
	for _, n := range []int{1, 100, 101, 201} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			accounts := make([]Account, n)
			for i := range accounts {
				accounts[i] = account(now, i+1)
			}
			data, e := Build(now, "platform-space", accounts)
			if e != nil {
				t.Fatal(e)
			}
			fs := files(t, data)
			expected := 2
			if n > 100 {
				expected += (n + 99) / 100
			}
			if len(fs) != expected {
				t.Fatal(len(fs), expected)
			}
			if len(strings.Split(strings.TrimSpace(string(fs["account-materials.txt"])), "\n")) != n {
				t.Fatal("materials subset")
			}
			var bundle struct {
				Accounts   []map[string]any `json:"accounts"`
				Proxies    []any            `json:"proxies"`
				ExportedAt string           `json:"exported_at"`
			}
			if e = json.Unmarshal(fs["sub2api_all.json"], &bundle); e != nil || len(bundle.Accounts) != n || bundle.ExportedAt != "2026-10-03T09:08:07Z" || bundle.Proxies == nil {
				t.Fatal(bundle, e)
			}
			for i, entry := range bundle.Accounts {
				credentials := entry["credentials"].(map[string]any)
				if credentials["email"] != accounts[i].Identifier || credentials["chatgpt_account_id"] != "platform-space" || credentials["client_id"] != "app_EMoamEEZ73f0CkXaXp7hrann" || entry["type"] != "oauth" || entry["platform"] != "openai" || len(credentials["model_mapping"].(map[string]any)) != 0 {
					t.Fatal("reference account mapping changed", i)
				}
			}
			if n > 100 {
				for start := 0; start < n; start += 100 {
					end := min(start+100, n)
					path := fmt.Sprintf("split/sub2api_%03d_%03d.json", start+1, end)
					if e = json.Unmarshal(fs[path], &bundle); e != nil || len(bundle.Accounts) != end-start {
						t.Fatal(path, e)
					}
				}
			}
			if Filename(now.In(time.FixedZone("zone", 8*3600))) != "Apophis-TeamSeatWatch-2026-10-03-09-08-07.zip" {
				t.Fatal("not UTC")
			}
		})
	}
}
func TestArchiveRejectsEveryInvalidObjectWithoutPartialBytes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, mode := range []string{"password", "totp_missing", "totp_invalid", "line_injection", "scope", "workspace", "expired", "refresh", "id", "subject", "plan", "email", "duplicates"} {
		t.Run(mode, func(t *testing.T) {
			a := account(now, 1)
			switch mode {
			case "password":
				a.Password = ""
			case "totp_missing":
				a.TOTP = ""
			case "totp_invalid":
				a.TOTP = "bad!"
			case "line_injection":
				a.Password = "pw\nother"
			case "scope":
				a.OAuth.Scope = "personal"
			case "workspace":
				a.OAuth.WorkspaceID = "another"
			case "expired":
				a.ExpiresAt = now
			case "refresh":
				a.OAuth.RefreshToken = ""
			case "id":
				a.OAuth.IDToken = "invalid"
			case "subject":
				a.Subject = "other"
			case "plan", "email":
				raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(a.OAuth.IDToken, ".")[1])
				var c map[string]any
				_ = json.Unmarshal(raw, &c)
				if mode == "plan" {
					c["https://api.openai.com/auth"].(map[string]any)["chatgpt_plan_type"] = "free"
				} else {
					c["email"] = "different@example.test"
				}
				raw, _ = json.Marshal(c)
				a.OAuth.IDToken = "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".mock"
			}
			items := []Account{account(now, 0), a}
			if mode == "duplicates" {
				items[1] = items[0]
			}
			data, e := Build(now, "platform-space", items)
			if e == nil || data != nil {
				t.Fatal("partial/unqualified archive", mode, e)
			}
		})
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("injected archive failure") }
func TestArchiveWriteFailureIsReturned(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if e := Write(brokenWriter{}, now, "platform-space", []Account{account(now, 1)}); e == nil {
		t.Fatal("archive failure hidden")
	}
}
func TestArchiveRejectsMoreThan999SpaceMembers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	values := make([]Account, 1000)
	for i := range values {
		values[i] = account(now, i)
	}
	if data, e := Build(now, "platform-space", values); e == nil || data != nil {
		t.Fatal("space limit exceeded")
	}
}
