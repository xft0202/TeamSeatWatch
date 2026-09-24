# V1 Verification Report

Date: 2026-09-24
Commit under test: `0169c9a`

## Passed

- Fixed Go preflight: Go `1.27.1`.
- OpenAPI generation clean check.
- `go test -count=1 ./...`.
- `go test -p=1 -tags=integration -count=1 ./...` against PostgreSQL 17 at `127.0.0.1:55436`.
- Docker `go test -race ./cmd/... ./internal/...`.
- `go vet ./...`.
- Staticcheck with the repository's generated-code exception.
- `govulncheck ./...`: no vulnerabilities in called code; three vulnerabilities exist only in required-but-not-called modules and remain a release review item.
- Linux amd64 OCI build and config-missing migration smoke.
- Runtime dependency license policy and approved build exception.
- Frontend peer check, ESLint, TypeScript typecheck, Owner/Public production builds.

## Not Executed

These gates require credentials, external participants, or deployment infrastructure and therefore are not represented as passed:

- Playwright multi-viewport route and accessibility run. No Playwright suite is present in this checkout.
- Five-person first-use usability walk-through.
- Controlled live platform smoke for account, Workspace, member mutation, OAuth, and approved proxy endpoints.
- 10,000-account/1,000-target capacity envelope.
- Encrypted PostgreSQL backup/restore drill, RPO/RTO evidence, and post-restore cleanup/opening procedure.
- Production observability, mTLS gateway deployment, SBOM publication, and OCI deployment smoke against a deployed environment.

## Release Decision

`V1 release blocked`. Automated repository gates pass, but the unexecuted live, usability, capacity, backup/recovery, and deployment gates are release prerequisites and need owner-controlled evidence before the ticket can be marked publishable.
