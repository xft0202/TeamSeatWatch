FROM node@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553 AS web-builder
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
COPY web/tools/openapi/package.json ./tools/openapi/package.json
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM golang@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/teamseatwatch ./cmd/teamseatwatch

FROM scratch
COPY --from=go-builder /out/teamseatwatch /teamseatwatch
COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=web-builder /src/web/dist/owner /app/owner
COPY --from=web-builder /src/web/dist/public /app/public
ENTRYPOINT ["/teamseatwatch"]
