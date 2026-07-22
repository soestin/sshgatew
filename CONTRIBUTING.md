# Contributing to SSHGateW

Thank you for helping improve SSHGateW. Open an issue before large behavioral
changes so authentication and compatibility implications can be discussed.

## Development

SSHGateW requires Go 1.26 or newer.

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
```

Keep changes focused, add tests for new behavior, and update the operator and
security documentation when appropriate. Never commit real private keys,
passwords, TOTP seeds, production databases, or unsanitized logs.

By contributing, you agree that your contribution is licensed under the MIT
License.
