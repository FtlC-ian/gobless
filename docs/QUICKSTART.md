# GoBless — Local Development Quickstart

## Prerequisites

- Go version matching `go.mod` (currently Go 1.25+)
- `make`
- Git

## Setup

```bash
git clone https://github.com/FtlC-ian/gobless.git
cd gobless
```

## Run CI Checks Locally

```bash
make ci
```

This runs `go vet ./...`, `go test ./...`, and `go test -race ./...` in sequence. All must pass before pushing.

## Individual Targets

```bash
make vet          # Static analysis
make test         # Unit tests
make test-race    # Race detector
make build        # Compile all packages
make deps         # Verify modules and go.mod/go.sum tidiness
```

## First Test Pass

After cloning, `make ci` should pass cleanly with zero errors. If it doesn't, check your Go version (`go version` — must match `go.mod`, currently 1.25+) and that dependencies are fetched (`go mod download`).
