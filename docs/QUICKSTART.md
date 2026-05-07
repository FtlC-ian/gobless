# GoBless — Local Development Quickstart

## Prerequisites

- Go 1.22+
- `make`
- Git

## Setup

```bash
git clone https://github.com/your-org/gobless.git
cd gobless
```

Replace `your-org` with the GitHub owner for your fork or release repository.

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
make deps         # Print module dependency graph
```

## First Test Pass

After cloning, `make ci` should pass cleanly with zero errors. If it doesn't, check your Go version (`go version` — must be 1.22+) and that dependencies are fetched (`go mod download`).
