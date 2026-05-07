.PHONY: build test test-race vet lint deps ci e2e

build:
	go build ./...

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint:
	go vet ./...

deps:
	go mod verify
	go mod tidy
	git diff --exit-code go.mod go.sum || (echo "go.mod or go.sum changed after go mod tidy — commit the diff" && exit 1)

ci: vet test test-race

e2e:
	GOTOOLCHAIN=local go test -v -tags e2e ./test/e2e/
