.PHONY: build test test-race vet lint deps ci e2e docs-check

build:
	GOTOOLCHAIN=local go build -tags production ./...

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

fuzz:
	GOTOOLCHAIN=local go test -fuzz=FuzzPolicyEvaluate -fuzztime=10s ./internal/policy/
	GOTOOLCHAIN=local go test -fuzz=FuzzCertSign        -fuzztime=10s ./internal/cert/
	GOTOOLCHAIN=local go test -fuzz=FuzzConfigLoad      -fuzztime=10s ./internal/config/
	GOTOOLCHAIN=local go test -fuzz=FuzzRedact          -fuzztime=10s ./internal/log/

docs-check:
	bash scripts/check-docs.sh
