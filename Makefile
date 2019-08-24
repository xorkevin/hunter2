.PHONY: test coverage cover bench fmt vet prepare

TEST_ARGS=
COVERAGE=cover.out
COVERAGE_ARGS=-covermode count -coverprofile $(COVERAGE)

test:
	go test $(TEST_ARGS) -cover $(COVERAGE_ARGS) ./...

coverage:
	go tool cover -html $(COVERAGE)

cover: test coverage

BENCHMARK_ARGS=-benchtime 5s -benchmem

bench:
	go test -bench . $(BENCHMARK_ARGS)

fmt:
	go fmt ./...

vet:
	go vet ./...

prepare: fmt vet
