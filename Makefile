.PHONY: build test lint clean tidy

BINARY := seance
CMD     := ./cmd/seance

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
	go clean ./...
