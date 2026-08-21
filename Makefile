GO_IMAGE ?= golang:1.27
GO_MIN_IMAGE ?= golang:1.18

.PHONY: fmt-check vet test check docker-check docker-check-min

fmt-check:
	test -z "$$(find . -name '*.go' -type f -not -path './vendor/*' -print0 | xargs -0 gofmt -l)"

vet:
	go vet ./...

test:
	LIBDNS_SPACESHIP_RUN_LIVE=0 go test ./...

check: fmt-check vet test

docker-check:
	docker run --rm -v "$$(pwd):/src" -w /src $(GO_IMAGE) sh -c 'LIBDNS_SPACESHIP_RUN_LIVE=0 go test ./... && go vet ./... && test -z "$$(find . -name "*.go" -type f -not -path "./vendor/*" -print0 | xargs -0 gofmt -l)"'

docker-check-min:
	docker run --rm -v "$$(pwd):/src" -w /src $(GO_MIN_IMAGE) sh -c 'LIBDNS_SPACESHIP_RUN_LIVE=0 go test ./... && go vet ./... && test -z "$$(find . -name "*.go" -type f -not -path "./vendor/*" -print0 | xargs -0 gofmt -l)"'
