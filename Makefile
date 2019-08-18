PROJECT_NAME := "vault-plugin-xrp"

VERSION := $(shell cat ./VERSION)

PKG := "github.com/ChainFront/$(PROJECT_NAME)"

.PHONY: all dep build clean test coverage lint

all: build

lint: ## Lint the files
	@golint -set_exit_status ./...

test: ## Run unit tests
	@go test  ./...

race: dep ## Run data race detector
	@go test -race -short ./...

msan: dep ## Run memory sanitizer (requires clang on the host)
	CC=clang go test -msan -short ./...

coverage: dep ## Generate code coverage report
	@go test -coverprofile="coverage.out" ./...
	@go tool cover -html="coverage.out"

dep: ## Get the dependencies
	@go get -v -d ./...

build: dep ## Build the binary file
	@go build -i -v $(PKG)

clean: ## Remove previous build
	@rm -f $(PROJECT_NAME) coverage.out

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
