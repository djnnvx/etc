TARGET 		= mdb-ls
SRC 		= main.go

.PHONY: all
all: compile

.PHONY: help
help:
	@echo "\033[34m => targets:\033[0m"
	@perl -nle'print $& if m{^[a-zA-Z_-\d]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: compile
compile: ## compile the project
	@go build -o $(TARGET) $(SRC)

.PHONY: clean
clean: ## cleans up the project
	rm -f $(TARGET)

.PHONY: tidy
tidy: ## runs tidy and formatting
	@go mod tidy
	@gofmt -s -w .
