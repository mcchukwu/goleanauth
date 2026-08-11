APP_NAME := goleanauth
CMD_PATH := ./cmd
BIN_PATH := bin

.PHONY: run build clean test test-integration migrate-up migrate-down migrate-status create-client

run: 
	go run $(CMD_PATH)

build:
	go build -o $(BIN_PATH)/$(APP_NAME) $(CMD_PATH)

clean:
	rm -rf $(BIN_PATH)

test:
	go test ./...

TEST_DB_PORT := $(shell grep -E '^DB_PORT=' .env | cut -d= -f2-)
TEST_DB_USER := $(shell grep -E '^DB_USER=' .env | cut -d= -f2-)
TEST_DB_PASSWORD := $(shell grep -E '^DB_PASSWORD=' .env | cut -d= -f2-)
TEST_DB_NAME := $(shell grep -E '^TEST_DB_NAME=' .env | cut -d= -f2-)
ifeq ($(TEST_DB_NAME),)
TEST_DB_NAME := goleanauth_test
endif

test-integration:
	./scripts/setup_test_db.sh
	TEST_DB_URL="postgres://$(TEST_DB_USER):$(TEST_DB_PASSWORD)@localhost:$(TEST_DB_PORT)/$(TEST_DB_NAME)?sslmode=disable" \
		go test -tags integration -count=1 -v ./internal/integration/

migrate-up:
	go run ./cmd/migrate up

migrate-down:
	go run ./cmd/migrate down 1

migrate-status:
	go run ./cmd/migrate status

create-client:
	go run ./cmd/create-client
	