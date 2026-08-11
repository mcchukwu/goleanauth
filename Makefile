APP_NAME := goleanauth
CMD_PATH := ./cmd
BIN_PATH := bin

.PHONY: run build clean test migrate-up migrate-down migrate-status create-client

run: 
	go run $(CMD_PATH)

build:
	go build -o $(BIN_PATH)/$(APP_NAME) $(CMD_PATH)

clean:
	rm -rf $(BIN_PATH)

test:
	go test ./...

migrate-up:
	go run ./cmd/migrate up

migrate-down:
	go run ./cmd/migrate down 1

migrate-status:
	go run ./cmd/migrate status

create-client:
	go run ./cmd/create-client
	