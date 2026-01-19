.PHONY: build clean

run-server:
	go run cmd/api/*.go

run-docker:
	docker-compose up --build

test:
	go test ./...
