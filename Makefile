build:
	@go build -o bin/go-auth cmd/main.go

run: build
	@./bin/go-auth

watch:
	@reflex -r '\.go$$' -s -- make run

test:
	@go test -v ./...

migration:
	@migrate create -ext sql -dir cmd/migrate/migrations $(filter-out $@,$(MAKECMDGOALS))

migrate-up:
	@go run cmd/migrate/migrate.go up

migrate-down:
	@go run cmd/migrate/migrate.go down
