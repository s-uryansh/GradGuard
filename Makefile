.PHONY: install build run clean generate

install:
	docker build -t honeypot-base -f Dockerfile.base .
	docker network create --driver bridge --subnet=172.19.0.0/16 gradguard-net || true

generate:
	go generate ./internal/monitor

build: generate
	go build -o gradguard cmd/honeypot/main.go

run: build
	sudo ./gradguard

clean:
	rm -f gradguard
	docker network rm gradguard-net || true