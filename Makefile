.PHONY: install build run clean

install:
	@echo "Building Honeypot Base Image..."
	docker build -t honeypot-base .
	@echo "Creating Isolated Network..."
	docker network create --driver bridge --subnet=172.19.0.0/16 gradguard-net || true

build:
	go build -o gradguard cmd/honeypot/main.go

run: build
	sudo ./gradguard

clean:
	rm -f gradguard
	docker network rm gradguard-net || true