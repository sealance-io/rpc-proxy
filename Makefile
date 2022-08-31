.PHONY: build docker run install test

build:
	go build

run: build
	./rpc-proxy --config config.toml

docker:
	docker build -t gochain/rpc-proxy .

run-docker: docker
	docker run --rm -it -p 8545:8545 -v ${PWD}/config.toml:/proxy.toml gochain/rpc-proxy --port 8545 --rpm 1000 --config /proxy.toml

install:
	go install

test:
	go test ./...
