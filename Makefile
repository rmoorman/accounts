.PHONY: default build release clean proto test patch

default: build

build: clean
	script/build

cross: clean
	script/build cross

docker: clean
	script/build docker

release: clean vet
	script/build docker
	script/release

fmt:
	goimports -w src

proto:
	script/proto

vet:
	go vet ./src/...

test:
	script/test

clean:
	rm -rf bin

patch:
	script/patch

start:
	script/first-start

restart:
	script/restart
