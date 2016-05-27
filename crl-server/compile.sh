#!/bin/sh

mkdir -p ./binaries/linux/
GOOS=linux GOARCH=amd64 go build --ldflags '-extldflags "-static"' -o ./binaries/linux/crl-server ./main.go
