#!/bin/bash

sudo env "PATH=$PATH" "GOPATH=$GOPATH" go run main.go -p wlan0 -c eth0