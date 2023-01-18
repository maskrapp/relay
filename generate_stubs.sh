#!/bin/bash
mkdir -p internal/pb
protoc --go_out=./internal/pb/ --go-grpc_out=./internal/pb protobuf/backend/v1/*.proto
