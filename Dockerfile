FROM golang:1.18 as build-stage
RUN apt-get update
WORKDIR /build
COPY ./ /build/
RUN go mod download
RUN go build -o main
FROM ubuntu:22.04 as final-stage
WORKDIR /app
RUN apt-get update && \
    apt-get install -y \
    ca-certificates && \
    apt-get autoremove -y && \
    apt-get clean -y && \
    rm -rf /var/cache/apt/archives /var/lib/apt/lists/*
COPY --from=build-stage ./build/ .
CMD ["./main"] 