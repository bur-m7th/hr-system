FROM golang:1.24-bullseye AS builder

WORKDIR /app

ENV CGO_ENABLED=1
ENV GOOS=linux

# Install build dependencies
RUN apt-get update && \
    apt-get install -y gcc libc6-dev sqlite3 libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build binary
RUN go build -o hr-app

# Add this line: Specify the command to run the binary
CMD ["./hr-app"]