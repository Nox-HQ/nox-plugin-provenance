FROM golang:latest

RUN apt-get install -y curl wget
RUN curl -sSL https://example.com/setup.sh | bash

COPY . /app
WORKDIR /app

RUN go build -o myapp .
