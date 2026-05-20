FROM golang:1.26-alpine AS builder
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /seance ./cmd/seance

FROM scratch
# CA certs required for TLS to api.github.com from the scratch image.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /seance /seance
COPY signatures/ /signatures/
ENTRYPOINT ["/seance"]
