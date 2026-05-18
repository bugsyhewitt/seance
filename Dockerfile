FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /seance ./cmd/seance

FROM scratch
COPY --from=builder /seance /seance
COPY signatures/ /signatures/
ENTRYPOINT ["/seance"]
