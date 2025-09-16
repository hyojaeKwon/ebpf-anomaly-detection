FROM golang:1.24 AS go-build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o /out/app ./main.go

# --------
FROM alpine:3.13
WORKDIR /app
RUN adduser -D -u 10001 adduser
COPY --from=go-build /out/app /app/app
COPY ingress_filter.o /app/bpf/ingress_filter.o
USER appuser
ENTRYPOINT ["/app/app"]