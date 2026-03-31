FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /jurispath ./cmd/jurispath

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /jurispath /usr/local/bin/jurispath
COPY policies/ /etc/jurispath/policies/
COPY dashboard/ /opt/jurispath/dashboard/
ENV JURISPATH_POLICY_DIR=/etc/jurispath/policies
ENV JURISPATH_DASHBOARD_DIR=/opt/jurispath/dashboard
EXPOSE 8080
ENTRYPOINT ["jurispath"]
