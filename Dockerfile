FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/certflow ./cmd/certflow

FROM alpine:3.22

WORKDIR /app
RUN adduser -D -H certflow
COPY --from=build /out/certflow /app/certflow
COPY web/static /app/web/static
COPY fixtures /app/fixtures
USER certflow

ENV CERTFLOW_DB=/tmp/certflow.db
ENV CERTFLOW_OTEL_STDOUT=false
ENV PORT=8080
EXPOSE 8080

CMD ["/bin/sh", "-c", "/app/certflow seed --db ${CERTFLOW_DB} >/dev/null 2>&1 || true; /app/certflow serve --db ${CERTFLOW_DB} --addr 0.0.0.0:${PORT}"]
