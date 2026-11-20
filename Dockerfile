# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/gingered-cat/asiri/internal/server.Version=${VERSION}" \
      -o /out/asiri ./cmd/asiri \
 && mkdir -m 0700 /out/data

# Static, no shell, runs as uid 65532.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/asiri /usr/local/bin/asiri
COPY --from=build --chown=65532:65532 /out/data /data
ENV ASIRI_DATA=/data \
    ASIRI_LISTEN=0.0.0.0:7420 \
    ASIRI_SAN=asiri
VOLUME /data
EXPOSE 7420
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/usr/local/bin/asiri", "server", "health"]
ENTRYPOINT ["/usr/local/bin/asiri"]
CMD ["server", "run"]
