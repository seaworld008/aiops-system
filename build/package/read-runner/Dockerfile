# syntax=docker/dockerfile:1.7

ARG GO_BUILD_IMAGE=docker.io/library/golang:1.26.5-bookworm
FROM --platform=$BUILDPLATFORM ${GO_BUILD_IMAGE} AS build

ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    install -d -m 0755 /out && \
    test "${TARGETOS}" = "linux" && \
    test -n "${TARGETARCH}" && \
    test "$(go env GOVERSION)" = "go1.26.5" && \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -buildvcs=false -ldflags="-s -w" \
      -o /out/aiops-read-runner ./cmd/read-runner

FROM scratch

COPY --from=build --chmod=0555 /out/aiops-read-runner /usr/local/bin/aiops-read-runner

USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/aiops-read-runner"]
