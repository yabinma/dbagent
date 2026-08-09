# probe — Go static binary (data plane, no listening port).
# Runtime ARGs must be declared before the first FROM so --build-arg reaches them
# (Docker scopes post-FROM ARGs to that stage only).
ARG GO_IMAGE=golang:1.26.4
ARG GO_RUNTIME_IMAGE=gcr.io/distroless/static:nonroot
FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY gen/go ./gen/go
COPY internal ./internal
COPY probe ./probe
COPY proto ./proto
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/probe ./probe/cmd/probe

FROM ${GO_RUNTIME_IMAGE}
COPY --from=builder /out/probe /usr/local/bin/probe
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/probe"]
