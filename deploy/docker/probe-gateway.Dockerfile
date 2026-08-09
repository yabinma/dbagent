# probe-gateway — Go static binary (mTLS session + bootstrap + internal HTTP).
# Runtime ARGs must be declared before the first FROM so --build-arg reaches them.
ARG GO_IMAGE=golang:1.26.4
ARG GO_RUNTIME_IMAGE=gcr.io/distroless/static:nonroot
FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY gen/go ./gen/go
COPY internal ./internal
COPY services/probe-gateway ./services/probe-gateway
COPY proto ./proto
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/probe-gateway ./services/probe-gateway/cmd/probe-gateway

FROM ${GO_RUNTIME_IMAGE}
COPY --from=builder /out/probe-gateway /usr/local/bin/probe-gateway
USER nonroot:nonroot
EXPOSE 8443 8444 8080
ENTRYPOINT ["/usr/local/bin/probe-gateway"]
