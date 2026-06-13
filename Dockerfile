FROM golang:1.22-bookworm AS builder

WORKDIR /src
COPY . .
RUN make pcce && cp /src/pcce /pcce

FROM ubuntu:22.04
COPY --from=builder /pcce /pcce
ENTRYPOINT ["/bin/sh", "-c", "while sleep 3600; do :; done"]
