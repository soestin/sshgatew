# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN version=${VERSION#v} && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${version}" \
    -o /out/sshgatew ./cmd/sshgatew

FROM alpine:3.24

RUN apk add --no-cache ca-certificates su-exec \
    && addgroup -S -g 10001 sshgatew \
    && adduser -S -D -H -u 10001 -G sshgatew -s /sbin/nologin sshgatew \
    && mkdir -p /etc/sshgatew /var/lib/sshgatew \
    && chown sshgatew:sshgatew /etc/sshgatew /var/lib/sshgatew \
    && chmod 0750 /etc/sshgatew /var/lib/sshgatew

COPY --from=build /out/sshgatew /usr/local/bin/sshgatew
COPY --chmod=0755 deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 2222
VOLUME ["/etc/sshgatew", "/var/lib/sshgatew"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
