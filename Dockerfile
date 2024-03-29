FROM docker.io/golang:1.17 as builder

WORKDIR /builder

# Cache deps
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN make build-cdi

# --------------

FROM docker.io/alpine:latest

ARG GIT_COMMIT=unspecified
ARG VERSION=unspecified

LABEL maintainer="hello@tcfw.com.au" description="Open Cryptography Standard CDI node (go)" \
	git_commit=${GIT_COMMIT} version=${VERSION}}

COPY --from=builder /builder/bin/ocs-cdi /usr/bin

EXPOSE 80/tcp 443/tcp 443/udp 4002/tcp 4002/udp

CMD ["ocs-cdi"]