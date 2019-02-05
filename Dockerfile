FROM golang:1.11.1-alpine3.8 as builder

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV GO111MODULE=on

RUN apk update && apk add --no-cache git ca-certificates tzdata && update-ca-certificates

RUN adduser -D -g '' appuser

ADD . ${GOPATH}/src/app/
WORKDIR ${GOPATH}/src/app

RUN go build -mod=vendor -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/safebrowsing_exporter

FROM scratch
ARG VCS_REF
ARG BUILD_DATE

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/tnwhitwell/safebrowsing_exporter" \
      org.label-schema.docker.cmd="docker run -e API_KEY=google-api-key -p 9222:9222 tnwhitwell/safebrowsing_exporter" \
      org.label-schema.docker.params="API_KEY=google API token" \
      org.label-schema.schema-version="1.0" \
      maintainer="tom@whi.tw"

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

COPY --from=builder /go/bin/safebrowsing_exporter /go/bin/safebrowsing_exporter

EXPOSE 9264

USER appuser

ENTRYPOINT [ "/go/bin/safebrowsing_exporter" ]