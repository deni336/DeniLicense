# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS build
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/denilicense ./cmd/denilicense \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/denilic ./cmd/denilic

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN addgroup -S denilicense \
    && adduser -S -G denilicense -h /var/lib/denilicense denilicense \
    && mkdir -p /var/lib/denilicense/secrets \
    && chown -R denilicense:denilicense /var/lib/denilicense
COPY --from=build /out/denilicense /usr/local/bin/denilicense
COPY --from=build /out/denilic /usr/local/bin/denilic
USER denilicense:denilicense
WORKDIR /var/lib/denilicense
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/denilicense"]
CMD ["serve"]
