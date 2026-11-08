FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /da .

FROM alpine:3.20
COPY --from=build /da /usr/local/bin/da
RUN mkdir -p /data
ENTRYPOINT ["da"]
CMD ["node"]
