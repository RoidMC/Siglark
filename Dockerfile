# Build stage
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/siglark ./cmd/siglark

# Runtime stage. Alpine keeps a shell for the identity-file wait in
# examples/pnx/docker-compose.yml and ships the CA bundle the Minecraft
# authorization JWKS needs.
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/siglark /usr/local/bin/siglark
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/siglark"]
