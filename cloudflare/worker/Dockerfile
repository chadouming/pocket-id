# syntax=docker/dockerfile:1.7

ARG BUILD_TAGS="exclude_frontend"

# Stage 1: Build Backend (API-only, no frontend)
FROM golang:1.26-alpine AS backend-builder
ARG BUILD_TAGS
WORKDIR /build
COPY ./backend/go.mod ./backend/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
  go mod download

COPY ./backend ./
RUN mkdir -p frontend/dist
COPY .version .version

WORKDIR /build/cmd
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  VERSION=$(cat /build/.version) && \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64 \
  go build \
    -tags "${BUILD_TAGS}" \
    -ldflags="-s -w -X github.com/pocket-id/pocket-id/backend/internal/common.Version=${VERSION} -buildid=${VERSION}" \
    -trimpath \
    -o /build/pocket-id \
    .

# Stage 2: Minimal production image
FROM alpine:3.23.4
WORKDIR /app

RUN addgroup -g 1000 pocket-id && \
    adduser -u 1000 -G pocket-id -D pocket-id && \
    mkdir -p /app/data && \
    chown -R 1000:1000 /app/data

COPY --from=backend-builder /build/pocket-id /app/pocket-id
RUN chmod +x /app/pocket-id

EXPOSE 1411

ENV APP_ENV=production
ENV HOST=0.0.0.0
ENV PORT=1411

USER 1000:1000

CMD ["/app/pocket-id"]
