# EasyEAP proxy: builds the console + enrollment portal, serves them with nginx (non-root).
FROM node:24-alpine AS build
WORKDIR /src
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM nginxinc/nginx-unprivileged:1.29-alpine
COPY deploy/proxy/default.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/proxy/security-headers.conf deploy/proxy/proxy-params.conf /etc/nginx/snippets/
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080 8443
