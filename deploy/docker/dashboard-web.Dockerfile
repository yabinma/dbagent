# dashboard-web — static Vite build served by unprivileged nginx.
# Runtime ARGs must be declared before the first FROM so --build-arg reaches them.
ARG NODE_IMAGE=node:20-alpine
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.27-alpine
FROM ${NODE_IMAGE} AS builder
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM ${NGINX_IMAGE}
USER root
COPY deploy/docker/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/docker/nginx/10-rca-config.sh /docker-entrypoint.d/10-rca-config.sh
# Copy first, then chown so the built assets are nginx-owned (S3).
COPY --from=builder /web/dist /usr/share/nginx/html
RUN chmod +x /docker-entrypoint.d/10-rca-config.sh \
 && chown -R nginx:nginx /usr/share/nginx/html /etc/nginx/templates
ENV RCA_API_BASE_URL=/api/v1 \
    RCA_API_UPSTREAM=http://dashboard-api:8081/
USER nginx
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
