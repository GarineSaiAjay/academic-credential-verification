FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.30.6-alpine
# Pick up fixes for libraries the base image has not caught up with yet.
RUN apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN mkdir -p /etc/nginx/acvs
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 3000
