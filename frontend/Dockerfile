FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.30.6-alpine@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951
# Pick up fixes for libraries the base image has not caught up with yet.
RUN apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN mkdir -p /etc/nginx/acvs
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 3000
