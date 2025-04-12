ARG APP_PATH=/opt/outline
FROM node:20-alpine AS dev

ARG APP_PATH
WORKDIR $APP_PATH
COPY ./package.json ./yarn.lock ./
COPY ./patches ./patches

RUN yarn install --no-optional --frozen-lockfile --network-timeout 1000000 && \
  yarn cache clean

COPY . .

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["yarn", "dev:watch"]

FROM deps as base

ARG APP_PATH
WORKDIR $APP_PATH


ARG APP_PATH=/opt/outline
FROM node:20-alpine AS deps

ARG APP_PATH
WORKDIR $APP_PATH
COPY ./package.json ./yarn.lock ./
COPY ./patches ./patches

RUN yarn install --no-optional --frozen-lockfile --network-timeout 1000000 && \
  yarn cache clean

COPY . .
ARG CDN_URL
RUN yarn build

RUN rm -rf node_modules

RUN yarn install --production=true --frozen-lockfile --network-timeout 1000000 && \
  yarn cache clean

ARG APP_PATH=/opt/outline
FROM deps as base

ARG APP_PATH
WORKDIR $APP_PATH

# ---
FROM node:20-slim AS runner

LABEL org.opencontainers.image.source="https://github.com/outline/outline"

ARG APP_PATH
WORKDIR $APP_PATH
ENV NODE_ENV=production

COPY --from=base $APP_PATH/build ./build
COPY --from=base $APP_PATH/server ./server
COPY --from=base $APP_PATH/public ./public
COPY --from=base $APP_PATH/.sequelizerc ./.sequelizerc
COPY --from=base $APP_PATH/node_modules ./node_modules
COPY --from=base $APP_PATH/package.json ./package.json

# Install wget to healthcheck the server
RUN  apt-get update \
  && apt-get install -y wget \
  && rm -rf /var/lib/apt/lists/*

# Create a non-root user compatible with Debian and BusyBox based images
RUN addgroup --gid 1001 nodejs && \
  adduser --uid 1001 --ingroup nodejs nodejs && \
  chown -R nodejs:nodejs $APP_PATH/build && \
  mkdir -p /var/lib/outline && \
	chown -R nodejs:nodejs /var/lib/outline

ENV FILE_STORAGE_LOCAL_ROOT_DIR=/var/lib/outline/data
RUN mkdir -p "$FILE_STORAGE_LOCAL_ROOT_DIR" && \
  chown -R nodejs:nodejs "$FILE_STORAGE_LOCAL_ROOT_DIR" && \
  chmod 1777 "$FILE_STORAGE_LOCAL_ROOT_DIR"

VOLUME /var/lib/outline/data

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER nodejs

HEALTHCHECK --interval=1m CMD wget -qO- "http://localhost:${PORT:-3000}/_health" | grep -q "OK" || exit 1

EXPOSE 3000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["yarn", "start"]
