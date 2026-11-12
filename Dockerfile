FROM node:22-alpine
ENV NODE_ENV=production PHOENIX_MODE=production HOST=0.0.0.0 PORT=3000 PHOENIX_DB=/data/phoenix.db PHOENIX_BACKUP_DIR=/data/backups PHOENIX_TRUST_PROXY=on
RUN apk add --no-cache su-exec
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY public ./public
COPY scripts ./scripts
COPY db ./db
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /data && chown -R node:node /data /app
VOLUME ["/data"]
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "--disable-warning=ExperimentalWarning", "server/index.js"]
