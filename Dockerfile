FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY db ./db
COPY public ./public

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# 관리자 권한 없이 실행 (기본 이미지에 있는 node 사용자)
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/health || exit 1

CMD ["node", "server.js"]
