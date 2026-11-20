FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

# Cài dependency trước để tận dụng layer cache.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

COPY src ./src

EXPOSE 8080

# Không COPY .env vào image: cấu hình được inject qua env_file của compose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/index.js"]
