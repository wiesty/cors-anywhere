FROM node:lts-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY lib/ ./lib/
COPY server.js ./

EXPOSE 8080

ENV HOST=0.0.0.0
ENV PORT=8080

CMD ["node", "server.js"]
