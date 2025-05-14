FROM node:18-alpine

WORKDIR /app

RUN apk add --no-cache curl

RUN curl -sSL https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-v0.6.1.tar.gz | tar -xz -C /usr/local/bin

COPY package.json ./
COPY tsconfig.json ./
RUN npm install

COPY prisma ./prisma/

RUN npx prisma generate

COPY . .

RUN npm run build

CMD ["sh", "-c", "dockerize -wait tcp://db:5432 -timeout 30s && npx prisma migrate deploy && npm run start:dev"]