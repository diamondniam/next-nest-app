FROM node:18-alpine

WORKDIR /app

RUN apk add --no-cache curl

RUN curl -sSL https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-v0.6.1.tar.gz | tar -xz -C /usr/local/bin

COPY package.json ./
COPY tsconfig.json ./
RUN npm install

COPY prisma ./prisma/

COPY . .

RUN npm run build

CMD ["dockerize", "-wait", "tcp://db:5432", "-timeout", "30s", "npm", "run", "start:dev"]