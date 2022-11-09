FROM node:18 as build-deps

WORKDIR /opt/app

COPY package*.json ./
RUN npm clean-install

COPY . .
RUN npm run build

FROM nginx as production
EXPOSE 80
COPY dist /usr/share/nginx/html