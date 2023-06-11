FROM node:18 as build-deps

WORKDIR /opt/app

COPY package*.json ./
RUN npm clean-install

COPY . .
RUN npm run build

FROM nginx as production
EXPOSE 80
COPY cors.conf /etc/nginx/conf.d/default.conf
COPY --from=build-deps /opt/app/dist /usr/share/nginx/html