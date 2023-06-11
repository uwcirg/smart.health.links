FROM node:18 as build-deps

EXPOSE 3000

# ENV DIRPATH /opt/app
ENV REACT_APP_REAL_SERVER_BASE=https://smart-health-links-server.cirg.washington.edu/api
ENV NODE_ENV production

WORKDIR /opt/app

COPY package*.json ./
RUN npm clean-install

COPY . .
RUN npm run build

CMD ["npm", "start"]