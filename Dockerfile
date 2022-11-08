FROM node:lts-bullseye as build-deps

EXPOSE 3000

ENV DIRPATH /opt/app
ENV REACT_APP_REAL_SERVER_BASE=https://smart-health-links-server.cirg.washington.edu/api
ENV NODE_ENV production

WORKDIR ${DIRPATH}

COPY ui ${DIRPATH}/ui
COPY client ${DIRPATH}/client

WORKDIR ${DIRPATH}/ui

RUN npm clean-install
RUN npm run build

WORKDIR ${DIRPATH}/client

RUN npm clean-install
RUN npm run build
RUN cp -r dist ${DIRPATH}/ui/build/viewer

WORKDIR ${DIRPATH}/ui

CMD ["npm", "start"]