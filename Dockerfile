FROM node:lts-bullseye as build-deps

EXPOSE 3000

ENV DIRPATH /opt/app
WORKDIR ${DIRPATH}

COPY ui ${DIRPATH}/ui
COPY client ${DIRPATH}/client

WORKDIR ${DIRPATH}/ui

ENV REACT_APP_REAL_SERVER_BASE=https://smart-health-links-server.cirg.washington.edu/api

RUN npm ci
RUN npm run build
# RUN mv build ${DIRPATH}
# RUN cp package.json ${DIRPATH}
# RUN cp -r node_modules ${DIRPATH}

WORKDIR ${DIRPATH}/client

RUN npm ci
RUN npm run build
RUN cp -r dist ${DIRPATH}/ui/public/viewer

WORKDIR ${DIRPATH}/ui

CMD ["npm", "start"]