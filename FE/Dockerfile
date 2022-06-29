FROM node:14-buster as build

WORKDIR /code

COPY ./FE/package.json package.json
COPY ./FE/package-lock.json package-lock.json

RUN npm install -D webpack-cli

RUN npm ci --production

COPY . .

RUN npm run build:prod

FROM nginx:1.21.6-alpine as prod

COPY --from=build /code/dist /usr/share/nginx/html

RUN rm /etc/nginx/conf.d/default.conf

COPY /config/nginx.conf /etc/nginx/conf.d

EXPOSE 80

ENTRYPOINT ["nginx", "-g", "daemon off;"]