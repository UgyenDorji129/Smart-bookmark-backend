FROM nginx
COPY ./index.html /usr/share/nginx/html/index.html
RUN rm /etc/nginx/conf.d/default.conf
COPY ./nginx.conf /etc/nginx/conf.d/default.conf