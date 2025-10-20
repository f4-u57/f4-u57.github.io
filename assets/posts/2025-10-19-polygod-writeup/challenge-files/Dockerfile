FROM ubuntu@sha256:dc17125eaac86538c57da886e494a34489122fb6a3ebb6411153d742594c2ddc

RUN apt update -y
RUN apt install -y nginx socat

COPY --chmod=0755 <<"EOF" /etc/nginx/sites-available/default
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /srv;
        server_name _;
        error_page  502 = @disappointing_gateway;

        location / {
                if ($request_method ~ "^\w+$" ) {
                        proxy_pass http://localhost:8080;
                }
                try_files /index.html =404;
        }

        location @disappointing_gateway {
                try_files /index.html =404;
        }
}
EOF

COPY --chmod=0555 polygod /srv/polygod
COPY --chmod=0555 index.html /srv/index.html

CMD ["bash", "-c", "nginx; echo \"$FLAG\" > /flag.txt; socat TCP4-LISTEN:8080,reuseaddr,fork EXEC:/srv/polygod"]
