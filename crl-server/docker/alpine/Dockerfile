FROM golang:alpine

COPY ./gitkey/id_gitrsa  /root/.ssh/id_rsa

#####################################################
# CREATE SERVER BINARY
#####################################################
RUN apk add --update --virtual removable git openssh-client \
  && touch /root/.ssh/known_hosts \
  && ssh-keyscan github.com >> /root/.ssh/known_hosts \
  && git clone git@github.com:besol/r509-ca-manager.git /go/src/github.com/besol/r509-ca-manager \
  && go get github.com/tools/godep \
  && cd /go/src/github.com/besol/r509-ca-manager/crl-server \
  && godep restore \
  && cd /go/src/github.com/besol/r509-ca-manager/crl-server \
  && ./compile.sh \
  && mkdir -p /usr/local/concerto/ \
  && mv binaries/linux/crl-server /usr/local/concerto/crl-server \
  && rm -rf /go/src/github.com \
  && rm /root/.ssh/id_rsa \
  && rm /root/.ssh/known_hosts \
  && apk del removable \
  && rm -rf /var/cache/apk/*

#####################################################
# CONFIGURE CONTAINER
#####################################################
COPY ./scripts/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["crl-server"]
