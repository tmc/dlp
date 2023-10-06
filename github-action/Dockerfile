FROM golang:1.20.8-alpine

RUN apk add --no-cache bash curl git

RUN curl -sL https://raw.githubusercontent.com/reviewdog/reviewdog/master/install.sh| sh -s -- -b /usr/local/bin/ v0.9.15
RUN curl -sLO https://github.com/tmc/dlp/releases/download/v1.0.0/dlp_1.0.0_linux_amd64.tar.gz
RUN echo '61f567e6ee0fd23ce1ae0e556998ec213b87b57eb10e036ddcce5873f3f5909d  dlp_1.0.0_linux_amd64.tar.gz' | sha256sum -c
RUN tar xvf *gz
RUN chmod +x detect-pii && mv detect-pii /usr/local/bin/

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["-h"]
