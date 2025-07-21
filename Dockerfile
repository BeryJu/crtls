FROM debian

COPY crtls /

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean

RUN update-ca-certificates

VOLUME [ "/storage" ]

ENTRYPOINT [ "/crtls" ]
