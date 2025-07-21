FROM debian

COPY crtls /

ENTRYPOINT [ "/crtls" ]
