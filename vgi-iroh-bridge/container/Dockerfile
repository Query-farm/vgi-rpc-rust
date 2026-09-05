FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY vgi-iroh-bridge /usr/local/bin/vgi-iroh-bridge

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/vgi-iroh-bridge"]
