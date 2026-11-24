# Image unique du lab SYNTRAF : serveur et clients.
ARG PYTHON_VERSION=3.14

FROM debian:bookworm-slim AS iperf-build
# IPERF3_SOURCE : iperf3v (fork maintenu, IPERF3_REF = tag v3.22.1-v1...), esnet (IPERF3_REF = tag ESnet)
# ou fork (IPERF3_FORK_REPO / IPERF3_FORK_BRANCH).
ARG IPERF3_SOURCE=iperf3v
ARG IPERF3_REF=v3.22.1-v2
ARG IPERF3_FORK_REPO=https://github.com/davidBar-On/iperf.git
ARG IPERF3_FORK_BRANCH=issue-812-835-control-connection-keepalive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    if [ "$IPERF3_SOURCE" = "iperf3v" ]; then \
        git clone --depth 1 --branch "$IPERF3_REF" https://github.com/lbsou/iperf3v.git /build; \
    elif [ "$IPERF3_SOURCE" = "fork" ]; then \
        git clone --depth 1 --branch "$IPERF3_FORK_BRANCH" "$IPERF3_FORK_REPO" /build; \
    else \
        git clone --depth 1 --branch "$IPERF3_REF" https://github.com/esnet/iperf.git /build; \
    fi; \
    cd /build && ./configure --prefix=/opt/iperf3 && make -j"$(nproc)" && make install; \
    if ! LD_LIBRARY_PATH=/opt/iperf3/lib /opt/iperf3/bin/iperf3 --help 2>&1 | grep -q -- '--cntl-ka'; then \
        echo "ERREUR : cette version d'iperf3 ne supporte pas --cntl-ka ; choisir un tag plus rÃ©cent ou IPERF3_SOURCE=fork" >&2; \
        exit 1; \
    fi

FROM python:${PYTHON_VERSION}-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables procps tzdata iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY --from=iperf-build /opt/iperf3/bin/iperf3 /usr/local/bin/iperf3
COPY --from=iperf-build /opt/iperf3/lib/ /usr/local/lib/
# SYNTRAF appelle encore « iperf3 » ; « iperf3v » est le nom du binaire du fork.
RUN ln -s iperf3 /usr/local/bin/iperf3v && ldconfig && iperf3 --version
# Le serveur importe aussi des modules listés seulement côté client (ex. tabulate).
COPY requirements_server.txt requirements_client.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements_server.txt -r /tmp/requirements_client.txt
COPY lab/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /app /etc/syntraf /logs
WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
