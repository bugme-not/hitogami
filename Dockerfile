# -----------------------------------------------------------------
# Build Stage: Fetch Sing-Box binary dynamically
# -----------------------------------------------------------------
FROM alpine:3.20 AS singbox-bin

RUN apk add --no-cache \
    curl \
    tar \
    ca-certificates \
    bash

WORKDIR /app

# Detect architecture and pull the latest release tag
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then SB_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then SB_ARCH="arm64"; \
    else SB_ARCH="amd64"; fi && \
    RELEASE_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') && \
    VERSION=${RELEASE_TAG#v} && \
    curl -L -o sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/${RELEASE_TAG}/sing-box-${VERSION}-linux-${SB_ARCH}.tar.gz" \
    || curl -L -o sing-box.tar.gz "https://ghproxy.com/https://github.com/SagerNet/sing-box/releases/download/${RELEASE_TAG}/sing-box-${VERSION}-linux-${SB_ARCH}.tar.gz" && \
    tar -xzf sing-box.tar.gz --strip-components=1 && \
    mv sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf sing-box.tar.gz

# -----------------------------------------------------------------
# Final Stage: OpenResty + Sing-Box + Python Scripts
# -----------------------------------------------------------------
FROM openresty/openresty:alpine-fat

ENV TZ=Asia/Shanghai

RUN apk add --no-cache \
    ca-certificates \
    bash \
    curl \
    tzdata \
    wget \
    supervisor \
    python3 \
    py3-pip \
    iptables

WORKDIR /app

# Copy Sing-Box binary
COPY --from=singbox-bin /usr/local/bin/sing-box /usr/local/bin/sing-box
RUN chmod +x /usr/local/bin/sing-box

# Copy Python scripts & configs
COPY sub_server.py /app/sub_server.py
COPY anti_ddos.py /app/anti_ddos.py
COPY log_cleaner.py /app/log_cleaner.py
COPY entrypoint.sh /app/entrypoint.sh

# Copy Sing-Box config & server configs
COPY singbox.json /etc/sing-box/config.json
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY supervisord.conf /etc/supervisord.conf

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
CMD wget -qO- http://[::1]:8080/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
