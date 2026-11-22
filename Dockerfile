# Stage 1: Install Mermaid CLI in official Node.js (musl/Alpine) image
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS mermaid-builder
ENV PUPPETEER_SKIP_DOWNLOAD=true
WORKDIR /opt/mermaid
COPY docker/mermaid/package.json docker/mermaid/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

# Stage 2: Final runtime image
FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd AS runtime

# Labels following OCI specifications
LABEL org.opencontainers.image.title="secdiagram" \
      org.opencontainers.image.description="Deterministic architecture, relationship, and security diagrams for Python repositories." \
      org.opencontainers.image.authors="secdiagram maintainers" \
      org.opencontainers.image.licenses="MIT"

# Alpine publishes security fixes as package revision bumps on the stable
# branch, so upgrade the base distribution first, then install git,
# ca-certificates, and the headless Chromium renderer with fonts. libstdc++ is
# required by the Node.js binary copied below.
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        git \
        ca-certificates \
        chromium \
        font-freefont \
        libstdc++

# Copy Node binary and locked Mermaid CLI dependencies from the builder stage
COPY --from=mermaid-builder /usr/local/bin/node /usr/local/bin/node
COPY --from=mermaid-builder /opt/mermaid/node_modules /opt/mermaid/node_modules
RUN ln -sf /opt/mermaid/node_modules/.bin/mmdc /usr/local/bin/mmdc

# Configure Puppeteer to use system Chromium without sandbox inside Docker container
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Create Puppeteer and Mermaid config files for mmdc
RUN echo '{"args": ["--no-sandbox", "--disable-setuid-sandbox"]}' > /etc/puppeteer-config.json \
    && echo '{"maxTextSize": 5000000, "maxEdges": 2000}' > /etc/mermaid-config.json
ENV PUPPETEER_CONFIG=/etc/puppeteer-config.json \
    MERMAID_CONFIG=/etc/mermaid-config.json

# Create non-root user for container security
RUN addgroup -g 10001 secdiagram \
    && adduser -D -u 10001 -G secdiagram -h /home/secdiagram -s /bin/sh secdiagram \
    && mkdir -p /repo /app \
    && chown -R secdiagram:secdiagram /app /repo /home/secdiagram

WORKDIR /app

# Copy application source code
COPY . /app

# Install secdiagram package
RUN pip install --no-cache-dir .

# Switch to non-root user and target volume
USER secdiagram
WORKDIR /repo
VOLUME ["/repo"]

ENTRYPOINT ["secdiagram"]
CMD ["--dir", "."]
