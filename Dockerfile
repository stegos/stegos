# Use multi-stage build to reduce image size
FROM rust:1.34-slim-stretch AS builder
LABEL maintainer="Stegos AG <info@stegos.com>"

RUN apt-get update && apt-get install -y git-core
ADD . /usr/src/stegos
WORKDIR /usr/src/stegos
RUN ./ci-scripts/install-deps.sh
RUN cargo install --bins --path . --root /usr/local

# rust:x.yy-slim-stretch is based on debian:stretch-slim
FROM debian:stretch-slim
RUN apt-get update && apt-get install -y \
    libssl1.1

COPY --from=builder /usr/local/bin/* /usr/local/bin/
RUN stegos --version

CMD ["stegos"]
