# Use multi-stage build to reduce image size
FROM rust:1.32-slim-stretch AS builder
LABEL maintainer="Stegos AG <info@stegos.cc>"

RUN apt-get update && apt-get install -y git-core
ADD . /usr/src/stegos
WORKDIR /usr/src/stegos
RUN ./ci-scripts/install-deps.sh
RUN cargo install --path . --root /usr/local

# rust:x.yy-slim-stretch is based on debian:stretch-slim
FROM debian:stretch-slim
RUN apt-get update && apt-get install -y \
    libgmp10 \
    libmpfr4 \
    libssl1.1

COPY --from=builder /usr/local/lib/libpbc* /usr/local/lib/
COPY --from=builder /usr/local/bin/stegos /usr/local/bin/
RUN ldconfig && stegos --version

CMD ["stegos"]
