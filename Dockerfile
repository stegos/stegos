# Use multi-stage build to reduce image size
FROM rust:1.31-slim-stretch AS builder
LABEL maintainer="Stegos AG <info@stegos.cc>"

ADD . /usr/src/stegos
WORKDIR /usr/src/stegos
RUN ./ci-scripts/install-deps.sh
RUN cargo install --path . --root /usr/local

# rust:x.yy-slim-stretch is based on debian:stretch-slim
FROM debian:stretch-slim
COPY --from=builder /usr/local/lib/libpbc* /usr/local/lib/
COPY --from=builder /usr/local/lib/libgmp* /usr/local/lib/
COPY --from=builder /usr/local/bin/stegos /usr/local/bin/
RUN ldconfig && stegos --version

CMD ["stegos"]
