FROM debian:buster-slim as source
LABEL maintainer="Stegos AG <info@stegos.com>"
ARG RUST_TOOLCHAIN=nightly-2019-08-05
COPY build.sh /
RUN /build.sh builddep && apt-get clean all && rm -rf /root/.cargo/registry
ENV PATH="/root/.cargo/bin:$PATH"
