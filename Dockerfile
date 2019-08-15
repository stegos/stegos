# Use multi-stage build to reduce image size
FROM stegos/rust:nightly-2019-08-04 AS source
LABEL maintainer="Stegos AG <info@stegos.com>"

RUN apt-get update && apt-get install -y git-core
ADD . /usr/src/stegos
WORKDIR /usr/src/stegos
RUN ./ci-scripts/install-deps.sh
RUN cargo install --bins --path . --root /usr/local
RUN mkdir /node

FROM debian:stretch-slim
LABEL maintainer="Stegos AG <info@stegos.com>"

ENV RUST_BACKTRACE=1

RUN apt-get update && apt-get install -y gosu

ADD docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN groupadd -g 1111 stegos && useradd -u 1111 -g 1111 stegos

COPY --from=source /usr/local/bin/stegos /usr/local/bin/stegos
COPY --from=source /usr/local/bin/stegosd /usr/local/bin/stegosd

WORKDIR /node

RUN /usr/local/bin/stegosd --version

ENTRYPOINT [ "/usr/local/bin/docker-entrypoint.sh" ]
