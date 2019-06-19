# Use multi-stage build to reduce image size
FROM rust:1.34-slim-stretch AS source
LABEL maintainer="Stegos AG <info@stegos.com>"

RUN apt-get update && apt-get install -y git-core
ADD . /usr/src/stegos
WORKDIR /usr/src/stegos
RUN ./ci-scripts/install-deps.sh
RUN cargo install --bins --path . --root /usr/local
RUN mkdir /node

FROM scratch
LABEL maintainer="Stegos AG <info@stegos.com>"

COPY --from=source /usr/local/bin/stegos /usr/local/bin/stegos
COPY --from=source /usr/local/bin/stegosd /usr/local/bin/stegosd
COPY --from=source /usr/local/bin/transaction_generator /usr/local/bin/transaction_generator
COPY --from=source /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/x86_64-linux-gnu/libstdc++.so.6
COPY --from=source /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libdl.so.2
COPY --from=source /lib/x86_64-linux-gnu/librt.so.1 /lib/x86_64-linux-gnu/librt.so.1
COPY --from=source /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/libpthread.so.0
COPY --from=source /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=source /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
COPY --from=source /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
COPY --from=source /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/libm.so.6
COPY --from=source --chown=1111:1111 /node /node

USER 1111:1111
WORKDIR /node

ENTRYPOINT [ "/usr/local/bin/stegosd" ]
