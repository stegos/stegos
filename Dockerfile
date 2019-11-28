# Use multi-stage build to reduce image size
FROM quay.io/stegos/rust:nightly-2019-11-25 AS source
LABEL maintainer="Stegos AG <info@stegos.com>"

COPY . /usr/src/stegos
WORKDIR /usr/src/stegos
RUN cargo install --bins --path /usr/src/stegos --root /usr/local

FROM scratch
LABEL maintainer="Stegos AG <info@stegos.com>"

COPY --from=source /usr/local/bin/stegos /usr/local/bin/stegos
COPY --from=source /usr/local/bin/stegosd /usr/local/bin/stegosd
COPY --from=source /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/x86_64-linux-gnu/libstdc++.so.6
COPY --from=source /usr/lib/x86_64-linux-gnu/libgmp.so.10 /usr/lib/x86_64-linux-gnu/libgmp.so.10
COPY --from=source /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libdl.so.2
COPY --from=source /lib/x86_64-linux-gnu/librt.so.1 /lib/x86_64-linux-gnu/librt.so.1
COPY --from=source /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/libpthread.so.0
COPY --from=source /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=source /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
COPY --from=source /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
COPY --from=source /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/libm.so.6

WORKDIR /data
ENV STEGOS_DATA_DIR /data

EXPOSE 3144 3145 9090
ENTRYPOINT [ "/usr/local/bin/stegosd" ]
