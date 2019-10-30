FROM ubuntu:xenial as source
LABEL maintainer="Stegos AG <info@stegos.com>"
COPY * /usr/src/
WORKDIR /usr/src
RUN WITH_ANDROID=1 ./build.sh builddep && apt-get clean all && rm -rf /root/.cargo/registry
ENV PATH="$PATH:/root/.cargo/bin:/root/Android/Sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin"
