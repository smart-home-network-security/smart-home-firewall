# Dockerfile describing the container used to
# cross-compile the projet for OpenWrt,
# in GitHub Actions.
# The default platform is the TP-Link WDR4900.

# Base image: Ubuntu 22.04 LTS
FROM ubuntu:22.04

# Set build configuration variables
ARG VERSION=v22.03.5
ARG ROUTER=tl-wdr4900
ARG TOOLCHAIN_DIR=toolchain-powerpc_8540_gcc-11.2.0_musl
ARG TARGET_DIR=target-powerpc_8540_musl

# Set initial working directory
ENV HOME=/root
WORKDIR ${HOME}

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    clang \
    flex \
    bison \
    g++ \
    gawk \
    gcc-multilib \
    gettext \
    git \
    libncurses5-dev \
    libssl-dev \
    python3-distutils \
    rsync \
    unzip \
    zlib1g-dev \
    file \
    wget \
    cmake \
    python3-pip

# Clone OpenWrt repository
ENV OPENWRT_HOME=${HOME}/openwrt
RUN git clone https://git.openwrt.org/openwrt/openwrt.git ${OPENWRT_HOME}
WORKDIR ${OPENWRT_HOME}
RUN git checkout ${VERSION}

# Update and install feeds
RUN ${OPENWRT_HOME}/scripts/feeds update -a
RUN ${OPENWRT_HOME}/scripts/feeds install -a

# Configure OpenWrt toolchain
COPY openwrt/${ROUTER}/config/config-minimal ${OPENWRT_HOME}/.config
ENV FORCE_UNSAFE_CONFIGURE=1
RUN make defconfig
RUN make download
RUN make -j $(($(nproc)+1))
ENV STAGING_DIR=${OPENWRT_HOME}/staging_dir
ENV TOOLCHAIN_PATH=${STAGING_DIR}/${TOOLCHAIN_DIR}
ENV TARGET_PATH=${STAGING_DIR}/${TARGET_DIR}
ENV C_INCLUDE_PATH=${TARGET_PATH}/usr/include
ENV LD_LIBRARY_PATH=${TARGET_PATH}/usr/lib
ENV PATH=${TOOLCHAIN_PATH}/bin:$PATH

# Get ready for next steps
WORKDIR ${HOME}
