# Use an official Ubuntu 22.04 as a parent image
FROM ubuntu:22.04

# Set environment variables to non-interactive (this prevents some prompts)
ENV DEBIAN_FRONTEND=non-interactive
WORKDIR /llvm-source

# Run package updates and install packages
RUN apt-get update \
    && apt-get install -y \
    build-essential \
    make \
    cmake \
    z3 \
    unzip \
    zlib1g-dev \
    git \
    python3 \
    python3-pip \
    ninja-build \
    nlohmann-json3-dev \
    wget 

RUN wget https://github.com/Z3Prover/z3/releases/download/z3-4.8.11/z3-4.8.11-x64-glibc-2.31.zip && \
    unzip z3-4.8.11-x64-glibc-2.31.zip && \
    rm z3-4.8.11-x64-glibc-2.31.zip && \
    cd z3-4.8.11-x64-glibc-2.31 && \
    export Z3_DIR=`pwd`

# Download clang
RUN wget -q https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-15.0.7.zip \
    && unzip llvmorg-15.0.7.zip \
    && rm llvmorg-15.0.7.zip \
    && mv llvm-project-llvmorg-15.0.7 llvm-15.0.7

# Setup and compile it
RUN cd llvm-15.0.7 \
    && mkdir build && cd build \
    && cmake -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_RTTI=ON \
    && ninja -j4

ENV PATH /llvm-source/llvm-15.0.7/build/bin:$PATH

COPY analyze.sh /llvm-source

RUN apt install -y bear

RUN git clone https://github.com/tianocore/edk2.git \
    && cd edk2 \
    && git submodule update --init --recursive \
    && make -C BaseTools \
    && source edksetup.sh
    && bear -- build OvmfPkg/OvmfPkgX86.dsc -t CLANGPDB -a X64

# Set the default shell command
CMD ["bash"]
