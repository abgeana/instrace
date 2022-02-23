FROM ubuntu:21.04

ARG DYNAMORIO_VERSION=9.0.1

ENV DEBIAN_FRONTEND noninteractive

RUN apt update
RUN apt install -y -q curl build-essential cmake

RUN curl -L -O https://github.com/DynamoRIO/dynamorio/releases/download/release_${DYNAMORIO_VERSION}/DynamoRIO-Linux-${DYNAMORIO_VERSION}.tar.gz
RUN tar xfz DynamoRIO-Linux-${DYNAMORIO_VERSION}.tar.gz
ENV PATH "/DynamoRIO-Linux-${DYNAMORIO_VERSION}/bin64:${PATH}"

COPY src /instrace/src
COPY CMakeLists.txt /instrace/CMakeLists.txt

WORKDIR /instrace
RUN cmake -DDynamoRIO_DIR=/DynamoRIO-Linux-${DYNAMORIO_VERSION}/cmake -B build
RUN cmake --build build

ENV DYNAMORIO_VERSION ${DYNAMORIO_VERSION}
RUN echo 'go() { drrun -root /DynamoRIO-Linux-${DYNAMORIO_VERSION} -c build/libinstrace.so -- $1; }' >> /root/.bashrc
