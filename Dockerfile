FROM ubuntu:21.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt update
RUN apt install -y -q curl build-essential cmake

RUN curl -L -O https://github.com/DynamoRIO/dynamorio/releases/download/release_9.0.1/DynamoRIO-Linux-9.0.1.tar.gz
RUN tar xfz DynamoRIO-Linux-9.0.1.tar.gz
ENV PATH "/DynamoRIO-Linux-9.0.1/bin64:${PATH}"

COPY src /instrace/src
COPY CMakeLists.txt /instrace/CMakeLists.txt

WORKDIR /instrace
RUN cmake -DDynamoRIO_DIR=/DynamoRIO-Linux-9.0.1/cmake -B build
RUN cmake --build build

RUN drrun -root /DynamoRIO-Linux-9.0.1 -c build/libinstrace.so -- /usr/bin/ls
