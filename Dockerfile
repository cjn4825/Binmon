FROM ubuntu:24.04

ARG GCC=4:13.2.0-7ubuntu1
ARG ANSIBLE=9.2.0+dfsg-0ubuntu5
ARG MAKE=4.3-4.1build2

RUN apt update -y && apt upgrade -y

RUN apt install \
    git \
    gcc=${GCC} \
    ansible=${ANSIBLE} \
    make=${MAKE} \
    -y

RUN git clone https://github.com/cjn4825/binmon.git /build
WORKDIR /build
RUN make
