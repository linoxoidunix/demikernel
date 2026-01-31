#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Fail on error.
set -e

# Switch to working directory.
pushd $PWD
mkdir -p $HOME/tmp/dpdk
cd $HOME/tmp/dpdk

# Download sources.
wget https://fast.dpdk.org/rel/dpdk-22.11.tar.xz
tar -xvf dpdk-22.11.tar.xz
cd dpdk-22.11
mkdir -p build

# Install pre-requisites.
pip3 install pyelftools

# Build and install
CC=gcc-14 CXX=g++-14 meson setup build --prefix=$HOME/dpdk-22.11 -Ddisable_drivers=net/gve,net/ionic
ninja -C build
ninja -C build install

# Cleanup.
popd
rm -rf $HOME/tmp/dpdk
