#!/bin/bash
set -e

# 1. Настройка путей
PROJECT_ROOT=$(pwd)
INSTALL_DIR="$PROJECT_ROOT/install"
BUILD_TMP="$PROJECT_ROOT/build_tmp"

echo "--- Начинаем сборку DPDK ---"
echo "Корень проекта: $PROJECT_ROOT"
echo "Путь установки: $INSTALL_DIR"

# 2. Создаем временную директорию и заходим в неё
mkdir -p "$BUILD_TMP"
pushd "$BUILD_TMP"

# 3. Скачивание исходников
if [ ! -f "dpdk-22.11.tar.xz" ]; then
    echo "Скачивание DPDK 22.11..."
    wget https://fast.dpdk.org/rel/dpdk-22.11.tar.xz
fi

# 4. Распаковка
echo "Распаковка..."
rm -rf dpdk-22.11
tar -xvf dpdk-22.11.tar.xz
cd dpdk-22.11

# 5. Подготовка окружения
echo "Установка зависимостей сборки..."
pip3 install pyelftools meson ninja

# 6. Сборка
echo "Конфигурация Meson..."
# Указываем --prefix как нашу папку install
CC=gcc-14 CXX=g++-14 meson setup build \
    --prefix="$INSTALL_DIR" \
    --libdir="lib64" \
    -Ddisable_drivers=net/gve,net/ionic

echo "Компиляция..."
ninja -C build

echo "Установка в $INSTALL_DIR..."
ninja -C build install

# 7. Возвращаемся и чистим за собой
popd
rm -rf "$BUILD_TMP"

echo "--- Сборка завершена успешно! ---"
echo "Библиотеки находятся в: $INSTALL_DIR/lib64"