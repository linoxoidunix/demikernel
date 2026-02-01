#!/bin/bash
set -e

# ==========================================
# Настройки версии (меняй здесь)
# ==========================================
DPDK_VER="25.11" # Например, 22.11, 23.11 или 25.11
# ==========================================

# 1. Настройка путей
PROJECT_ROOT=$(pwd)
INSTALL_DIR="$PROJECT_ROOT/install"
BUILD_TMP="$PROJECT_ROOT/build_tmp"
DPDK_DIR="dpdk-$DPDK_VER"
DPDK_TAR="$DPDK_DIR.tar.xz"

echo "--- Начинаем сборку DPDK $DPDK_VER ---"
echo "Корень проекта: $PROJECT_ROOT"
echo "Путь установки: $INSTALL_DIR"

# 2. Создаем временную директорию
mkdir -p "$BUILD_TMP"
pushd "$BUILD_TMP"

# 3. Скачивание исходников
if [ ! -f "$DPDK_TAR" ]; then
    echo "Скачивание $DPDK_TAR..."
    wget "https://fast.dpdk.org/rel/$DPDK_TAR"
fi

# 4. Распаковка
echo "Распаковка $DPDK_DIR..."
rm -rf "$DPDK_DIR"
tar -xvf "$DPDK_TAR"
cd "$DPDK_DIR"

# 5. Подготовка окружения
echo "Обновление инструментов сборки..."
pip3 install --upgrade pyelftools meson ninja

# 6. Сборка
echo "Конфигурация Meson (Версия: $DPDK_VER)..."
# Используем префикс для локальной установки в папку проекта
CC=gcc-14 CXX=g++-14 meson setup build \
    --prefix="$INSTALL_DIR" \
    --libdir="lib64" \
    -Ddisable_drivers=net/gve,net/ionic

echo "Компиляция..."
ninja -C build

echo "Установка в $INSTALL_DIR..."
# В современных DPDK ninja install корректно учитывает префикс
ninja -C build install

# 7. Возвращаемся и чистим
popd
# rm -rf "$BUILD_TMP" # Можно закомментировать для отладки

echo "--- Сборка $DPDK_VER завершена успешно! ---"
echo "Файлы установлены в: $INSTALL_DIR"
echo "Библиотеки: $INSTALL_DIR/lib64"
echo "Инклюды: $INSTALL_DIR/include"