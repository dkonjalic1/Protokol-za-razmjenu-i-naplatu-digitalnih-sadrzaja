#!/bin/bash
set -e

# Osnovni alati
sudo apt update
sudo apt install -y build-essential cmake git ninja-build

# Verzije i putanje
OPENSSL_VERSION="3.5.0"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_ARCHIVE="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_DIR="openssl-${OPENSSL_VERSION}"
BUILD_DIR="$HOME/oqs-openssl-build"

# Instalacija paketa ako nedostaje
install_if_missing() {
    if ! dpkg -s "$1" >/dev/null 2>&1; then
        sudo apt-get install -y "$1"
    fi
}

# Zavisnosti
sudo apt-get update
install_if_missing wget
install_if_missing curl
install_if_missing build-essential
install_if_missing checkinstall
install_if_missing zlib1g-dev

sudo update-ca-certificates

# Preuzimanje i raspakivanje OpenSSL-a
wget "$OPENSSL_URL" || wget --no-check-certificate "$OPENSSL_URL"
tar -xzf "$OPENSSL_ARCHIVE"

cd "$OPENSSL_DIR"

# Build OpenSSL
./config \
    --prefix=/usr/local/openssl \
    --openssldir=/usr/local/openssl \
    shared zlib

make -j"$(nproc)"
sudo make install

# Odabir lib direktorija
if [ -d /usr/local/openssl/lib64 ]; then
    OPENSSL_LIB_DIR="/usr/local/openssl/lib64"
else
    OPENSSL_LIB_DIR="/usr/local/openssl/lib"
fi

# Dodavanje u linker konfiguraciju
echo "$OPENSSL_LIB_DIR" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig

# Zamjena openssl binarnog fajla
sudo mv /usr/bin/openssl /usr/bin/openssl.bak 2>/dev/null || true
sudo ln -s /usr/local/openssl/bin/openssl /usr/bin/openssl

# Okruzenje
echo 'export PATH=/usr/local/openssl/bin:$PATH' >> ~/.bashrc
echo "export LD_LIBRARY_PATH=$OPENSSL_LIB_DIR:\$LD_LIBRARY_PATH" >> ~/.bashrc
export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR:$LD_LIBRARY_PATH"

# Provjera
openssl version -a
sudo ln -s /usr/local/openssl/lib64 /usr/local/openssl/lib