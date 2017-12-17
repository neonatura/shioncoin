#!/bin/bash
mkdir -p release/share-coin
cd release
../configure --libdir=/src/share-coin/release/share-coin --bindir=/src/share-coin/release/share-coin --sbindir=/src/share-coin/release/share-coin --docdir=/src/share-coin/release/share-coin --with-libshare=/src/sharelib/release
make
make install
tar -cpf sharecoin-`arch`.tar share-coin
gzip -f sharecoin-`arch`.tar
