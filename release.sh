#!/bin/bash
mkdir -p release/shioncoin
cd release
../configure --libdir=/src/shioncoin/release/shioncoin --bindir=/src/shioncoin/release/shioncoin --sbindir=/src/shioncoin/release/shioncoin --docdir=/src/shioncoin/release/shioncoin --with-libshare=/src/sharelib/release
make
make install
tar -cpf sharecoin-`arch`.tar shioncoin
gzip -f sharecoin-`arch`.tar
