shioncoin
==========

<h3>Programs Provided</h3>

The "shcoind" daemon provides RPC, Stratum, and Currency services.

The "shc" console utility program provides access to the daemon. 

<h3>ShionCoin Service</h3>
The ShionCoin service "shcoind" provides the core SHC virtual currency server operations.


SHC Port: 24104

<h3>RPC Service</h3>
The ShionCoin package includes a command-line console program in order to run RPC commands against the server.

The RPC service is provided for the "shc" utility program to manage service or wallet operations.

Run the command "shc --prompt" in order to invoke a command-line processor.

RPC Port: 9447

<h3>Build Dependencies</h3>

The c++ boost shared library is required.  To be specific, the "system", "filesystem", and "thread" boost libraries. The "shcoind" and "shc" programs are the only sharelib program that link against boost libraries.
To install on linux run 'yum install libboost*' or 'apt-get install libboost*'.

The GMP library is required.  In order to install the GMP library;
Run "yum install gmp-devel" on CentOS.
Run "apt-get install libgmp-dev" on Ubuntu.
Run "pacman -S libgmp-devel" from MSYS2 64-bit.

<h2>SHC Specifications</h2>
The shioncoin is unique in that it provides additional types of transactions than only coin transfers. Examples of these capabilities include exchanging coins between currencies, providing certified licenses for custom use, and assigning names to otherwise hard to remember hash tags. Compatibilty with the 'share library' file-system and network providing methods to utilize SHC block-chain transactions via external programs.

Additional examples including commiting address alias names onto the block-chain, multi-level certification operations that are compatible with x509, geodetic context operations such as commiting a name to a location, and much more. 
 
The shcoind SHC coin server recalcultes the block difficulty rate every block using the Kimoto Gravity Well algorythm. The target duration for blocks is one minute.

A maximum of half a billion (500,000,000) SHC coins will be generated. The reward life-time is expected to continue for around 40 years (~ 2055).  

The SHC network requires 1 confirmation per transaction.

The SHC network block matures after 60 confirmations.



<h2>Quick Instructions</h2>

64-bit Cent-OS: Add '--libdir=/usr/local/lib64' as configure command-line option

Building the shioncoin programs:
<i><small><pre>
  git clone https://github.com/neonatura/shioncoin
  cd shioncoin
	./autogen.sh
  ./configure
  make
  make install
</pre></small></i>

The binaries can be found under "src/shioncoin/shcoind" and "src/coin-console/shc"". Performing a 'make install' will install these programs into the bin and sbin directories respectively. The "shc" client program must be ran on the same machine as the "shcoind" daemon. 
When installed on a unix-like systems that supports the traditional /etc/init.d/rc.d/ hierarchy a 'shcoind' daemon will be registered with the system to load upon startup as the root user. 
Note: The client utility programs "shc" must be ran as the same user as the 'shcoind' daemon.

The shcoind daemon and client programs store data in the "/var/lib/share/blockchain/" directory on linux and the "%APPDATA%\share\blockchain\" directory on windows. Commands are provided in order to import or export the entire block-chain, wallet transactions, and network peer addresses. No RPC access is permitted except via the local machine and only with the automatically generated rpc credentials (see "rpc.dat" file). 

Run the "shc --prompt" for a textual UI interactive environment.

<h3>Features</h3>

<h4>Stratum Service</h4>
The Stratum service provides full-capability gateway access for coin miner devices (ASIC) and programs (cpuminer). Typically, a seperate program is required in order to provide this service. In addition, capabilities for creating and managing wallet accounts is provided for web/API interfacing.

Note: The stratum service utilizes supplemental methods that are not standard, and require a compatible API client for full usage. 

Stratum Port: 9448

The stratum status web-page will display a "verification fractal" which can be compared to other sites in order to verify the integrity of their block-chain.

<h4>Fast and affordable transaction fees.</h4>
ShionCoin has a 60-second block difficulty and has a smaller transaction fee than typical coin services in order to ensure sending transactions is possible for small and large fund transfers alike. 

A 4mb allowance size for each blocks ensures that thousands of transactions can be stored in each block. 

<h4>Coin Address Alias</h4>
Create aliases for coin addresses and store them on the global block-chain. This provides the ability for other users to directly reference your own established name without the need to remember a lengthy coin address.

Alias commands can be used in lue of a coin address by prepending a "@" character.

Creating a context initially cost around 20 SHC, and this fee goes down in cost over time. Aliases expire after 12 years. 

Example "shc" console commands:
```
alias.set test <coin addr>
alias.get test
wallet.send bank @test 10
```

<h4>Context Data</h4>
Contextual data may be stored in the block-chain describing people places, or any other arbitrary information. This functionality has aspects similar to name-coin, except that the context data content has a larger 4k limit per record.

A context record will expire after two years. The owner can update the context with a new (or original) value which will reset the expiration date.

Creating a context initially cost around 20 SHC, and this fee goes down in cost over time.

Example "shc" console commands:
```
ctx.setloc bank "Missoula, MT" "geo:46.8787,113.9966" AREA US
ctx.getloc geo:46.8787,113.9966
```

<h4>Certification</h4>
Chained certificates may be created on the global block-chain which are linked to a particular coin address. 

Certified fund transfers may be made by associating a transaction with a particular certificate. This allows the end-point to verify the origin of the funds.

A fee may also be associated with a certificate allowing for certificates derived from it to be purchased.

A certificate may also be derived into a license. Licensing can be used with SEXE scripts and also can be integrated into a application key via the libshare suite thereby requiring a license to be purchased from the sharecoin network in order to be executed.

Asset transactions may be created and optionally signed with a certificate. These transactions are meant to be used in order to provide a record for physical items such as property or equipment. An asset transaction will not expire.

Creating a certificate initially cost around 10 SHC, and this fee goes down in cost over time. Certificate transactions will expire after 48 years, and cannot be updated after creation.

Example "shc" console commands:
```
cert.new bank "test CA"
{ .. "certhash": "d9ac92d017b790eee16e3fd46c8e376318144a81" .. }
cert.get d9ac92d017b790eee16e3fd46c8e376318144a81
cert.derive "test certificate" d9ac92d017b790eee16e3fd46c8e376318144a81 1
```

<h4>Geodetic Stamping</h4>
The "spring matrix" contains bit-flags derived from over 1000000 geodetic landmark locations. Each time a geodetic stamp is performed on a particular location contained in the matrix the bit-flag representing that location is removed. As time progresses it will become more difficult to pinpoint unique locations that have not already been found. 

A geodetic stamp is performed in order to "stamp" an identity derived from a coin address onto a particular geodetic location. Any valid latitude and longitude pair may be "stamped". If the location happens to be an unfround location stored in the spring matrix then the sharecoin network will automatically reward you ONE SHC to the account which stamped the location.

Example "shc" console commands:
```
wallet.stamp bank "geo:46.8787,113.9966"
"ident":  {
    "label":  "geo:46.8787,113.9966",
    "geo":  "46.878700,113.996600",
    "addr": "SM5JyMLR2RFzPnEBd2UXUWLzsKvGvxaDQL"
}
```

<h4>SEXE Scripting</h4>
Scripts associated with a particular coin server node may be created in the libshare SEXE programming language. These scripts allow for the tracking of information and creation of block transactions. An example script might be a simple coin faucet which collects and distributes coins, or a music ticket outlet. 

A SEXE transaction will expire after 48 years.


Example SEXE facuet program:
```
function send(a, v)
  userdata.txout = { }
  userdata.txout.addr = a
  userdata.txout.value = v
  userdata.total = userdata.total - v
end
function donate(farg)
  if (farg.value >= 1) then
    userdata.total = userdata.total + farg.value
    userdata.stamp = 0
    return farg.value
  end
  return 0
end
function spigot(farg)
  local a = abs(time() / 60)
  local b = abs(userdata.stamp / 60)
  if (a == b) then
    -- 1 SHC / minute --
    return 0
  end
  if (userdata.total >= 1) then
    send(farg.sender, 1)
    userdata.stamp = time()
    return 1
  end
  return 0
end
function init(farg)
  userdata.owner = farg.sender
  userdata.total = 0
  userdata.donate = donate
  userdata.spigot = spigot
  return 0
end
```

<h4>Coin Exchange Offers</h4>
A de-centralized exchange is provided in order to swap "color alt-chain coins" with SHC coins.



Client Utility Program
===============================

Run "shc help" to list command-line arguments:

Sending and receiving a funds transfer transaction:
```
shc wallet.new test
shc wallet.listaddr test
```

Send 1 SHC to address generated:
```
shc wallet.balance test
shc wallet.new test2
shc wallet.send test S9cXrHRUoDSJdNvBANSUVPKrMxCWGxHMuH 0.9998
```

Wait for transaction to be committed to a block:
```
shc wallet.unspent test
shc wallet.balance test2
```

Windows Build Instructions
====

In order to build the ShionCoin service download the MSYS2 64-bit build environment from "http://msys2.org/".
Note: The ShionCoin service is a 64-bit program, and therefore requires the "64-bit" version of MSYS2.

Open a MSYS2 command consolie window and run the following to install some basic development packages:
	pacman -S autoconf automake gcc openssl openssl-devel git doxygen

Create a "release" directory where the share coin programs will be stored. The can be ran outside of the MSYS environment.
	mkdir ~/shc_bin

Copy the dependant DLLs for MSYS2 that will be required to the the service and utility programs:
	cp /usr/bin/msys-2.0.dll ~/shc_bin
	cp /usr/bin/msys-gcc_s-seh-1.dll ~/shc_bin


** Share Runtime Library **

Download and install the libshare library:
	git clone https://github.com/neonatura/share ./libshare
	mkdir libshare/build
	cd libshare/build
	../configure --sbindir=/usr/bin --bindir=/usr/bin --libdir=/usr/lib
	make
	make install

Note: The library will automatically be downloaded and built under the default build ruleset for shioncoin.

** Boost C++ Runtime Library **

Download the boost source code from "http://www.boost.org/".

Open a MSYS2 command console window and run the following from where boost was extracted:
./bootstrap.sh gcc
./b2 toolset=gcc
cp -fr stage/lib/*.a /usr/lib
cp -fr stage/lib/*.dll ~/shc_bin
mkdir -p /usr/include/boost
find libs | grep "/include/boost$" | while read a; do cp -fr $a/* /usr/include/boost; done 



** ShionCoin Installation **

From the shioncoin build directory, copy the service and executables to the temporary release directory:
	cp ~/bin/shcoind.exe ~/shc_bin
	cp ~/bin/shc.exe ~/shc_bin

Note: This directory is typically located at "C:\msys64\home\<username>\shc_bin\" under the windows directory hierarchy.

Note: If you experience any autoconf compatibility issues (i.e. an error occurs while building) try running "./autogen.sh" in the root source code directory in order to remake the "configure" script based on your own platform environment.

You can optionally install the shcoind.exe program as a service:
	shcoind.exe --install
Note: The "shcoind.exe" must run as the same user when running the "shc.exe" utility program in order to communicate.


