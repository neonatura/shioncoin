share-coin
==========

<h4>Part of the Share Library Suite.</b>

<h3>Stratum + SHC + USDe Coin Service</h3>
The SHC and USDE virtual currency coin services, and a stratum service to handle mining, is embedded into the shc and usde coin services via the program "shcoind". The "shc" and "usde" client programs are provided to perform RPC commands against their respective coin services.

Note: No daemon or utility programs from the share library suite is required in order to run the coin+stratum service. The C share library is staticly linked against the coin services, and a 'make install' is not required to run the program.

The stratum service utilizes supplemental methods that are not standard, and require a compatible API client for full usage. 


<h3>Build Dependencies</h3>

The c++ boost shared library is required.  To be specific, the "system", "filesystem", "program_options", and "thread" boost libraries. The "shcoind" and "shcoin" programs are the only sharelib program that link against boost libraries.
To install on linux run 'yum install libboost*' or 'apt-get install libboost*'.

The 'openssl version 1.0.1g' distribution has been included in the directory '/src/share-ssl-lib'. This version will automatically be compiled and linked against the shcoind and shcoin programs. The Open SSL library is used for RPC protocol communication between the shcoind daemon and shcoin utility program.

The GMP library is required.  In order to install the GMP library;
Run "yum install gmp-devel" on CentOS.
Run "apt-get install libgmp-dev" on Ubuntu.
Run "pacman -S libgmp-devel" from MSYS2 64-bit.

<h2>SHC Specifications</h2>
The share-coin is unique in that it allows for additional types of transactions than regular coin transfers. Examples of these capabilities include exchanging coins between currencies, providing certified licenses for custom use, and assigning names to otherwise hard to remember hash tags. Compatibilty with the 'share library' file-system and network providing methods to utilize SHC block-chain transactions via external programs.
 
The shcoind SHC coin server recalcultes the block difficulty rate every block using the Kimoto Gravity Well algorythm. The target duration for blocks is one minute.

A maximum of 1 Billion SHC coins will be generated. The reward life-time is expected to continue for around 40 years (~ 2055).  

SHC Server Port: 24104

Stratum Port: 9448

The SHC network requires 1 confirmation per transaction.

The SHC network block matures after 60 confirmations.

<h2>USDe Specifications</h2>
The shcoind USDe coin server recalcultes the block difficulty rate every block using the Kimoto Gravity Well algorythm. The target duration for blocks is one minute.

A maximum of 1.6Billion USDe will be generated. Block reward halves every 130,000 blocks. The current money supply is estimated at 1.12 billion coins in circulation.

USDE Server Port: 54449

Stratum Port: 9448

The USDE network requires 5 confirmations per transaction.

The USDE network block matures after 100 confirmations.


<h2>Quick Instructions</h2>

64-bit Cent-OS: Add '--libdir=/usr/local/lib64' as configure command-line option

Building the share library:
<i><small><pre>
  git clone https://github.com/neonatura/share libshare
  cd libshare
  ./configure
  make
  make install
</pre></small></i>

Building the share-coin programs:
<i><small><pre>
  git clone https://github.com/neonatura/share-coin
  cd share-coin
  ./configure --with-libshare=../libshare
  make
  make install
</pre></small></i>

The binaries can be found under src/share-coin as "shc", "usde", and "shcoind". Performing a 'make install' will install these programs into the bin and sbin directories respectively. The "shc" and "usde" programs must be ran as the same user as the "shcoind" daemon. The daemons supplied with the share library suite (shared, shlogd, shfsyncd) and base libraries can be installed by running 'make install' in the libshare directory built from the instructions above. 

When installed on a unix-like systems that supports the traditional /etc/init.d/rc.d/ hierarchy a 'shcoind' daemon will be registered with the system to load upon startup as the root user. 
Note: The client utility programs "shc" and "usde" must be ran as the same user as the 'shcoind' daemon.

The shcoind daemon and client programs store data in the "/var/lib/share/blockchain/" directory. These programs will not [automatically] attempt to read the contents of the traditional currency hierarchy (i.e. "~/.usde/"). Commands are provided in order to import or export in either a legacy and/or optimized manner for the entire block-chain, wallet transactions, and network peer addresses. No RPC access is permitted except via the local machine and only with the automatically generated rpc credentials (see "rpc.conf" file). 


Client Utility Program
===============================

Run "shc help" or "usde help" to list command-line arguments:

<small>
addmultisigaddress <nrequired> <'["key","key"]'> [account]

<br>peer.add <host>[:port]
<br><i>Attempt to connect to a USDE server at the network destination specified.</i>

wallet.export <destination>

createrawtransaction [{"txid":txid,"vout":n},...] {address:amount,...}

decoderawtransaction <hex string>

wallet.key <address>

getaccount <address>

getaccountaddress <account>

getaddressesbyaccount <account>

getbalance [account] [minconf=1]

block.get <hash>

getblockcount

block.hash <index>

getblocktemplate [params]

getconnectioncount

block.difficulty

block.info

net.info

getnetworkhashps [blocks]

wallet.new

peer.info

getrawmempool

tx.get <txid> [verbose=0]

getreceivedbyaccount <account> [minconf=1]

getreceivedbyaddress <address> [minconf=1]

getwork [data]

getworkex [data, coinbase]

help [command]

wallet.importkey <privkey> <account>

keypoolrefill

wallet.accounts [minconf=1]

listreceivedbyaccount [minconf=1] [includeempty=false]

listreceivedbyaddress [minconf=1] [includeempty=false]

listsinceblock [blockhash] [target-confirmations]

listtransactions [account] [count=10] [from=0]

listunspent [minconf=1] [maxconf=999999]

wallet.move <fromaccount> <toaccount> <amount> [minconf=1] [comment]

wallet.send <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]

sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]

sendrawtransaction <hex string>

sendtoaddress <address> <amount> [comment] [comment-to]

setaccount <address> <account>

setmininput <amount>

settxfee <amount>

signmessage <address> <message>

signrawtransaction <hex string> [{"txid":txid,"vout":n,"scriptPubKey":hex},...] [<privatekey1>,...] [sighashtype="ALL"]

shutdown

validateaddress <address>

verifymessage <address> <signature> <message>
</small>



<h3>Stratum Protocol Template</h3>
<br>Command: mining.ping
<br>Description: Verify or measure server response time.
<br>Example Request: {"method":"mining.ping","id":1,"params":[]}
<br>Example Response: {"id":1,"error":null,"result":null}
<br>
<br>Command: mining.shares
<br>
<br>Command: mining.get_transactions
<br>
<br>Command: mining.info
<br>
<br>Command: mining.authorize
<br>
<br>Command: mining.submit
<br>
<br>Command: mining.subscribe
<br>
<br>Command: block.info[mode,hash]
<br>Description: Obtain block and transaction info from a block hash.
<br>
<br>Command: account.info[account,pkey]
<br>Description: Obtain account credentials by name and account key.
<br>
<br>Command: account.create[label]
<br>
<br>Command: account.transactions[amount,pkey,duration]
<br>
<br>Command: account.address[hash]
<br>
<br>Command: account.secret[addr,pkey]
<br>
<br>Command: account.import[account,priv addr]
<br>
<br>Command: account.transfer[account,pkey,addr,amount]



Windows Build Instructions
====

In order to build the Share Coin service download the MSYS2 64-bit build environment from "http://msys2.org/".
Note: The Share Coin service is a 64-bit program, and therefore requires the "64-bit" version of MSYS2.

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


** Boost C++ Runtime Library **

Download the boost source code from "http://www.boost.org/".

Open a MSYS2 command console window and run the following from where boost was extracted:
./bootstrap.sh gcc
./b2 toolset=gcc
cp -fr stage/lib/*.a /usr/lib
cp -fr stage/lib/*.dll ~/shc_bin
mkdir -p /usr/include/boost
find libs | grep "/include/boost$" | while read a; do cp -fr $a/* /usr/include/boost; done 



** Share Coin Installation **

From the share-coin build directory, copy the service and executables to the temporary release directory:
	cp ~/bin/shcoind.exe ~/shc_bin
	cp ~/bin/shc.exe ~/shc_bin

Note: This directory is typically located at "C:\msys64\home\<username>\shc_bin\" under the windows directory hierarchy.

Note: If you experience any autoconf compatibility issues (i.e. an error occurs while building) try running "./autogen.sh" in the root source code directory in order to remake the "configure" script based on your own platform environment.

You can optionally install the shcoind.exe program as a service:
	shcoind.exe --install
Note: The "shcoind.exe" must run as the same user when running the "shc.exe" utility program in order to communicate.

