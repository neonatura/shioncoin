
Create a new directory and copy the neccessary BaseXXX.lua files for the project. See ShareToken/ and ShareEvent directories for examples.

You can compile the project with the "sxc" program:

> sxc -o ShareToken.sx BaseObject.lua BaseToken.lua ShareToken.lua
> readsexe ./ShareToken.sx

Use the "test_run" program in order to ensure that all of the class methods are functioning properly. Use the "test_run.conf" to configure the parameters.

> ./test_run ./ShareToken.sx verify 
> ./test_run ./ShareToken.sx update
> ./test_run ./ShareToken.sx getSymbol
> ./test_run ./ShareToken.sx burn 10
> ./test_run ./ShareToken.sx balance

Publish the class onto the testnet network to fully test features:
> testnet block.mine 10240
<repeat above step as neccessary to generate coins>
> testnet exec.compile /src/share-coin/sexe/ShareToken/ShareToken.lua
> testnet exec.new "" ShareToken.sx 
"exec":	{
	"version":	1,
		"label":	"ShareToken",
		"expire":	"Aug  2 02:57:45 2066",
		"sender":	"SLWH9FV1snPzvfVunxRPJ417F8a98edRHJ",
		"hash":	"b32923a5beed58a8fc1048d71fec714d0405ae0d",
		"signature":	"a8d2d7ed3b49bc0bf4fb957be5223c9fc189ad27",
		"stack-size":	23545
}
> testnet block.mine
> testnet exec.run "" 1 ShareToken update
> testnet exec.run "" 0 ShareToken balance 

Once satisfied, publish the class on the main ShareCoin network by running "shc exec.compile" and "shc exec.new" commands.

> shc exec.new "sharetoken" ShareToken.sx 

