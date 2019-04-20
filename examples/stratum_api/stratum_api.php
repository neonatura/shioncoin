<?php
# php api.php
#
# Example php client for the ShionCoin stratum API service. 
#

class stratum_api
{

  public $host;
  public $port;
  public $req_id;
	public $iface;
	public $api_id;
	public $api_key;

  function __construct($host, $port, $iface, $api_id, $api_key)
  {
    $this->host = $host;
    $this->port = $port;
    $this->iface = $iface;
		$this->api_id = $api_id;
		$this->api_key = $api_key;

    $this->req_id = 0;
  }

  /* designed to be cached and fault-tolerant */
  function request($method, $data = array())
  {

    $sk = socket_create(AF_INET, SOCK_STREAM, 0);
    if (!$sk)
      return (FALSE);

		$return_data = FALSE;
    socket_set_option($sk, SOL_SOCKET, SO_SNDTIMEO, array('sec' => 4, 'usec' => 0));
    socket_set_option($sk, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 4, 'usec' => 0));
    if (@socket_connect($sk, $this->host, $this->port)) {
			$req = array();

			if (0 == strncmp($method, "api.", 4)) {
				$now = (int)time();
				$auth = array();
				$auth['API_ID'] = trim($this->api_id);
				$auth['API_KEY'] = trim($this->api_key);
				$auth['API_STAMP'] = $now;
				$auth['API_SIG'] = hash('sha256', json_encode($data).trim($now).$auth['API_ID']);
				$req['auth'] = $auth;
			}

      $req['method'] = $method;
      $req['id'] = ++$this->req_id;
      $req['params'] = $data;
      $req['iface'] = $this->iface;
      $out_json = json_encode($req) . "\n";
      socket_write($sk, $out_json);
      $return_data = socket_read($sk, 2048000, PHP_NORMAL_READ);
    }
    socket_close($sk);
    $json = @json_decode($return_data, true);
    if (!$json) {
      return (FALSE);
    }

    if (!is_array($json['result']))
			return ($json);

    return ($json['result']);
  }
}


#$acc_name = hash('sha1', trim(microtime(true)));
#$api = new stratum_api('localhost', 9448, 'testnet', $acc_name, "");
#$r = $api->request("api.account.create");
#print "ACCOUNT-CREATE: " . json_encode($r) . "\n";
#$r = $r['testnet']; /* coin interface */
#$r = array_pop($r); /* first record */
#$api_id = $r['api_id'];
#$api_key = $r['api_key'];

$api = new stratum_api('localhost', 9448, 'testnet',
		"378e6c4143a08b3637531410bd56f6ca04847fd2",
		"6dcf6c66fc81cc085c4a948dc197c1bd01d2ac2a81fcb12b7c3b8de07a9055af");

$r = $api->request("api.account.txlist");
print json_encode($r) . "\n";

$r = $api->request("api.account.addr");
print "ADDR: " . json_encode($r) . "\n";

$r = $api->request("api.account.secret");
print "SECRET: " . json_encode($r) . "\n";

$r = $api->request("api.account.unspent");
print "UNSPENT: " . json_encode($r) . "\n";

#$arg = array();
#$arg['amount'] = "1";
#$arg['address'] = "TULGtfJbJpDs5byeP4pPLvz8TFqbaX9BwK";
##$arg['address'] = "RxvQW6G5Bjn3rEwKWPh6YmGhrAs6RGYawR";
#$r = $api->request("api.account.send", $arg);
#print "SEND: " . json_encode($r) . "\n";

#$arg = array();
#$arg['amount'] = "1";
#$arg['address'] = "TULGtfJbJpDs5byeP4pPLvz8TFqbaX9BwK";
#$r = $api->request("api.account.bsend", $arg);
#print "BATCHSEND: " . json_encode($r) . "\n";

$arg = array();
$arg['amount'] = "1";
$arg['address'] = "TULGtfJbJpDs5byeP4pPLvz8TFqbaX9BwK";
$r = $api->request("api.account.tsend", $arg);
print "TESTSEND: " . json_encode($r) . "\n";


#$r = $api->request("api.cert.list");
#print "CERT: " . json_encode($r) . "\n";
#
#$r = $api->request("api.exec.list");
#print "EXEC: " . json_encode($r) . "\n";
#
#$r = $api->request("api.ident.list");
#print "IDENT: " . json_encode($r) . "\n";
#
#$r = $api->request("api.license.list");
#print "LICENSE: " . json_encode($r) . "\n";
#
#$r = $api->request("api.asset.list");
#print "ASSET: " . json_encode($r) . "\n";
#
#$r = $api->request("api.offer.list");
#print "OFFER: " . json_encode($r) . "\n";


$r = $api->request("api.validate.list");
print "VALIDATE: " . json_encode($r) . "\n";


#
#
#$arg = array("label" => "test", "address" => "TULGtfJbJpDs5byeP4pPLvz8TFqbaX9BwK"); 
#$r = $api->request("api.alias.set", $arg);
#print "ALIAS-SET: " . json_encode($r) . "\n";
#
#$arg = array("label" => "test");
#$r = $api->request("api.alias.get", $arg);
#print "ALIAS-GET: " . json_encode($r) . "\n";
#
#$r = $api->request("api.alias.list");
#print "ALIAS: " . json_encode($r) . "\n";
#
#
#
#$r = $api->request("api.context.list");
##print "CONTEXT: " . json_encode($r) . "\n";
##
#$r = $api->request("api.context.get", array("label" => "test"));
#print "CONTEXT-GET: " . json_encode($r) . "\n";
##
#$r = $api->request("api.context.get", array("hash" => "e96f4f37b1139a43606486e9eafd896a19fab31d"));
##print "CONTEXT-GET/hash: " . json_encode($r) . "\n";
##
#$r = $api->request("api.context.set", array("label" => "test", "value" => "test value"));
#print "CONTEXT-SET: " . json_encode($r) . "\n";
#

#$r = $api->request("api.faucet.send", array("amount" => "1"));
#print "FAUCET-SEND: " . json_encode($r) . "\n";
#
#$r = $api->request("api.faucet.recv");
#print "FAUCET-RECV: " . json_encode($r) . "\n";

#$r = $api->request("api.faucet.list");
#print "FAUCET-RECV: " . json_encode($r) . "\n";
#
#$r = $api->request("api.faucet.info");
#print "FAUCET-INFO: " . json_encode($r) . "\n";


$r = $api->request("api.alt.list");
print "ALT: " . json_encode($r) . "\n";

$r = $api->request("api.alt.get", array("label" => "share"));
print "ALT: " . json_encode($r) . "\n";

$r = $api->request("api.alt.block", array("hash" => "d552a9449cc29ec761adbca616262b7cd5b3ff2c4fd1afe1623f7b5329066dd5"));
print "ALT: " . json_encode($r) . "\n";


?>
