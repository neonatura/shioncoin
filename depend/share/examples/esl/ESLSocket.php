<?php

class ESLSocket
{

	public static $ESL_MAGIC = 0x2222;

	public static $ESL_VERSION = 4;

	public static $ESL_FLAGS = 0;

	public static $ESL_DATA = 0;
	public static $ESL_INIT_CERT = 2;
	public static $ESL_INIT_PRIV = 3;

	private static $op = 0xffffffff;

	public $eslkey;

	public $sock;

	public $error;

	public $inbuff;

	public $outbuff;

	public function __construct()
	{
		$this->eslkey = null;
		$this->sock = null;
		$this->error = null;
		$this->inbuff = "";
		$this->outbuff = "";
	}

	public function SetKey($eslkey = "")
	{
		if (strlen($eslkey) != 16) {
			$eslkey = pack("L", rand());
			$eslkey .= pack("L", rand());
			$eslkey .= pack("L", rand());
			$eslkey .= pack("L", rand());
		}
		$this->eslkey = $eslkey;
	}

	public function Connect($host_name, $host_port)
	{

		$sk = socket_create(AF_INET, SOCK_STREAM, 0);
		if (!$sk)
			return (false);

		socket_set_option($sk, SOL_SOCKET, SO_SNDTIMEO, array('sec' => 4, 'usec' => 0));
    socket_set_option($sk, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 4, 'usec' => 0));

		if (!@socket_connect($sk, $host_name, $host_port)) {
			socket_close($sk);
			return (false);
		}
		$this->sock = $sk;

		if (!$this->Control(self::$ESL_INIT_CERT, $this->eslkey)) {
			socket_close($sk);
			$this->sock = null;
			return (false);
		}

		return (true);
	}

	public function Close()
	{
		socket_close($this->sock);
	}

	public function GetError()
	{
		return ($this->error);
	}

	public function Poll()
	{

		if ($this->sock == null)
			return (false);

		$data = @socket_read($this->sock, 65536);//, PHP_NORMAL_READ);
		if (!$data || strlen($data) == 0)
			return (false);

		$this->inbuff .= $data;
		return (true);
	}

	public function Receive()
	{

		if ($this->sock == null)
			return (null);

		$this->Poll();

		do {
			if (strlen($this->inbuff) < 8)
				break;

			$magic = $this->uint16($this->inbuff);
			$mode = $this->uint16(substr($this->inbuff, 2));

			if ($magic != self::$ESL_MAGIC) {
				$this->Close();
				return (null);
			}

			if ($mode == self::$ESL_DATA) {
				$len = $this->uint16(substr($this->inbuff, 6));
				if (strlen($this->inbuff) < (8 + $len))
					break; /* not ready */

				return ($this->DecryptInputBuffer($len));
			}

			if (strlen($this->inbuff) < 24)
				break; /* not ready */

			$this->TrimInputBuffer(24);
		} while ($this->Poll() || strlen($this->inbuff) >= 8);

		return ("");
	}

	public function Flush()
	{

		if ($this->sock == null)
			return (false);

		if (strlen($this->outbuff) == 0)
			return (false);

		$len = socket_write($this->sock, $this->outbuff);
		if ($len) {
			$this->TrimOutputBuffer($len);
		}

		return (true);
	}

	public function Send($data)
	{

		if ($this->sock == null)
			return (false);

		$this->EncryptOutputBuffer($data);

		if (!$this->Flush())
			return (false);

		return (true);
	}

	public function Control($mode, $eslkey)
	{

		$hdr = "";
		$hdr .= $this->uint16(self::$ESL_MAGIC);
		$hdr .= $this->uint16($mode);
		$hdr .= $this->uint16(self::$ESL_VERSION);
		$hdr .= $this->uint16(self::$ESL_FLAGS);
		$hdr .= $eslkey;

		if (!socket_write($this->sock, $hdr))
			return (false);
		
		return (true);
	}

	public function EncryptOutputBuffer($data)
	{

		$of = 0;
		$b_len = 0;

		$data_len = strlen($data);
		for (; $of < $data_len; $of += $b_len) {
			$b_len = min(65536, ($data_len - $of));

			$enc_len = floor(($b_len + 7) / 8) * 8;
			$blocks = $enc_len / 8;
			$enc_data = "";

			$enc_data .= $this->uint16(self::$ESL_MAGIC);
			$enc_data .= $this->uint16(self::$ESL_DATA);
			$enc_data .= $this->Checksum($data);
			$enc_data .= $this->uint16($b_len);

			$i = 0;
			for (; $i < $blocks; $i++) {
				$enc_data .= $this->EncryptBlock(substr($data, $of + ($i * 8), 8));
			}

			$this->outbuff .= $enc_data;
		}

	}

	public function DecryptInputBuffer($data_len)
	{

		$dec_len = floor(($data_len + 7) / 8) * 8;
		$blocks = $dec_len / 8;

		$i = 0;
		$enc_data = "";
		for (; $i < $blocks; $i++) {
			$enc_data .= $this->DecryptBlock(substr($this->inbuff, 8 + ($i * 8), 8));
		}

		$this->TrimInputBuffer(8 + $dec_len);

		return ($enc_data);
	}

	public function Checksum($data)
	{
		$b = 0;
		$d = 0;
		$a = 1;
		$c = 1;

		if ($data) {
			$idx = 0;
			$data_len = strlen($data);
			for (; $idx < $data_len; $idx += 4) {
				$seg = substr($data, $idx);
				while (strlen($seg) < 4)
					$seg .= chr(0);

				$ival = unpack("L", $seg);
				$ival = is_array($ival) ? $ival[1] : $ival;
				$cval = unpack("C", $seg);
				$cval = is_array($cval) ? $cval[1] : $cval;

				$a = ($a + $ival) & 0xFFFFFFFF;
				$b = ($b + $a) & 0xFFFFFFFF;
				$c = ($c + $cval) % 65521;
				$d = ($d + $c) % 65521;
			}
		}

		$ret_val = (($d << 16) | $c);
		$ret_val += (($b << 32) | $a);

		/* convert to big-endian 2b binary segment. */
		$ret_val = $ret_val & 0xFFFF;
		$ret_data = pack("n", $ret_val); /* htons */
		return ($ret_data);
	}

	public function EncryptBlock($in_data)
	{
		$delta = 0x9e3779b9;
		$sum = 0;
		$i = 0;

		while (strlen($in_data) < 8)
			$in_data .= chr(0);

		$v0 = unpack("L", $in_data); $v0 = $v0[1];
		$v1 = unpack("L", substr($in_data, 4)); $v1 = $v1[1];

		$k0 = unpack("L", $this->eslkey); $k0 = $k0[1];
		$k1 = unpack("L", substr($this->eslkey, 4)); $k1 = $k1[1];
		$k2 = unpack("L", substr($this->eslkey, 8)); $k2 = $k2[1];
		$k3 = unpack("L", substr($this->eslkey, 12)); $k3 = $k3[1];

		for (; $i < 32; $i++) {
			$sum += $delta;

			$v0 += (self::$op & ($v1 << 4)) + $k0 ^ $v1 + $sum ^ (self::$op & ($v1 >> 5)) + $k1;
			$v0 &= self::$op;

			$v1 += (self::$op & ($v0 << 4)) + $k2 ^ $v0 + $sum ^ (self::$op & ($v0 >> 5)) + $k3;
			$v1 &= self::$op;
		}

		$ret_data = pack("L", $v0);
		$ret_data .= pack("L", $v1);
		return ($ret_data);
	}

	public function DecryptBlock($in_data)
	{
		$delta = 0x9e3779b9;
		$sum = 0xC6EF3720;
		$i = 0;

		$v0 = unpack("L", $in_data); $v0 = $v0[1];
		$v1 = unpack("L", substr($in_data, 4)); $v1 = $v1[1];

		$k0 = unpack("L", $this->eslkey); $k0 = $k0[1];
		$k1 = unpack("L", substr($this->eslkey, 4)); $k1 = $k1[1];
		$k2 = unpack("L", substr($this->eslkey, 8)); $k2 = $k2[1];
		$k3 = unpack("L", substr($this->eslkey, 12)); $k3 = $k3[1];

		for (; $i < 32; $i++) {

			$v1 -= (($v0 << 4) + $k2) ^ ($v0 + $sum) ^ (($v0 >> 5) + $k3);
			$v1 &= self::$op;

			$v0 -= (($v1 << 4) + $k0) ^ ($v1 + $sum) ^ (($v1 >> 5) + $k1);
			$v0 &= self::$op;

			$sum -= $delta;
			$sum &= self::$op;
		}


		$ret_data = pack("L", $v0);
		$ret_data .= pack("L", $v1);
		return ($ret_data);
	}

	function TrimOutputBuffer($trim_len)
	{
		$this->outbuff = substr($this->outbuff, $trim_len);
	}

	function TrimInputBuffer($trim_len)
	{
		$this->inbuff = substr($this->inbuff, $trim_len);
	}

	function uint16($i)
	{
		$f = is_int($i) ? "pack" : "unpack";
    $i = $f("n", $i);
		return is_array($i) ? $i[1] : $i;
  }

}

$sk = new ESLSocket();
$sk->SetKey();

#$text = "01234567";
#$enc_data = $sk->EncryptBlock($text);
#printf ("ENC: " . $enc_data . "\n");
#$dec_data = $sk->DecryptBlock($enc_data);
#printf ("DEC: " . $dec_data . "\n");

if (!$sk->Connect("localhost", 48981))
	exit(1);

$pl = "This is a sentence.";
$pl_len = strlen($pl);

# send size of payload.
$lenb = pack("N", $pl_len);
if (!$sk->Send($lenb))
	exit(1);

# send payload.
if (!$sk->Send($pl))
	exit(1);

sleep(1);

$reply = $sk->Receive();
if ($reply == null)
	exit(1);

printf ("REPLY: " . $reply . "\n");

$sk->Close();

?>
