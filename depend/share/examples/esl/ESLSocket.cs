
/*
 *  Copyright 2020 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

public class ESLSocket
{

	public const ProtocolType SOCKET_TYPE = ProtocolType.Tcp;

	public const ushort ESL_MAGIC = 0x2222;

	public const ushort ESL_VERSION = 2;

	public const ushort ESL_DATA = 0;

	public const ushort ESL_INIT_CERT = 2;

	public const ushort ESL_INIT_PRIV = 3;

	public const ushort ESL_FLAGS = 0;

	protected Socket socket;

	protected byte[] host_key;

	protected UInt32[] tea_key;

	/* an error message */
	protected string _error;

	/* socket output buffer */
	List<byte> outbuff = new List<byte>();

	/* socket input buffer */
	List<byte> inbuff = new List<byte>();

	public ESLSocket(byte[] host_key)
	{
		SetKey(host_key);
	}

	public ESLSocket()
	{
		SetKey(null);
	}

	/* Essentially a five-stage handshake when used with TCP. */
	public bool Connect(string host_name, int host_port)
	{

		try {
			socket = new Socket(AddressFamily.InterNetwork,
					SocketType.Stream, SOCKET_TYPE);
			socket.Connect(host_name, host_port);
		} catch (SocketException sk_err) {
			_error = sk_err.ToString();
			return (false);
		}

		/* send ESL_INIT_PRIV control message. */
		if (!ESLControl(ESL_INIT_CERT, GetKey()))
			return (false);

		return (true);
	}

	public string GetError()
	{
		return (_error);
	}

	public void Close()
	{
		socket.Close();
		socket = null;
	}

	public bool IsConnected()
	{

		if (socket != null && socket.Connected)
			return (true);

		return (false);
	}

	public bool HasAvailable()
	{
		if (!IsConnected())
			return (false);
		return (socket.Available != 0);
	}

	public bool Poll()
	{
		byte[] buffer = new byte[65536];

		try {
			int bytes = socket.Receive(buffer, 65536, 0);
			for (int i = 0; i < bytes; i++)
				inbuff.Add(buffer[i]);
		} catch (SocketException sk_err) {
			_error = sk_err.ToString();
			return (false);
		}

		return (true);
	}

	public byte[] Receive()
	{

		if (!IsConnected())
			return (null);

		do {
			if (socket.Available > 0) {
				if (!Poll())
					return (null);
			}

			if (inbuff.Count < 8)
				break;

			byte[] buff = inbuff.ToArray();
			ushort[] hdr = new ushort[4];
			Buffer.BlockCopy(buff, 0, hdr, 0, 8);
			int mode = ntohs(hdr[1]);

			if (hdr[0] != ESL_MAGIC) {
				/* invalid state */
				Close();
				return (null);
			}

			if (mode == ESL_DATA) {
				int len = ntohs(hdr[3]); 

				if (buff.Length < (8 + len))
					break;

				return (DecryptInputBuffer(len));
			}

			if (inbuff.Count < 24)
				break;

			TrimInputBuffer(24);
		} while (socket.Available > 0 || inbuff.Count > 0);

		return (new byte[0]);
	}

	public string RecvText()
	{
		byte[] data = Receive();
		return (Encoding.ASCII.GetString(data, 0, data.Length));
	}

	public bool Flush()
	{
		int bytes;

		try {
			if (outbuff.Count > 0) {
				byte[] buff = outbuff.ToArray();
				bytes = socket.Send(buff, buff.Length, 0);
				TrimOutputBuffer(bytes);
			}
		} catch (SocketException sk_err) {
			_error = sk_err.ToString();
			return (false);
		}

		return (true);
	}

	public bool Send(byte[] buffer)
	{

		if (!IsConnected())
			return (false);

		EncryptOutputBuffer(buffer);

		if (!Flush())
			return (false);

		return (true);
	}

	public bool SendText(string text)
	{
		byte[] buffer = Encoding.ASCII.GetBytes(text);
		return (Send(buffer));
	}

	public byte[] GetKey()
	{
		return (host_key);
	}

	/* Utilizes the first 32 bytes of the key or creates a random one if no key is provided. */
	public void SetKey(byte[] key)
	{
		int len;

		host_key = new byte[16];

		len = 0;
		if (key != null)
			len = Math.Min(key.Length, 16);

		if (len == 0) {
			/* random generated */
			(new Random()).NextBytes(host_key);
		} else {
			/* user-specified */
			Buffer.BlockCopy(key, 0, host_key, 0, len);
		}

		/* 128-bit TEA encryption */
		tea_key = new uint[4];
		Buffer.BlockCopy(host_key, 0, tea_key, 0, 16);
	}

	public string PrintKey()
	{
		return (BitConverter.ToString(host_key).Replace("-","").ToLower());
	}

	public bool ESLControl(int mode, byte[] key)
	{
		byte[] buffer = new byte[24];
		ushort[] vals = new ushort[4];

		vals[0] = ESL_MAGIC;
		vals[1] = htons((ushort)mode);
		vals[2] = htons(ESL_VERSION);
		vals[3] = ESL_FLAGS;
		Buffer.BlockCopy(vals, 0, buffer, 0, 8);
		Buffer.BlockCopy(host_key, 0, buffer, 8, 16);

		try
		{
			socket.Send(buffer, buffer.Length, 0);
		} catch (SocketException sk_err) {
			_error = sk_err.ToString();
			return (false);
		}

		return (true);
	}

	/* encrypt binary data onto output socket buffer. */
	public void EncryptOutputBuffer(byte[] data)
	{
		ushort[] d_hdr;
		int blocks;
		int enc_len;
		int b_len;
		int b_of;

		b_len = 0;
		for (b_of = 0; b_of < data.Length; b_of += b_len) {
			b_len = Math.Min(65536, (data.Length - b_of));

			enc_len = (int)((b_len + 7) / 8) * 8;
			blocks = enc_len / 8;
			byte[] enc_data = new byte[enc_len + 8];

			/* esl data header (8b) */
			d_hdr = new ushort[4];
			d_hdr[0] = ESL_MAGIC;
			d_hdr[1] = htons(ESL_DATA);
			d_hdr[2] = Checksum(data, b_of, b_len); /* decrypted data crc */
			d_hdr[3] = htons((ushort)b_len); /* decrypted data length */
			Buffer.BlockCopy(d_hdr, 0, enc_data, 0, 8);

			/* encrypted data payload */
			UInt32[] v = new UInt32[blocks * 2];
			Buffer.BlockCopy(data, b_of, v, 0, b_len);
			for (int i = 0; i < blocks; i++)
				TEA_EncryptBlock(ref v, i*2, tea_key);
			Buffer.BlockCopy(v, 0, enc_data, 8, enc_len);

			for (int i = 0; i < enc_data.Length; i++)
				outbuff.Add(enc_data[i]);
		}	

	}

	public byte[] DecryptInputBuffer(int data_len)
	{
		byte[] data = inbuff.ToArray();
		int dec_len;
		int blocks;

		dec_len = (int)((data_len + 7) / 8) * 8;
		blocks = dec_len / 8;

		UInt32[] v = new UInt32[blocks * 2];
		Buffer.BlockCopy(data, 8, v, 0, blocks * 8);
		for (int i = 0; i < blocks; i++) {
			TEA_DecryptBlock(ref v, i*2, tea_key);
		}

		TrimInputBuffer(8 + dec_len);

		byte[] dec_data = new byte[data_len];
		Buffer.BlockCopy(v, 0, dec_data, 0, data_len);
		return (dec_data);
	}

	public void TrimInputBuffer(int trim_len)
	{
		byte[] buff = inbuff.ToArray();
		byte[] new_buff;
		int len;
		int of;

		len = Math.Max(0, inbuff.Count - trim_len);
		of = inbuff.Count - len;
		new_buff = new byte[len]; 

		Buffer.BlockCopy(buff, of, new_buff, 0, len);
		inbuff = new List<byte>(new_buff);
	}

	public void TrimOutputBuffer(int trim_len)
	{
		byte[] buff = outbuff.ToArray();
		byte[] new_buff;
		int len;
		int of;

		len = Math.Max(0, outbuff.Count - trim_len);
		of = outbuff.Count - len;
		new_buff = new byte[len]; 

		Buffer.BlockCopy(buff, of, new_buff, 0, len);
		outbuff = new List<byte>(new_buff);
	}

	static public ushort Checksum(byte[] data, int data_of, int data_len)
	{
		UInt64 b = 0;
		UInt64 d = 0;
		UInt32 a = 1, c = 1;
		UInt64 ret_val;
		int idx;

		if (data != null) {
			UInt32[] num_p = new UInt32[1];
			for (idx = 0; idx < data_len; idx += 4) {
				int cp_len = Math.Min(4, data_len - idx);
				num_p[0] = 0;
				Buffer.BlockCopy(data, data_of + idx, num_p, 0, cp_len);

				a = (a + num_p[0]);
				b = (b + a);
				c = (c + (UInt32)data[data_of+idx]) % 65521;
				d = (d + c) % 65521;
			}
		}

		ret_val = ((d << 16) | c);
		ret_val += ((b << 32) | a);
		return (htons((ushort)(ret_val & 0xFFFF)));
	}

	/* v is 8 bytes, k is 16 bytes */
	static public void TEA_EncryptBlock(ref UInt32[] v, int v_of, UInt32[] k)
	{
		const UInt32 delta=0x9e3779b9; /* a key schedule constant */
		UInt32 v0=v[v_of+0], v1=v[v_of+1], sum=0, i;           /* set up */
		UInt32 k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
		for (i=0; i < 32; i++) {                       /* basic cycle start */
			sum += delta;
			v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
			v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
		}                                              /* end cycle */
		v[v_of+0]=v0; v[v_of+1]=v1;
	}

	/* v is 8 bytes, k is 16 bytes */
	static public void TEA_DecryptBlock(ref UInt32[] v, int v_of, UInt32[] k)
	{
		const UInt32 delta=0x9e3779b9; /* a key schedule constant */
		UInt32 v0=v[v_of+0], v1=v[v_of+1], sum=0xC6EF3720, i;  /* set up */
		UInt32 k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
		for (i=0; i<32; i++) {                         /* basic cycle start */
			v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
			v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
			sum -= delta;
		}                                              /* end cycle */
		v[v_of+0]=v0; v[v_of+1]=v1;
	}

	static public ushort htons(ushort val)
	{
		return (ushort)System.Net.IPAddress.HostToNetworkOrder((short)val);
	}

	static public ushort ntohs(ushort val)
	{
		return (ushort)System.Net.IPAddress.NetworkToHostOrder((short)val);
	}

	static public UInt32 htonl(UInt32 val)
	{
		return (UInt32)System.Net.IPAddress.HostToNetworkOrder((int)val);
	}

	static public UInt64 htonll(UInt64 val)
	{
		return (UInt64)System.Net.IPAddress.HostToNetworkOrder((long)val);
	}

	static void Main()
	{
		const string TEST_TEXT = "This is a test message.";
		ESLSocket socket = new ESLSocket();
		Console.WriteLine("ESLSocket: initialized new ESL socket.");

		if (!socket.Connect("127.0.0.1", 48981)) {
			Console.WriteLine("ESLSocket: ERROR: connect to 127.0.0.1:48981.");
			return;
		}
		Console.WriteLine("ESLSocket: connected to 127.0.0.1:48981.");

		/* write message length. */
		byte[] len_b = new byte[4];
		UInt32[] len_ar = new UInt32[1];
		len_ar[0] = htonl((UInt32)TEST_TEXT.Length);
		Buffer.BlockCopy(len_ar, 0, len_b, 0, 4);
		if (!socket.Send(len_b)) {
			Console.WriteLine("ESLSocket: error writing test message length.");
			return;
		}

		/* write message content. */
		if (!socket.SendText(TEST_TEXT)) {
			Console.WriteLine("ESLSocket: error writing test message.");
			return;
		}
		Console.WriteLine("ESLSocket: wrote test message.");

		byte[] resp = socket.Receive();
		string converted = Encoding.UTF8.GetString(resp, 0, resp.Length);
		Console.WriteLine("ESLSocket: READ: " + converted);

		socket.Close();
	}

}

