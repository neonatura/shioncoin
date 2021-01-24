
/*
 *  Copyright 2015 Neo Natura 
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

#include "share.h"

static esl_key *get_esl_key(int sk)
{
  uint8_t *raw;
  unsigned int usk;

	usk = (unsigned short)sk;
  if (usk >= USHORT_MAX)
    return (NULL);

	raw = (uint8_t *)&_sk_table[usk].key;
  return ((esl_key *)(raw + 4));
}

int esl_control(int sk, int mode, esl_key *key) 
{
  esl_t sec;
  unsigned int usk;
  int err;

	usk = (unsigned short)sk;
  if (usk >= USHORT_MAX)
    return (SHERR_BADF);

	/* prep esl packet header */
  memset(&sec, 0, sizeof(esl_t));
  sec.s_magic = SHMEM16_MAGIC;
  sec.s_ver = htons(SHNET_ENCRYPT_PROTO_VERSION);
  sec.s_mode = htons(mode);
  memcpy(&sec.s_key, key, sizeof(sec.s_key));

  /* append control to outgoing buffer */
  shnet_write_buf(sk, (unsigned char *)&sec, sizeof(sec));
}

/**
 * Initiate a secure connection.
 */
int esl_connect(char *hostname, int port, shkey_t *in_key)
{
	uint8_t t_eslkey[16];
	esl_key *eslkey;
  shpeer_t *peer;
  int sk;
  int err;

  sk = shconnect_host(hostname, port, SHNET_ASYNC);
  if (sk < 0)
    return (sk);

	eslkey = NULL;
	if (in_key)
		eslkey = (esl_key *)( ((uint8_t *)in_key) + 4 );

  if (!eslkey) {
		uint64_t val;

		memset(t_eslkey, 0, sizeof(t_eslkey));

		val = shrand();
		memcpy(t_eslkey, &val, sizeof(val));
		val = shrand();
		memcpy(t_eslkey + 8, &val, sizeof(val));

		eslkey = (esl_key *)&t_eslkey;
  }

  err = esl_control(sk, ESL_INIT_CERT, eslkey);
  if (err) {
    return (err);
	}

	{
		shkey_t *p_key = &_sk_table[sk].key;
		memset(p_key, 0, sizeof(shkey_t));
		if (in_key)
			memcpy(p_key, in_key, sizeof(shkey_t));
		memcpy((uint8_t *)p_key + 4, eslkey, 16);
	}

  return (sk);
}

int esl_write_data(int sk, unsigned char *data, size_t data_len)
{
	static unsigned char pkt[65536];
  esl_data_t hdr;
  ssize_t w_len;
  size_t b_len;
  size_t b_of;
  size_t raw_data_len;
  unsigned int usk = (unsigned int)sk;
	int enc_len;
  int err;

  if (usk >= USHORT_MAX)
    return (SHERR_BADF);

  w_len = 0;
	for (b_of = 0; b_of < data_len; b_of += b_len) {
		b_len = MIN(65536, (data_len - b_of));
		enc_len = (int)((b_len + 7) / 8) * 8;

		/* esl protocol data header */
		memset(&hdr, 0, sizeof(hdr));
		hdr.s_magic = SHMEM16_MAGIC;
		hdr.s_mode = htons(ESL_DATA);
		hdr.s_crc = ESL_CHECKSUM(data + b_of, b_len); /* crc of decoded data */ 
		hdr.s_size = htons(b_len); /* size of decoded data */
		shnet_write_buf(sk, (unsigned char *)&hdr, sizeof(hdr));

		/* encode data payload */
		memset(pkt, 0, enc_len);
		memcpy(pkt, data + b_of, b_len);
		TEA_encrypt_data(pkt, enc_len, (uint32_t *)get_esl_key(sk));
		shnet_write_buf(sk, pkt, enc_len);
	}

  return (0);
}

int esl_writeb(int sk, shbuf_t *wbuff)
{
  ssize_t len;

  len = esl_write(sk, shbuf_data(wbuff), shbuf_size(wbuff));
  if (len < 0)
    return (len);

  return (0);
}

ssize_t esl_write(int sk, const void *data, size_t data_len)
{
  unsigned int usk = (unsigned int)sk;
  int err;

  if (!(_sk_table[usk].flags & SHNET_CRYPT)) {
    esl_readb(sk, NULL);
  }
  if (!(_sk_table[usk].flags & SHNET_CRYPT)) {
    /* not initialized for ESL */
    return (SHERR_AGAIN);
  }

  err = esl_write_data(sk, (unsigned char *)data, data_len);
  if (err)
    return ((ssize_t)err);

  err = shnet_write_flush(sk);
  if (err)
    return (err);

  return ((ssize_t)data_len);
}

static int esl_read_ctrl(int sk, shbuf_t *rbuff)
{
  shkey_t *key;
  unsigned int usk;
  esl_t hdr;
  int err;

	usk = (unsigned short)sk;
  if (usk >= USHORT_MAX)
    return (SHERR_BADF);

  if (shbuf_size(rbuff) < sizeof(esl_t))
    return (SHERR_AGAIN);

  memcpy(&hdr, shbuf_data(rbuff), sizeof(esl_t));

	hdr.s_ver = ntohs(hdr.s_ver);
  if (hdr.s_ver < MIN_SHNET_ENCRYPT_PROTO_VERSION)
		return (SHERR_OPNOTSUPP);

  hdr.s_mode = ntohs(hdr.s_mode);
  if (hdr.s_mode == ESL_INIT_CERT) {
    /* this socket initiated the connection */
    shkey_t *p_key = &_sk_table[usk].key;

    if (shkey_cmp(p_key, ashkey_blank())) {
			/* use client's key */
			memcpy(&p_key->code, &hdr.s_key, sizeof(esl_key));
		} else {
			/* require client has server key. */
			if (0 != memcmp((uint8_t *)p_key + 4, &hdr.s_key, 16)) {
				/* client did not send pre-defined key for listen socket. */
				shnet_close(sk);
				return (SHERR_ACCESS);
			}
    }

		_sk_table[usk].flags |= SHNET_CRYPT;
  } else if(hdr.s_mode == ESL_INIT_PRIV) {
    /* receiver of public handshake. */
    _sk_table[usk].flags |= SHNET_CRYPT;
	}

  shbuf_trim(rbuff, sizeof(esl_t));
  return (0);
}

static int esl_read_data(int sk, shbuf_t *rbuff, shbuf_t *pbuff)
{
	static unsigned char pkt[65536];
  esl_data_t hdr;
  uint8_t *raw_data;
  unsigned int usk;
  size_t raw_data_len;
	size_t enc_len;
  int err;

	usk = (unsigned short)sk;
  if (usk >= USHORT_MAX)
    return (SHERR_BADF);

  if (shbuf_size(rbuff) < sizeof(esl_data_t))
    return (SHERR_AGAIN);

	/* esl data packet header */
  memcpy(&hdr, shbuf_data(rbuff), sizeof(hdr));
  hdr.s_size = ntohs(hdr.s_size);
	enc_len = (int)((hdr.s_size + 7) / 8) * 8; /* 8b boundary */
  if (shbuf_size(rbuff) < (enc_len + sizeof(esl_data_t)))
    return (SHERR_AGAIN); /* incomplete */
  shbuf_trim(rbuff, sizeof(hdr));

	/* decrypt data payload */
	memset(pkt, 0, enc_len);
	memcpy(pkt, shbuf_data(rbuff), enc_len);
	TEA_decrypt_data(pkt, enc_len, (uint32_t *)get_esl_key(sk));

  /* verify checksum */
  if (hdr.s_crc != ESL_CHECKSUM(pkt, hdr.s_size)) {
		/* invalid key */
    return (SHERR_ILSEQ);
  }

  /* clear incoming encoded segment. */
  shbuf_trim(rbuff, (size_t)enc_len);
  
  /* append to processed data buffer */
  shbuf_cat(pbuff, pkt, (size_t)hdr.s_size);

  return (0); 
}

int esl_readb(int sk, shbuf_t *in_buff)
{
  ssize_t b_len;
  shbuf_t *rbuff;
  unsigned char *rdata;
  uint16_t *hdr;
  unsigned int usk;
  int _data_read;
  int mode;
  int err;

  usk = (unsigned int)sk;
  if (usk >= USHORT_MAX)
    return (SHERR_BADF);

  if (in_buff != _sk_table[usk].proc_buff &&
      shbuf_size(_sk_table[usk].proc_buff) != 0) {
    /* pending data from esl_read() call */
    shbuf_append(_sk_table[usk].proc_buff, in_buff);
    shbuf_clear(_sk_table[usk].proc_buff);
  }

  _data_read = FALSE;
  while (1) {
    rbuff = shnet_read_buf(sk);
    if (!rbuff) {
      if (_data_read)
        break;
      return (SHERR_CONNRESET);
    }

    if (shbuf_size(rbuff) < 4)
      break;

    hdr = (uint16_t *)shbuf_data(rbuff);
    mode = (int)ntohs(hdr[1]);

    if (hdr[0] != SHMEM16_MAGIC) {
      shclose(sk);
      return (SHERR_ILSEQ);
    }

    err = 0;
    if (mode == ESL_DATA) {
      err = esl_read_data(sk, rbuff, in_buff);
      if (!err)
        _data_read = TRUE;
    } else {
      err = esl_read_ctrl(sk, rbuff);
    }
    if (err && err != SHERR_AGAIN) {
      PRINT_ERROR(err, "esl_readb"); 
      /* critical error in protocol */
      rbuff = shnet_read_buf(sk);
      if (rbuff)
        shbuf_clear(rbuff);
      shclose(sk);
      return (err);
    }
  }
   
  return (0);
}

ssize_t esl_read(int sk, const void *data, size_t data_len)
{
  shbuf_t *in_buff;
  unsigned short usk;
  ssize_t len;
  int err;

	usk = (unsigned short)sk;
  if (usk >= USHORT_MAX)
    return (SHERR_BADF);

  if (!_sk_table[usk].proc_buff)
    _sk_table[usk].proc_buff = shbuf_init();

  in_buff = _sk_table[usk].proc_buff;
  err = esl_readb(sk, in_buff);
  if (err)
    return (err);

  len = MIN(data_len, shbuf_size(in_buff));
  memcpy((void *)data, shbuf_data(in_buff), len);
  shbuf_trim(in_buff, len);

  return (len);
}

int esl_bind(int port)
{
  int err;
  int sk;

  sk = shnet_sk();
  if (sk < 0)
    return (sk);

  err = shnet_bindsk(sk, NULL, port); 
  if (err < 0) {
    close(sk);
    return (err);
  }

  return (sk);
}

int esl_bind_host(char *host, int port)
{
  int err;
  int sk;

  sk = shnet_sk();
  if (sk < 0)
    return (sk);

  err = shnet_bindsk(sk, host, port); 
  if (err < 0) {
    close(sk);
    return (err);
  }

  return (sk);
}

int esl_accept(int sk)
{
  shkey_t *key;
  unsigned short usk;
  int l_sk;
  int err;

  l_sk = shnet_accept(sk);
  if (l_sk < 0)
    return (errno2sherr());

  shnet_fcntl(l_sk, F_SETFL, O_NONBLOCK);

	usk = (unsigned short)l_sk;
  if (usk >= USHORT_MAX)
    return (SHERR_IO);

	/* inherit bound socket's key */
	memcpy(&_sk_table[usk].key, &_sk_table[sk].key, sizeof(shkey_t));

  err = esl_control(l_sk, ESL_INIT_PRIV, get_esl_key(l_sk));
  if (err)
    return (err);

  return (l_sk);
}

void esl_key_set(int sk, shkey_t *key)
{
  unsigned short usk;

	usk = (unsigned short)sk;
  if (usk >= USHORT_MAX)
    return;

  if (_sk_table[usk].flags & SHNET_LISTEN)
    return;

  memcpy(&_sk_table[usk].key, key, sizeof(shkey_t)); 
}

int esl_verify(int sk)
{
  unsigned int usk = (unsigned int)sk;
  fd_set write_set;
  fd_set read_set;
  long ms;
  int err;

  if (usk >= USHORT_MAX)
    return (SHERR_BADF);

  if (!(_sk_table[usk].flags & SHNET_CRYPT))
    esl_readb(sk, NULL);

  ms = 100;
  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  FD_SET(sk, &read_set);
  FD_SET(sk, &write_set);
  err = shnet_verify(&read_set, &write_set, &ms);

  if (err >= 0 && /* not an error */
      !FD_ISSET(sk, &read_set) && /* socket not marked */
      (shbuf_size(_sk_table[usk].recv_buff) != 0 ||
       shbuf_size(_sk_table[usk].proc_buff) != 0)) { /* pending incoming data */
    err++;
    FD_SET(sk, &read_set);
  }

  return (err);
}

