
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura 
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
 *
 *  @endcopyright
 */

#ifndef __SHPEER_H__
#define __SHPEER_H__


/**
 * @addtogroup libshare
 * @{
 */

/**
 * The local machine.
 */
#define SHNET_PEER_LOCAL 0

/**
 * A remote IPv4 network destination.
 */
#define SHNET_PEER_IPV4 1

/**
 * A remote IPv6 network destination.
 */
#define SHNET_PEER_IPV6 2

/**
 * A IPv4 network destination on the sharenet VPN.
 */
#define SHNET_PEER_VPN_IPV4 3

/**
 * A IPv6 network destination on the sharenet VPN.
 */
#define SHNET_PEER_VPN_IPV6 4

/**
 * Global network destination.
 */
#define SHNET_BROADCAST 5


/** 32bit hardware (i.e. not 64bit) */
#define SHARCH_32BIT (1 << 0)
/** linux */
#define SHARCH_LINUX (1 << 1)
/** win/doh */
#define SHARCH_WIN (1 << 2)
/** apple/mac */
#define SHARCH_MAC (1 << 3)
/** bsd/freebsd */
#define SHARCH_BSD (1 << 4)
/** sun os */
#define SHARCH_SUN (1 << 5)
/** (android) mips chipset */
#define SHARCH_MIPS (1 << 7)
/** (aix/4) big endian / network byte order */
#define SHARCH_BIGEND (1 << 7)



struct shpeer_addr_t {
  /** The definition AF_INET or AF_INET6. */
  uint16_t sin_family;
  /** The network byte order socket port. */
  uint16_t sin_port;
  /** The ipv4/ipv6 socket address. */
  uint32_t sin_addr[4];
  /** The ethernet hardware address associated with the socket peer.  */
  uint8_t hwaddr[6];
  uint8_t sin_proto;
  uint8_t _reserved_[1];
};
typedef struct shpeer_addr_t shpeer_addr_t;

struct shpeer_key_t
{
  /**
   * A key reference to the peer's public identity.
   */
  shkey_t pub;

  /**
   * A key reference to the peer's priveleged identity.
   */
  shkey_t priv;
};
typedef struct shpeer_key_t shpeer_key_t;

/**
 * A local or remote reference to a libshare runtime enabled application.
 * @manonly
 * See the libshare_net.3 API man page for ESP protocol network operations.
 * @endmanonly
 * @note Addresses are stored in network byte order.
 */
struct shpeer_t 
{
  /**
   * A IP 4/6 network address
   */
  shpeer_addr_t addr;

  /**
   * A label identifying a perspective view of the peer.
   */
  char label[16];

  /**
   * A label identifying a sub-group of this peer.
   */
  char group[16];

  /**
   * The client user ID that is associated with the peer.
   */
  uint32_t uid;

  /**
   * Architecture of local machine for private key generation.
   */
  uint32_t arch;

  /**
   * A SHNET_PEER_XX type
   */
  uint32_t type;

  /**
   * Key references to this peer.
   */
  shpeer_key_t key;
};

/**
 * A local or remote network address.
 */
typedef struct shpeer_t shpeer_t;


/** public key reference of peer */
#define shpeer_kpub(_peer) \
  (& (_peer)->key.pub)

/** priveleged key reference of peer */
#define shpeer_kpriv(_peer) \
  (& (_peer)->key.priv)

/**
 * Set the application's default peer reference. 
 * @see shapp_init()
 */ 
void shpeer_set_default(shpeer_t *peer);

/**
 * Returns the default peer reference to the local user for IPv4.
 * @returns Information relevant to identifying a peer host.
 * @note Use shpeer_free() to free resources allocated.
 */
shpeer_t *shpeer(void);


/**
 * Returns the default peer reference to the local user for IPv4 without dynamic memory allocation..
 * @returns Information relevant to identifying a peer host.
 * @note Do NOT use shpeer_free() to free.
 */
shpeer_t *ashpeer(void);

/**
 * Generate a peer reference.
 * @param appname An application name an optional group name in "[<group>@]app" format or NULL for a un-named generic "libshare" app.
 * @param hostname A host and optional port in "<host>[:<port>]" format or NULL for a localhost reference.
 * @returns A peer identity reference.
 * @note Use shpeer_free() to free.
 */
shpeer_t *shpeer_init(char *appname, char *hostname);

/**
 * Free the resources associated with a peer reference.
 */
void shpeer_free(shpeer_t **peer_p);

/**
 * A string representation of the libshare peer.
 */
char *shpeer_print(shpeer_t *peer);

/**
 * Test whether a peer identity is referencing localhost.
 * @returns TRUE if a localhost and FALSE if not.
 */
int shpeer_localhost(shpeer_t *peer);

/**
 * Obtain a label referencing the peer entity.
 */
char *shpeer_get_app(shpeer_t *peer);

void shpeer_host(shpeer_t *peer, char *hostname, int *port_p);

struct sockaddr *shpeer_addr(shpeer_t *peer);

/**
 * @}
 */

#endif /* ndef __SHPEER_H__ */

