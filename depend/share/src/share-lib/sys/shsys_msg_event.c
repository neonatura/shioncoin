

#include "share.h"

/*
 *
 */

/**
 * A generic 'libshare system message queue operation' function.
 */
typedef void (*shmsg_event_f)(shpeer_t *peer, void *data, size_t data_len);

/**
 * An array of callback functions performed in response to incoming message queue data or called for outgoing message operations.
 */
typedef struct shmsg_event_t
{
  shmsg_event_f op_app;
  shmsg_event_f op_bond;
  shmsg_event_f op_account;
  shmsg_event_f op_metric;
  uint32_t in_tot;
  uint32_t out_tot;
} shmsg_event_t;

