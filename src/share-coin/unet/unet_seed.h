

#ifndef __UNET_SEED_H__
#define __UNET_SEED_H__


#define USDE_SEED_LIST_SIZE 3
static char *usde_seed_list[USDE_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108", /* coin2.sharelib.net */
  "69.41.171.40" /* node1.whiterockserver.com */
};

#define SHC_SEED_LIST_SIZE 2
static char *shc_seed_list[SHC_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108" /* coin2.sharelib.net */
};

#define EMC2_SEED_LIST_SIZE 2 
static char *emc2_seed_list[EMC2_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.sharelib.net */
  "45.79.195.108", /* coin2.sharelib.net */
  //"167.88.15.89:6035" //  /* prohashing-1.prohashing.com */
};



#endif /* ndef __UNET_SEED_H__ */
