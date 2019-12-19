

#ifndef __UNET_SEED_H__
#define __UNET_SEED_H__


#define SHC_SEED_LIST_SIZE 2
static char *shc_seed_list[SHC_SEED_LIST_SIZE] = {
  "45.79.197.174", /* coin1.shcoins.com */
  "45.79.195.108"  /* coin2.shcoins.com */
};

#define TESTNET_SEED_LIST_SIZE 2
static char *testnet_seed_list[TESTNET_SEED_LIST_SIZE] = {
  "45.79.195.108", /* coin2.shcoins.com */
  "45.56.115.51",  /* coin3.shcoins.com */
};

#define EMC2_SEED_LIST_SIZE 1
static char *emc2_seed_list[EMC2_SEED_LIST_SIZE] = {
  "45.79.195.108"  /* coin2.shcoins.com */
};


#endif /* ndef __UNET_SEED_H__ */
