
#ifdef __cplusplus
extern "C" {
#endif


void get_rpc_cred(char *username, char *password);

int set_rpc_dat_password(char *host, shkey_t *in_key);

shkey_t *get_rpc_dat_password(char *host);

const char *get_rpc_password(char *host);

const char *get_rpc_username(void);

uint32_t get_rpc_pin(char *host);

int verify_rpc_pin(char *host, uint32_t pin);

int rpc_init(void);

void rpc_term(void);


#ifdef __cplusplus
}
#endif
