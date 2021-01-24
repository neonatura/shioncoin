
/*Type for representing a ecdsa_signature*/
typedef struct ecdsa_signature_s* ecdsa_signature;
struct ecdsa_signature_s
{
	mpz_t r;
	mpz_t s;
};

/*Initialize a ecdsa_signature*/
ecdsa_signature ecdsa_signature_init(void);

/*Set ecdsa_signature from strings of a base from 2-62*/
void ecdsa_signature_set_str(ecdsa_signature sig, char *r, char *s, int base);

/*Set ecdsa_signature from hexadecimal strings*/
void ecdsa_signature_set_hex(ecdsa_signature sig, char *r, char *s);

/*Set ecdsa_signature from decimal unsigned long ints*/
void ecdsa_signature_set_ui(ecdsa_signature sig, unsigned long int r, unsigned long int s);

/*Print ecdsa_signature to standart output stream*/
void ecdsa_signature_print(ecdsa_signature sig);

/*Make R a copy of P*/
void ecdsa_signature_copy(ecdsa_signature R, ecdsa_signature sig);

/*Compare two ecdsa_signatures return 1 if not the same, returns 0 if they are the same*/
bool ecdsa_signature_cmp(ecdsa_signature sig1, ecdsa_signature sig2);

/*Release ecdsa_signature*/
void ecdsa_signature_clear(ecdsa_signature sig);

/*Generates a public key for a private key*/
void ecdsa_signature_generate_key(ecdsa_point public_key, mpz_t private_key, ecdsa_parameters curve);

/*Generate ecdsa_signature for a message*/
void ecdsa_signature_sign(ecdsa_signature sig, mpz_t message, mpz_t private_key, ecdsa_parameters curve);

/*Verify the integrity of a message using it's ecdsa_signature*/
bool ecdsa_signature_verify(mpz_t message, ecdsa_signature sig, ecdsa_point public_key, ecdsa_parameters curve);


