
/*Initialize a ecdsa_point*/
ecdsa_point ecdsa_point_init(void);

/*Release ecdsa_point*/
void ecdsa_point_clear(ecdsa_point p);

/*Set ecdsa_point to be a infinity*/
void ecdsa_point_at_infinity(ecdsa_point p);

/*Set R to the additive inverse of P, in the curve curve*/
void ecdsa_point_inverse(ecdsa_point R, ecdsa_point P, ecdsa_parameters curve);

/*Print ecdsa_point to standart output stream*/
void ecdsa_point_print(ecdsa_point p);

/*Set ecdsa_point from hexadecimal strings*/
void ecdsa_point_set_hex(ecdsa_point p, char *x, char *y);

/*Set ecdsa_point from decimal unsigned long ints*/
void ecdsa_point_set_ui(ecdsa_point p, unsigned long int x, unsigned long int y);

/*Addition of ecdsa_point P + Q = result*/
void ecdsa_point_addition(ecdsa_point result, ecdsa_point P, ecdsa_point Q, ecdsa_parameters curve);

/*Set ecdsa_point R = 2P*/
void ecdsa_point_doubling(ecdsa_point R, ecdsa_point P, ecdsa_parameters curve);

/*Perform scalar multiplication to P, with the factor multiplier, over the curve curve*/
void ecdsa_point_multiplication(ecdsa_point R, mpz_t multiplier, ecdsa_point P, ecdsa_parameters curve);

/*Set ecdsa_point from strings of a base from 2-62*/
void ecdsa_point_set_str(ecdsa_point p, char *x, char *y, int base);

/*Compare two ecdsa_points return 1 if not the same, returns 0 if they are the same*/
int ecdsa_point_cmp(ecdsa_point P, ecdsa_point Q);

/*Decompress a ecdsa_point from hexadecimal representation
 *This function is implemented as specified in SEC 1: Elliptic Curve Cryptography, section 2.3.4.*/
void ecdsa_point_decompress(ecdsa_point P, char* zPoint, ecdsa_parameters curve);

/*Compress a ecdsa_point to hexadecimal string
 *This function is implemented as specified in SEC 1: Elliptic Curve Cryptography, section 2.3.3.*/
char* ecdsa_point_compress(ecdsa_point P, size_t len);

/*Make R a copy of P*/
void ecdsa_point_copy(ecdsa_point R, ecdsa_point P);

/*Set a ecdsa_point from another ecdsa_point*/
void ecdsa_point_set(ecdsa_point R, ecdsa_point P);

