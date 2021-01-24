

/*Type that represents a ecdsa_point*/
typedef struct ecdsa_point_s* ecdsa_point;
struct ecdsa_point_s
{
	mpz_t x;
	mpz_t y;
	int infinity;
};

/*Type that represents a curve*/
typedef struct ecdsa_parameters_s* ecdsa_parameters;
struct ecdsa_parameters_s
{
	char* name;
	mpz_t p;	//Prime
	mpz_t a;	//'a' parameter of the elliptic curve
	mpz_t b;	//'b' parameter of the elliptic curve
	ecdsa_point G;	//Generator ecdsa_point of the curve, also known as base ecdsa_point.
	mpz_t n;
	mpz_t h;
};

/*Initialize a curve*/
ecdsa_parameters ecdsa_parameters_init();

/*Sets the name of a curve*/
void ecdsa_parameters_set_name(ecdsa_parameters curve, char* name);

/*Set domain parameters from decimal unsigned long ints*/
void ecdsa_parameters_set_ui(ecdsa_parameters curve,
								char* name,
								unsigned long int p,
								unsigned long int a,
								unsigned long int b,
								unsigned long int Gx,
								unsigned long int Gy,
								unsigned long int n,
								unsigned long int h);

/*Set domain parameters from hexadecimal string*/
void ecdsa_parameters_set_hex(ecdsa_parameters curve, char* name, char* p, char* a, char* b, char* Gx, char* Gy, char* n, char* h);

/*Release memory*/
void ecdsa_parameters_clear(ecdsa_parameters curve);

