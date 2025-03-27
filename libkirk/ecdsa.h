#ifndef ECDSA_H
#define ECDSA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "kirk_engine.h"
#include "SHA1.h"

// Each limb is 64 bits, and we use 3 limbs for a 160-bit number
typedef struct {
    uint64_t value[3];
} bigint160_t;

// Point structure for elliptic curve points
typedef struct {
    bigint160_t x;
    bigint160_t y;
    int infinity;  // Flag for point at infinity
} ec_point_t;

// Function prototypes for basic operations
void bigint_print(const char* label, const bigint160_t* a);
int bigint_is_zero(const bigint160_t* a);
int bigint_is_equal(const bigint160_t* a, const bigint160_t* b);
int bigint_compare(const bigint160_t* a, const bigint160_t* b);
void bigint_set_zero(bigint160_t* r);
void bigint_from_hexbuf(bigint160_t* a, const uint8_t* hexbuf, int len);
void bigint_to_hexbuf(uint8_t* hexbuf, const bigint160_t* a, int len);
void bigint_copy(bigint160_t* r, const bigint160_t* a);
void bigint_add(bigint160_t* r, const bigint160_t* a, const bigint160_t* b);
void bigint_sub(bigint160_t* r, const bigint160_t* a, const bigint160_t* b);
void bigint_mod(bigint160_t* r, const bigint160_t* a, const bigint160_t* mod);
void bigint_mul(bigint160_t* r, const bigint160_t* a, const bigint160_t* b);
void bigint_mod_mul(bigint160_t* r, const bigint160_t* a, const bigint160_t* b, const bigint160_t* mod);
void bigint_mod_inv(bigint160_t* r, const bigint160_t* a, const bigint160_t* mod);
void elt_sub(bigint160_t* r, const bigint160_t* a, const bigint160_t* b);
void ec_point_copy(ec_point_t* r, const ec_point_t* point);
void ec_point_add(ec_point_t* r, const ec_point_t* point1, const ec_point_t* point2);
void ec_point_double(ec_point_t* r, const ec_point_t* point);
void ec_point_mul(ec_point_t* r, const bigint160_t* k, const ec_point_t* point);

// Function prototypes for ecdsa operations
void ecdsa_sign(const uint8_t* hash, uint8_t* R, uint8_t* S);
int ecdsa_verify(const uint8_t* hash, const uint8_t* r, const uint8_t* s);
int ecdsa_set_curve(uint8_t* p, uint8_t* a, uint8_t* b, uint8_t* N, uint8_t* Gx, uint8_t* Gy);
void ecdsa_set_pub(uint8_t* Q);
void ecdsa_set_priv(uint8_t* k);

// Function prototypes for other operations
void ec_priv_to_pub(uint8_t* k, uint8_t* Q);
void ec_pub_mult(uint8_t* k, uint8_t* Q);
int point_is_on_curve(const uint8_t* p);
void dump_ecc(void);

#endif // ECDSA_H