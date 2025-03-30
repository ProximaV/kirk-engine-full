/**
 * ECDSA Implementation for 160bits curve
 *
 * This implementation uses a 3-limb representation for 160-bit integers
 * and implements modular inversion using the Extended Euclidean GCD algorithm.
 */

 // For our 3-limb representation, each bigint160_t is arranged with:
 // value[0] = least significant 64 bits
 // value[1] = middle 64 bits
 // value[2] = most significant 32 bits (padded to 64 bits)

#include "ecdsa.h"

// ECDSA Curve Parameters
bigint160_t prime; // Prime field: 2^160 - 2^31 - 1
bigint160_t curve_a; // Curve parameter a = p - 3
bigint160_t curve_b; // Curve parameter b
bigint160_t order_n; // Order of G
ec_point_t base_point; //Generator point

// ECDSA Public key
ec_point_t pub_key;

// ECDSA Private key
bigint160_t priv_key;

/**
 * Print a bigint160_t value with a label
 */
void bigint_print(const char* label, const bigint160_t* a) {
    printf("%s: 0x", label);
    printf("%016llX", a->value[2]);
    printf("%016llX", a->value[1]);
    printf("%016llX\n", a->value[0]);
}

/**
 * Check if a bigint160_t is zero
 */
int bigint_is_zero(const bigint160_t* a) {
    return (a->value[0] == 0 && a->value[1] == 0 && a->value[2] == 0);
}

/**
 * Check if two bigint160_t values are equal
 */
int bigint_is_equal(const bigint160_t* a, const bigint160_t* b) {
    return (a->value[0] == b->value[0] &&
        a->value[1] == b->value[1] &&
        a->value[2] == b->value[2]);
}

/**
 * Compare two bigint160_t values
 * Returns -1 if a < b, 0 if a == b, 1 if a > b
 */
int bigint_compare(const bigint160_t* a, const bigint160_t* b) {
    for (int i = 2; i >= 0; i--) {
        if (a->value[i] < b->value[i]) return -1;
        if (a->value[i] > b->value[i]) return 1;
    }
    return 0;
}

/**
 * Compare two 320 bits values
 * Returns -1 if a < b, 0 if a == b, 1 if a > b
 */
int bigint_compare_320(const uint64_t* a, const uint64_t* b) {
    for (int i = 4; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/**
 * Set a bigint160_t to zero
 */
void bigint_set_zero(bigint160_t* r) {
    r->value[0] = 0;
    r->value[1] = 0;
    r->value[2] = 0;
}

/**
 * Convert a hexadecimal buffer to a bigint160_t
 */
void bigint_from_hexbuf(bigint160_t* a, const uint8_t* hexbuf, int len) {
    // 24 bytes max
    bigint_set_zero(a);
    size_t bytes_to_copy = len < 24 ? len : 24;

    for (size_t i = 0; i < bytes_to_copy; i++) {
        if (i < 8) {
            a->value[0] |= ((uint64_t)hexbuf[bytes_to_copy - 1 - i]) << (i * 8);
        }
        else if (i < 16) {
            a->value[1] |= ((uint64_t)hexbuf[bytes_to_copy - 1 - i]) << ((i - 8) * 8);
        }
        else {
            a->value[2] |= ((uint64_t)hexbuf[bytes_to_copy - 1 - i]) << ((i - 16) * 8);
        }
    }
}

/**
 * Convert a bigint160_t to a hexadecimal buffer
 */
void bigint_to_hexbuf(uint8_t* hexbuf, const bigint160_t* a, int len) {
    // 24 bytes max
    int bytes_to_copy = len < 24 ? len : 24;

    for (int i = (bytes_to_copy - 1); i >= 0 ; i--) {
        if ((bytes_to_copy - i) < 9) {
            hexbuf[i] = (uint8_t)(a->value[0] >> ((bytes_to_copy - 1 - i) * 8));
        }
        else if ((bytes_to_copy - i) < 17) {
            hexbuf[i] = (uint8_t)(a->value[1] >> ((bytes_to_copy - 9 - i) * 8));
        }
        else {
            hexbuf[i] = (uint8_t)(a->value[2] >> ((bytes_to_copy - 17 - i) * 8));
        }
    }
}

/**
 * Copy one bigint160_t to another
 */
void bigint_copy(bigint160_t* r, const bigint160_t* a) {
    r->value[0] = a->value[0];
    r->value[1] = a->value[1];
    r->value[2] = a->value[2];
}

/**
 * Copy one 320 bits value to another
 */
void bigint_copy_320(uint64_t* r, const uint64_t* a) {
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
    r[4] = a[4];
}

/**
 * Add two bigint160_t values
 */
void bigint_add(bigint160_t* r, const bigint160_t* a, const bigint160_t* b) {
    uint64_t carry = 0;

    for (int i = 0; i < 3; i++) {
        uint64_t sum = a->value[i] + b->value[i] + carry;
        carry = (sum < a->value[i]) || (sum == a->value[i] && b->value[i] > 0);
        r->value[i] = sum;
    }
}

/**
 * Subtract one bigint160_t from another
 */
void bigint_sub(bigint160_t* r, const bigint160_t* a, const bigint160_t* b) {
    uint64_t borrow = 0;

    for (int i = 0; i < 3; i++) {
        // Split the computation to avoid potential overflow in the comparison
        uint64_t a_val = a->value[i];
        uint64_t b_val = b->value[i];

        // Check if previous borrow causes underflow
        if (borrow > a_val) {
            r->value[i] = UINT64_MAX - (b_val - (a_val + UINT64_MAX + 1 - borrow));
            borrow = 1;
        }
        else {
            uint64_t a_minus_borrow = a_val - borrow;

            // Regular subtraction with potential new borrow
            if (a_minus_borrow >= b_val) {
                r->value[i] = a_minus_borrow - b_val;
                borrow = 0;
            }
            else {
                r->value[i] = (UINT64_MAX - b_val) + a_minus_borrow + 1;
                borrow = 1;
            }
        }
    }
}

/**
 * Subtract one 320 bits value from another
 */
void bigint_sub_320(uint64_t* r, const uint64_t* a, const uint64_t* b) {
    uint64_t borrow = 0;

    for (int i = 0; i < 5; i++) {
        // Split the computation to avoid potential overflow in the comparison
        uint64_t a_val = a[i];
        uint64_t b_val = b[i];

        // Check if previous borrow causes underflow
        if (borrow > a_val) {
            r[i] = UINT64_MAX - (b_val - (a_val + UINT64_MAX + 1 - borrow));
            borrow = 1;
        }
        else {
            uint64_t a_minus_borrow = a_val - borrow;

            // Regular subtraction with potential new borrow
            if (a_minus_borrow >= b_val) {
                r[i] = a_minus_borrow - b_val;
                borrow = 0;
            }
            else {
                r[i] = (UINT64_MAX - b_val) + a_minus_borrow + 1;
                borrow = 1;
            }
        }
    }
}

/**
 * Compute a mod m for bigint160_t values
 * This implementation is more efficient than repeated subtraction
 */
void bigint_mod(bigint160_t* r, const bigint160_t* a, const bigint160_t* mod) {
    // First check if no reduction is needed
    if (bigint_compare(a, mod) < 0) {
        bigint_copy(r, a);
        return;
    }

    bigint160_t temp;
    bigint_copy(&temp, a);

    // Find most significant bit of mod
    int mod_msb_limb = 2;
    int mod_msb_bit = 63;
    int found = 0;

    for (int i = 2; i >= 0 && !found; i--) {
        if (mod->value[i] != 0) {
            uint64_t v = mod->value[i];
            mod_msb_bit = 63;
            while (mod_msb_bit >= 0 && !found) {
                if (v & (1ULL << mod_msb_bit)) {
                    mod_msb_limb = i;
                    found = 1;
                    break;
                }
                mod_msb_bit--;
            }
        }
    }

    // Main reduction loop - uses binary long division approach
    while (bigint_compare(&temp, mod) >= 0) {
        // Find most significant bit of temp
        int temp_msb_limb = 2;
        int temp_msb_bit = 63;
        found = 0;

        for (int i = 2; i >= 0 && !found; i--) {
            if (temp.value[i] != 0) {
                uint64_t v = temp.value[i];
                temp_msb_bit = 63;
                while (temp_msb_bit >= 0 && !found) {
                    if (v & (1ULL << temp_msb_bit)) {
                        temp_msb_limb = i;
                        found = 1;
                        break;
                    }
                    temp_msb_bit--;
                }
            }
        }

        // Calculate the bit difference for shifting
        int bit_diff = (temp_msb_limb - mod_msb_limb) * 64 + (temp_msb_bit - mod_msb_bit);

        if (bit_diff < 0) {
            // temp is smaller than mod, we're done
            break;
        }

        // Create a shifted copy of mod
        bigint160_t shifted_mod;
        bigint_copy(&shifted_mod, mod);

        // Shift left by bit_diff
        for (int i = 0; i < bit_diff; i++) {
            uint64_t carry = 0;
            for (int j = 0; j < 3; j++) {
                uint64_t new_carry = shifted_mod.value[j] >> 63;
                shifted_mod.value[j] = (shifted_mod.value[j] << 1) | carry;
                carry = new_carry;
            }
        }

        // If shifted_mod is too large, shift right once
        if (bigint_compare(&shifted_mod, &temp) > 0) {
            uint64_t carry = 0;
            for (int j = 2; j >= 0; j--) {
                uint64_t new_carry = shifted_mod.value[j] & 1;
                shifted_mod.value[j] = (shifted_mod.value[j] >> 1) | (carry << 63);
                carry = new_carry;
            }
        }

        // Subtract
        bigint_sub(&temp, &temp, &shifted_mod);
    }

    bigint_copy(r, &temp);
}

/**
 * Multiply two bigint160_t values
 * This is a simplified implementation - in production you'd use more optimized algorithms
 */
void bigint_mul(bigint160_t* r, const bigint160_t* a, const bigint160_t* b) {
    // First, compute the full product using double - word arithmetic
    uint32_t product[10] = { 0 }; // 10 32-bit words for a full 320-bit result

    // Convert a and b to 32-bit words for easier manipulation
    uint32_t a_words[6], b_words[6];
    for (int i = 0; i < 3; i++) {
        a_words[i * 2] = a->value[i] & 0xFFFFFFFF;         // Lower 32 bits
        a_words[i * 2 + 1] = (a->value[i] >> 32) & 0xFFFFFFFF; // Upper 32 bits

        b_words[i * 2] = b->value[i] & 0xFFFFFFFF;         // Lower 32 bits
        b_words[i * 2 + 1] = (b->value[i] >> 32) & 0xFFFFFFFF; // Upper 32 bits
    }

    // Perform schoolbook multiplication using 32-bit limbs
    for (int i = 0; i < 6; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < 6; j++) {
            // Skip multiplications that won't affect our 160-bit result
            if (i + j >= 10) continue;

            // Compute the product and add to the result
            uint64_t prod = (uint64_t)a_words[i] * b_words[j] + product[i + j] + carry;
            product[i + j] = prod & 0xFFFFFFFF;  // Store lower 32 bits
            carry = prod >> 32;                // Carry the upper 32 bits
        }

        // If we have any remaining carry, add it to the next word
        if (carry && i + 6 < 10) {
            product[i + 6] += carry;
        }
    }

    // Convert the 32-bit product back to 64-bit limbs (truncating to 160 bits)
    r->value[0] = ((uint64_t)product[1] << 32) | product[0];
    r->value[1] = ((uint64_t)product[3] << 32) | product[2];
    r->value[2] = (((uint64_t)product[5] << 32) | product[4]) & 0xFFFFFFFF;
}

/**
 * Compute (a * b) mod m for bigint160_t values
 */
void bigint_mod_mul(bigint160_t* r, const bigint160_t* a, const bigint160_t* b, const bigint160_t* mod) {

    uint64_t mul_result[5] = { 0 }; //320 bits

    // First, compute the full product using double - word arithmetic
    uint32_t product[10] = { 0 }; // 10 32-bit words for a full 320-bit result

    // Convert a and b to 32-bit words for easier manipulation
    uint32_t a_words[6], b_words[6];
    for (int i = 0; i < 3; i++) {
        a_words[i * 2] = a->value[i] & 0xFFFFFFFF;         // Lower 32 bits
        a_words[i * 2 + 1] = (a->value[i] >> 32) & 0xFFFFFFFF; // Upper 32 bits

        b_words[i * 2] = b->value[i] & 0xFFFFFFFF;         // Lower 32 bits
        b_words[i * 2 + 1] = (b->value[i] >> 32) & 0xFFFFFFFF; // Upper 32 bits
    }

    // Perform schoolbook multiplication using 32-bit limbs
    for (int i = 0; i < 6; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < 6; j++) {
            // Skip multiplications that won't affect our 160-bit result
            if (i + j >= 10) continue;

            // Compute the product and add to the result
            uint64_t prod = (uint64_t)a_words[i] * b_words[j] + product[i + j] + carry;
            product[i + j] = prod & 0xFFFFFFFF;  // Store lower 32 bits
            carry = prod >> 32;                // Carry the upper 32 bits
        }

        // If we have any remaining carry, add it to the next word
        if (carry && i + 6 < 10) {
            product[i + 6] += carry;
        }
    }

    mul_result[0] = ((uint64_t)product[1] << 32) | product[0];
    mul_result[1] = ((uint64_t)product[3] << 32) | product[2];
    mul_result[2] = (((uint64_t)product[5] << 32) | product[4]);
    mul_result[3] = (((uint64_t)product[7] << 32) | product[6]);
    mul_result[4] = (((uint64_t)product[9] << 32) | product[8]);

    // Now MOD

    //Extend mod value to 320 bits
    uint64_t mod_320_bits[5] = { 0 };
    for (int i = 0; i < 3; i++)
        mod_320_bits[i] = mod->value[i];

    // First check if no reduction is needed
    //compare the mul_result and mod_320_bits
    int res = 0;
    for (int l = 4; l >= 0; l--) {
        if (mul_result[l] < mod_320_bits[l]) {
            res = -1;
            break;
        }
        if (mul_result[l] > mod_320_bits[l]) {
            res = 1;
            break;
        }
    }

    if (res < 0) {
        for (int i = 0; i < 3; i++) {
            r->value[i] = mul_result[i];
        }
        return;
    }

    uint64_t temp[5];
    bigint_copy_320(temp, mul_result);

    /*Fix it*/
    // Find most significant bit of mod
    int mod_msb_limb = 4;
    int mod_msb_bit = 63;
    int found = 0;

    for (int i = 4; i >= 0 && !found; i--) {
        if (mod_320_bits[i] != 0) {
            uint64_t v = mod_320_bits[i];
            mod_msb_bit = 63;
            while (mod_msb_bit >= 0 && !found) {
                if (v & (1ULL << mod_msb_bit)) {
                    mod_msb_limb = i;
                    found = 1;
                    break;
                }
                mod_msb_bit--;
            }
        }
    }

    // Main reduction loop - uses binary long division approach
    while (bigint_compare_320(temp, mod_320_bits) >= 0) {
        // Find most significant bit of temp
        int temp_msb_limb = 4;
        int temp_msb_bit = 63;
        found = 0;

        for (int i = 4; i >= 0 && !found; i--) {
            if (temp[i] != 0) {
                uint64_t v = temp[i];
                temp_msb_bit = 63;
                while (temp_msb_bit >= 0 && !found) {
                    if (v & (1ULL << temp_msb_bit)) {
                        temp_msb_limb = i;
                        found = 1;
                        break;
                    }
                    temp_msb_bit--;
                }
            }
        }

        // Calculate the bit difference for shifting
        int bit_diff = (temp_msb_limb - mod_msb_limb) * 64 + (temp_msb_bit - mod_msb_bit);

        if (bit_diff < 0) {
            // temp is smaller than mod, we're done
            break;
        }

        // Create a shifted copy of mod
        uint64_t shifted_mod[5];
        bigint_copy_320(shifted_mod, mod_320_bits);

        // Shift left by bit_diff
        for (int i = 0; i < bit_diff; i++) {
            uint64_t carry = 0;
            for (int j = 0; j < 5; j++) {
                uint64_t new_carry = shifted_mod[j] >> 63;
                shifted_mod[j] = (shifted_mod[j] << 1) | carry;
                carry = new_carry;
            }
        }

        // If shifted_mod is too large, shift right once
        if (bigint_compare_320(shifted_mod, temp) > 0) {
            uint64_t carry = 0;
            for (int j = 4; j >= 0; j--) {
                uint64_t new_carry = shifted_mod[j] & 1;
                shifted_mod[j] = (shifted_mod[j] >> 1) | (carry << 63);
                carry = new_carry;
            }
        }

        // Subtract
        bigint_sub_320(temp, temp, shifted_mod);
    }

    for (int i = 0; i < 3; i++)
        r->value[i] = temp[i];

}

/**
 * Compute modular inverse using Binary Extended GCD algorithm
 * Much more efficient than the Extended Euclidean algorithm with repeated subtraction
 * Computes a^(-1) mod m
 */
void bigint_mod_inv(bigint160_t* r, const bigint160_t* a, const bigint160_t* mod) {
    // Initialize variables
    bigint160_t u, v, x1, x2;

    // Ensure a is positive and less than mod
    bigint_mod(&u, a, mod);
    bigint_copy(&v, mod);

    // Initialize coefficients: x1 = 1, x2 = 0
    x1.value[0] = 1;
    x1.value[1] = 0;
    x1.value[2] = 0;

    bigint_set_zero(&x2);

    // Binary Extended GCD algorithm
    while (!bigint_is_zero(&u) && !bigint_is_zero(&v)) {
        // While u is even
        while ((u.value[0] & 1) == 0) {
            // u = u/2
            for (int i = 0; i < 2; i++) {
                u.value[i] = (u.value[i] >> 1) | ((u.value[i + 1] & 1) << 63);
            }
            u.value[2] >>= 1;

            // If x1 is odd, add mod
            if (x1.value[0] & 1) {
                bigint_add(&x1, &x1, mod);
            }

            // x1 = x1/2
            for (int i = 0; i < 2; i++) {
                x1.value[i] = (x1.value[i] >> 1) | ((x1.value[i + 1] & 1) << 63);
            }
            x1.value[2] >>= 1;
        }

        // While v is even
        while ((v.value[0] & 1) == 0) {
            // v = v/2
            for (int i = 0; i < 2; i++) {
                v.value[i] = (v.value[i] >> 1) | ((v.value[i + 1] & 1) << 63);
            }
            v.value[2] >>= 1;

            // If x2 is odd, add mod
            if (x2.value[0] & 1) {
                bigint_add(&x2, &x2, mod);
            }

            // x2 = x2/2
            for (int i = 0; i < 2; i++) {
                x2.value[i] = (x2.value[i] >> 1) | ((x2.value[i + 1] & 1) << 63);
            }
            x2.value[2] >>= 1;
        }

        // If u >= v
        if (bigint_compare(&u, &v) >= 0) {
            // u = u - v
            bigint_sub(&u, &u, &v);

            // x1 = x1 - x2
            if (bigint_compare(&x1, &x2) >= 0) {
                bigint_sub(&x1, &x1, &x2);
            }
            else {
                bigint160_t temp;
                bigint_sub(&temp, &x2, &x1);
                bigint_sub(&x1, mod, &temp);
            }
            bigint_mod(&x1, &x1, mod);
        }
        else {
            // v = v - u
            bigint_sub(&v, &v, &u);

            // x2 = x2 - x1
            if (bigint_compare(&x2, &x1) >= 0) {
                bigint_sub(&x2, &x2, &x1);
            }
            else {
                bigint160_t temp;
                bigint_sub(&temp, &x1, &x2);
                bigint_sub(&x2, mod, &temp);
            }
            bigint_mod(&x2, &x2, mod);
        }
    }

    // If u is the gcd (should be 1 for a prime modulus), then x1 is the inverse
    // If v is the gcd, then x2 is the inverse
    if (bigint_is_zero(&u)) {
        bigint_copy(r, &x2);
    }
    else {
        bigint_copy(r, &x1);
    }
}

/**
 * Helper subtract function,
 */
void elt_sub(bigint160_t* r, const bigint160_t* a, const bigint160_t* b) {
    bigint160_t temp;

    if ((bigint_compare(a, b) == -1)) {
        bigint_sub(&temp, b, a);
        bigint_sub(&temp, &prime, &temp);
    }
    else
        bigint_sub(&temp, a, b);

    bigint_copy(r, &temp);
}

/**
 * Copy an EC point
 */
void ec_point_copy(ec_point_t* r, const ec_point_t* point) {
    r->infinity = point->infinity;
    if (!point->infinity) {
        bigint_copy(&r->x, &point->x);
        bigint_copy(&r->y, &point->y);
    }
}

/**
 * Add two EC points
 */
void ec_point_add(ec_point_t* r, const ec_point_t* point1, const ec_point_t* point2) {
    // Handle special cases
    if (point1->infinity) {
        ec_point_copy(r, point2);
        return;
    }
    if (point2->infinity) {
        ec_point_copy(r, point1);
        return;
    }

    // Check if points are inverses of each other (x coordinates the same, y coordinates are negatives of each other)
    if (bigint_is_equal(&point1->x, &point2->x)) {
        bigint160_t neg_qy;
        bigint_sub(&neg_qy, &prime, &point2->y);  // Using global prime for modular arithmetic
        bigint_mod(&neg_qy, &neg_qy, &prime);

        if (bigint_is_equal(&point1->y, &neg_qy) || bigint_is_zero(&point1->y)) {
            r->infinity = 1;
            return;
        }

        // Points are the same, use point doubling
        if (bigint_is_equal(&point1->y, &point2->y)) {
            ec_point_double(r, point1);
            return;
        }
    }

    // Calculate the slope
    bigint160_t slope, temp1, temp2;

    // Point addition: slope = (y2 - y1) / (x2 - x1)
    elt_sub(&temp1, &point2->y, &point1->y);
    bigint_mod(&temp1, &temp1, &prime);

    elt_sub(&temp2, &point2->x, &point1->x);
    bigint_mod(&temp2, &temp2, &prime);

    bigint_mod_inv(&temp2, &temp2, &prime);
    bigint_mod_mul(&slope, &temp1, &temp2, &prime);

    // Calculate r->x = slope^2 - point1->x - point2->x
    bigint_mod_mul(&temp1, &slope, &slope, &prime);
    elt_sub(&temp1, &temp1, &point1->x);
    elt_sub(&temp1, &temp1, &point2->x);
    bigint_mod(&r->x, &temp1, &prime);

    // Calculate r->y = slope * (point1->x - r->x) - point1->y
    elt_sub(&temp1, &point1->x, &r->x);
    bigint_mod_mul(&temp1, &slope, &temp1, &prime);
    elt_sub(&temp1, &temp1, &point1->y);
    bigint_mod(&r->y, &temp1, &prime);

    r->infinity = 0;
}

/**
 * Double an EC point
 */
void ec_point_double(ec_point_t* r, const ec_point_t* point) {
    // Handle point at infinity
    if (point->infinity) {
        r->infinity = 1;
        return;
    }

    // Check if y-coordinate is 0 (tangent is vertical)
    if (bigint_is_zero(&point->y)) {
        r->infinity = 1;
        return;
    }

    // Calculate lambda = (3*x^2 + a) / (2*y)
    bigint160_t lambda, temp1, temp2;

    // temp1 = 3*x^2
    bigint_mod_mul(&temp1, &point->x, &point->x, &prime);
    bigint160_t three = { {3ULL, 0, 0} };
    bigint_mod_mul(&temp1, &temp1, &three, &prime);

    // temp1 = 3*x^2 + a
    bigint_add(&temp1, &temp1, &curve_a);
    bigint_mod(&temp1, &temp1, &prime);

    // temp2 = 2*y
    bigint160_t two = { {2ULL, 0, 0} };
    bigint_mod_mul(&temp2, &point->y, &two, &prime);

    // lambda = temp1 / temp2
    bigint_mod_inv(&temp2, &temp2, &prime);
    bigint_mod_mul(&lambda, &temp1, &temp2, &prime);

    // Calculate new x = lambda^2 - 2*x
    bigint_mod_mul(&temp1, &lambda, &lambda, &prime);
    bigint_mod_mul(&temp2, &point->x, &two, &prime);
    elt_sub(&temp1, &temp1, &temp2);
    bigint_mod(&r->x, &temp1, &prime);

    // Calculate new y = lambda*(x - new_x) - y
    elt_sub(&temp1, &point->x, &r->x);
    bigint_mod_mul(&temp1, &lambda, &temp1, &prime);
    elt_sub(&temp1, &temp1, &point->y);
    bigint_mod(&r->y, &temp1, &prime);

    r->infinity = 0;
}

/**
 * Multiply an EC point by a scalar
 * Uses the double-and-add algorithm from MSB to LSB
 */
void ec_point_mul(ec_point_t* r, const bigint160_t* k, const ec_point_t* point) {
    // Handle special cases
    if (point->infinity || bigint_is_zero(k)) {
        r->infinity = 1;
        return;
    }

    // Find the most significant bit
    int msb_limb = 2;
    int msb_bit = 63;
    int found = 0;

    // Find MSB
    for (int i = 2; i >= 0 && !found; i--) {
        for (int j = 63; j >= 0 && !found; j--) {
            if (k->value[i] & (1ULL << j)) {
                msb_limb = i;
                msb_bit = j;
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        // k is zero
        r->infinity = 1;
        return;
    }

    // Start with the input point
    ec_point_t result;
    ec_point_copy(&result, point);

    // Process bits from MSB-1 downto LSB
    for (int i = msb_limb; i >= 0; i--) {
        int start_bit = (i == msb_limb) ? msb_bit - 1 : 63;

        for (int j = start_bit; j >= 0; j--) {
            // Double
            ec_point_t temp;
            ec_point_double(&temp, &result);
            ec_point_copy(&result, &temp);

            // Add if bit is set
            if (k->value[i] & (1ULL << j)) {
                ec_point_add(&temp, &result, point);
                ec_point_copy(&result, &temp);
            }
        }
    }

    // Copy result
    ec_point_copy(r, &result);
}

/**
 * ECDSA signature generation
 */
void ecdsa_sign(const uint8_t* hash, uint8_t* R, uint8_t* S) {
    bigint160_t message_hash, r_sig, s_sig;
    bigint_from_hexbuf(&message_hash, hash, 20);
    bigint_set_zero(&r_sig);
    bigint_set_zero(&s_sig);

    bigint160_t k, kinv, temp;
    ec_point_t point;

    // Generate a random k value
    // Guaranteed to be random ;)
    uint8_t random[20];
    uint8_t priv_buf[20];
    bigint_to_hexbuf(priv_buf, &priv_key, 20);
    SHA_CTX sha1_context;
    kirk_CMD14(random);
    SHAInit(&sha1_context);
    SHAUpdate(&sha1_context, (uint8_t*)hash, 20);
    SHAUpdate(&sha1_context, priv_buf, 20);
    SHAUpdate(&sha1_context, random, 20);
    SHAFinal(random, &sha1_context);
    bigint_from_hexbuf(&k, random, 20);
    bigint_mod(&k, &k, &order_n);

    // Calculate r = (k * G).x mod n
    ec_point_mul(&point, &k, &base_point);
    bigint_mod(&r_sig, &point.x, &order_n);

    // Calculate s = k^(-1) * (message_hash + r * private_key) mod n
    bigint_mod_inv(&kinv, &k, &order_n);
    bigint_mod_mul(&temp, &r_sig, &priv_key, &order_n);
    bigint_add(&temp, &temp, &message_hash);
    bigint_mod(&temp, &temp, &order_n);
    bigint_mod_mul(&s_sig, &kinv, &temp, &order_n);

    // Copy the result
    bigint_to_hexbuf(R, &r_sig, 20);
    bigint_to_hexbuf(S, &s_sig, 20);
}

/**
 * ECDSA signature verification
 * Returns 1 if signature is valid, 0 otherwise
 */
int ecdsa_verify(const uint8_t* hash, const uint8_t* r, const uint8_t* s)
{
    bigint160_t r_sig, s_sig, message_hash;
    bigint_from_hexbuf(&r_sig, r, 20);
    bigint_from_hexbuf(&s_sig, s, 20);
    bigint_from_hexbuf(&message_hash, hash, 20);

    // Check that r, s are in [1, n-1]
    if (bigint_is_zero(&r_sig) || bigint_is_zero(&s_sig) ||
        bigint_compare(&r_sig, &order_n) >= 0 || bigint_compare(&s_sig, &order_n) >= 0) {
        return 0;
    }

    // Calculate w = s^(-1) mod n
    bigint160_t w, u1, u2, temp;
    bigint_mod_inv(&w, &s_sig, &order_n);

    // Calculate u1 = message_hash * w mod n
    bigint_mod_mul(&u1, &message_hash, &w, &order_n);

    // Calculate u2 = r * w mod n
    bigint_mod_mul(&u2, &r_sig, &w, &order_n);

    // Calculate point = u1*G + u2*Q
    ec_point_t point1, point2, point_result;
    ec_point_mul(&point1, &u1, &base_point);
    ec_point_mul(&point2, &u2, &pub_key);
    ec_point_add(&point_result, &point1, &point2);

    // Check if point_result.x mod n == r
    bigint_mod(&temp, &point_result.x, &order_n);
    return bigint_is_equal(&temp, &r_sig);
}

/**
 * Set curve parameters
 */
int ecdsa_set_curve(uint8_t* p, uint8_t* a, uint8_t* b, uint8_t* N, uint8_t* Gx, uint8_t* Gy) {
    //Set curve parameters
    bigint_from_hexbuf(&prime, p, 20);
    bigint_from_hexbuf(&curve_a, a, 20);
    bigint_from_hexbuf(&curve_b, b, 20);
    bigint_from_hexbuf(&order_n, N, 21);

    //Set base point
    bigint_from_hexbuf(&base_point.x, Gx, 20);
    bigint_from_hexbuf(&base_point.y, Gy, 20);
    base_point.infinity = 0;
    return 0;
}

/**
 * Set public key
 */
void ecdsa_set_pub(uint8_t* Q) {
    bigint_from_hexbuf(&pub_key.x, Q, 20);
    bigint_from_hexbuf(&pub_key.y, Q + 20, 20);
    return;
}

/**
 * Set private key
 */
void ecdsa_set_priv(uint8_t* ink){
    bigint_from_hexbuf(&priv_key, ink, 20);
}

/**
 * ECDSA public key generation by a private key
 */
void ec_priv_to_pub(uint8_t* k, uint8_t* Q)
{
    bigint160_t d;
    ec_point_t ec_temp;
    bigint_from_hexbuf(&d, k, 21);
    bigint_mod(&d, &d, &order_n);
    ec_point_mul(&ec_temp, &d, &base_point);

    // Copy the result
    bigint_to_hexbuf(Q, &ec_temp.x, 20);
    bigint_to_hexbuf(Q + 20, &ec_temp.y, 20);
    bigint_to_hexbuf(k, &d, 21);   
}

/**
 * ECDSA public key scalar multiplication
 */
void ec_pub_mult(uint8_t* k, uint8_t* Q)
{
    bigint160_t scalar;
    ec_point_t ec_temp;
    bigint_from_hexbuf(&scalar, k, 21);
    ec_point_mul(&ec_temp, &scalar, &pub_key);

    // Copy the result
    bigint_to_hexbuf(Q, &ec_temp.x, 20);
    bigint_to_hexbuf(Q + 20, &ec_temp.y, 20);
}

/**
 * Print curve parameters
 */
void dump_ecc(void) {
    bigint_print("P ", &prime);
    bigint_print("a ", &curve_a);
    bigint_print("b ", &curve_b);
    bigint_print("N ", &order_n);
    bigint_print("Gx", &base_point.x);
    bigint_print("Gy", &base_point.y);
}

/**
 * Check if a point is on the curve
 */
int point_is_on_curve(const uint8_t* p){
    ec_point_t point;
    bigint160_t s, t;

    bigint_from_hexbuf(&point.x, p, 20);
    bigint_from_hexbuf(&point.y, p + 20, 20);

    bigint_mod_mul(&t, &point.x, &point.x, &prime);
    bigint_mod_mul(&s, &t, &point.x, &prime); //s = x^3

    bigint_mod_mul(&t, &point.x, &curve_a, &prime);
    bigint_add(&s, &s, &t); //s = x^3 + a*x

    bigint_add(&s, &s, &curve_b); //s = x^3 + a*x + b
    bigint_mod(&s, &s, &prime);

    bigint_mod_mul(&t, &point.y, &point.y, &prime);  //t = y^2 
    bigint_print("S ", &s);
    bigint_print("T ", &t);
    bigint_sub(&s, &s, &t); //is s - t = 0 ?
    return bigint_is_zero(&s);
}
