#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"
#include <stdlib.h>
#include <inttypes.h>

// Makes a public key in the pair <e, n>
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    uint64_t remainder_bits = 0;

    mpz_t rand_num_bits, range, nbits_div_four, p_min_one, q_min_one, totient, gcd_e;

    mpz_inits(rand_num_bits, range, nbits_div_four, p_min_one, q_min_one, totient, gcd_e, NULL);

    // Calculates (nbits / 4) and sets nbits_div_four to the quotient.
    mpz_set_ui(nbits_div_four, nbits);
    mpz_fdiv_q_ui(nbits_div_four, nbits_div_four, 4);

    // Calculates the range.
    mpz_set_ui(range, nbits);
    mpz_mul_ui(range, range, 3);
    mpz_fdiv_q_ui(range, range, 4);
    mpz_sub(range, range, nbits_div_four);

    // Generates a random number of bits from range [(nbits / 4), (3 x nbits) / 4] for prime number "p".
    mpz_urandomm(rand_num_bits, state, range);
    mpz_add(rand_num_bits, rand_num_bits, nbits_div_four);

    // Finds the amount of bits left over for "q".
    remainder_bits = nbits - mpz_get_ui(rand_num_bits);

    // Make the prime numbers "p" and "q"
    make_prime(p, mpz_get_ui(rand_num_bits), iters);
    make_prime(q, remainder_bits, iters);
    mpz_mul(n, p, q);

    // Calculates the totient, totient(n) = (p - 1)(q - 1)
    mpz_sub_ui(p_min_one, p, 1);
    mpz_sub_ui(q_min_one, q, 1);
    mpz_mul(totient, p_min_one, q_min_one);

    // Find the public exponent.
    do {
        mpz_urandomb(e, state, nbits);
        gcd(gcd_e, e, totient);
    } while (mpz_cmp_ui(gcd_e, 1) != 0);

    // Freeing of allocated memory.
    mpz_clears(rand_num_bits, range, nbits_div_four, p_min_one, q_min_one, totient, gcd_e, NULL);
    return;
}

// Writes the public key to pbfile in the order n, e, s, and the username, each of which have a trailing new line after.
// n, e, and s are written as hexstrings.
// Each element has a trailing newline after.
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile,
        "%Zx\n"
        "%Zx\n"
        "%Zx\n"
        "%s\n",
        n, e, s, username);
    return;
}

// Reads the public key from file pointer pbfile.
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n %Zx\n %Zx\n %s\n", n, e, s, username);
    return;
}

// Generates a private key "d" by computing the modular inverse of "e" mod totient(n).
// totient(n) = (p - 1)(q - 1) where "p" and "q" are prime numbers.
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t p_min_one, q_min_one, totient;
    mpz_inits(p_min_one, q_min_one, totient, NULL);

    // Calculates the totient, totient(n) = (p - 1)(q - 1).
    mpz_sub_ui(p_min_one, p, 1);
    mpz_sub_ui(q_min_one, q, 1);
    mpz_mul(totient, p_min_one, q_min_one);

    // Computes the inverse of e mod totient(n).
    mod_inverse(d, e, totient);

    // Freeing of allocated memory.
    mpz_clears(p_min_one, q_min_one, totient, NULL);
    return;
}

// Writes the private key to pvfile in the order n, then d, each of which have a trailing new line after.
// n and d are written as hexstrings.
// Each element has a trailing newline after.
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile,
        "%Zx\n"
        "%Zx\n",
        n, d);
    return;
}

// Reads the private key from file pointer pvfile.
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n %Zx\n", n, d);
    return;
}

// Encrypts a message "m" by taking "m" to the power of public exponent "e" mod "n".
// Stores the ciphertext in "c".
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
    return;
}

// Encrypts an infile in k byte blocks.
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    uint64_t k = 0;
    uint64_t j = 0;
    mpz_t m, c;

    mpz_inits(m, c, NULL);

    // Calculate the block size k.
    k = ((mpz_sizeinbase(n, 2) - 1) / 8);

    // Dynamically allocate an array that can hold k bytes.
    // Set the 0th byte to 0xFF.
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));
    block[0] = 0xFF;

    // While we haven't reached EOF, read in k bytes at a time, import them into an mpz_t, encrypt the mpz_t, then print to the outfile.
    while (!feof(infile)) {
        j = fread(block + 1, sizeof(uint8_t), k - 1, infile);
        mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, block);
        rsa_encrypt(c, m, e, n);
        gmp_fprintf(outfile, "%Zx\n", c);
    }

    // Freeing of allocated memory.
    free(block);
    mpz_clears(m, c, NULL);
    return;
}

// Decrypts a ciphertext "c" by taking "c" to the power of private exponent "d" mod "n".
// Stores the message in "m".
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
    return;
}

// Decrypts an infile in k byte blocks.
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    uint64_t k = 0;
    uint64_t j = 0;
    mpz_t m, c;

    mpz_inits(m, c, NULL);

    // Calculate the block size k.
    k = ((mpz_sizeinbase(n, 2) - 1) / 8);

    // Dynamically allocate an array that can hold k bytes.
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));

    // While we haven't reached EOF, scan in hexstrings from infile, decrypt them, export them as bytes into block, then write them to the outfile.
    while (!feof(infile)) {
        gmp_fscanf(infile, "%Zx\n", c);
        rsa_decrypt(m, c, d, n);
        mpz_export(block, &j, 1, sizeof(uint8_t), 1, 0, m);
        fwrite(block + 1, sizeof(uint8_t), j - 1, outfile);
    }

    // Freeing of allocated memory.
    free(block);
    mpz_clears(m, c, NULL);
    return;
}

// Performs RSA signing.
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
    return;
}

// Performs RSA verification.
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n);
    // If t isn't the same as the expected message m, return false.
    if (mpz_cmp(m, t) != 0) {
        mpz_clear(t);
        return false;
    }
    mpz_clear(t);
    return true;
}
