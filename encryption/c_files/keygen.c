#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#define OPTIONS "b:i:n:d:s:vh"

void help_func(void);

int main(int argc, char **argv) {

    // Default values for the command line options.
    uint64_t num_bits = 256;
    uint64_t mr_iters = 50;
    time_t seed = time(NULL);
    char *username = NULL;
    bool verbose = false;

    // Initialize all mpz_t variables that we'll be using in keygen.
    // p: prime number 1
    // q: prime number 2
    // n: product of p and q
    // e: public exponent
    // d: private key
    // user: username of type mpz_t
    // s: signature
    mpz_t p, q, n, e, d, user, s;
    mpz_inits(p, q, n, e, d, user, s, NULL);

    // File pointers for public and private keys.
    FILE *pbfile = NULL;
    FILE *pvfile = NULL;

    // Variables to store file names specified by the user.
    char *pbfile_name = "rsa.pub";
    char *pvfile_name = "rsa.priv";

    int opt = 0;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        if (opt == '?') {
            help_func();
            mpz_clears(p, q, n, e, d, user, s, NULL);
            return 1;
        }
        switch (opt) {
        case 'b': num_bits = strtoul(optarg, NULL, 10); break;
        case 'i': mr_iters = strtoul(optarg, NULL, 10); break;
        case 'n': pbfile_name = optarg; break;
        case 'd': pvfile_name = optarg; break;
        case 's': seed = strtoul(optarg, NULL, 10); break;
        case 'v': verbose = true; break;
        case 'h':
            help_func();
            mpz_clears(p, q, n, e, d, user, s, NULL);
            return 1;
        }
    }

    // Opening of files to print the public and private keys to.
    pbfile = fopen(pbfile_name, "w");
    pvfile = fopen(pvfile_name, "w");

    // If the file fails to open, print an error.
    if (!pbfile || !pvfile) {
        fprintf(stderr, "Error: failed to open file.\n");
        return 1;
    }

    // Setting the permissions of the private key file to 0600, or read and write permissions for the USER ONLY.
    int fd = fileno(pvfile);
    fchmod(fd, 0600);

    // Initialize the random state with the given seed.
    randstate_init(seed);

    // Make both public and private keys.
    rsa_make_pub(p, q, n, e, num_bits, mr_iters);
    rsa_make_priv(d, e, p, q);

    // Retrieve the user's username; if we fail to retrieve the username, set the username to 'USER'.
    username = getenv("USER");
    if (!username) {
        fprintf(stderr, "Error: failed to retrieve username, setting username to 'USER'.\n");
        username = "USER";
    }

    // Sign the username.
    mpz_set_str(user, username, 62);
    rsa_sign(s, user, d, n);

    // Write both the public and private keys to their respective files.
    rsa_write_pub(n, e, s, username, pbfile);
    rsa_write_priv(n, d, pvfile);

    // If the user wants verbose output, print out all of the following to stdout...
    if (verbose) {
        printf("user = %s\n", username);
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("p (%d bits) = %Zd\n", mpz_sizeinbase(p, 2), p);
        gmp_printf("q (%d bits) = %Zd\n", mpz_sizeinbase(q, 2), q);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    // Freeing of allocated memory.
    mpz_clears(p, q, n, e, d, user, s, NULL);
    randstate_clear();
    fclose(pbfile);
    fclose(pvfile);
    return 0;
}

// Helper function to print out manual page.
void help_func(void) {
    printf("SYNOPSIS\n"
           "  Generates an RSA public/private key pair.\n\n"
           "USAGE\n"
           "  ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n\n"
           "OPTIONS\n"
           "  -h             Display program help and usage.\n"
           "  -v             Display verbose program output.\n"
           "  -b bits        Minimum bits needed for public key n.\n"
           "  -i iterations  Miller-Rabin iterations for testing primes (default: 50).\n"
           "  -n pbfile      Public key file (default: rsa.pub).\n"
           "  -d pvfile      Private key file (default: rsa.priv).\n"
           "  -s seed        Random seed for testing.\n");
    return;
}
