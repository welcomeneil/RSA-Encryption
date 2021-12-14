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

#define OPTIONS "i:o:n:vh"

void help_func(void);

int main(int argc, char **argv) {

    bool verbose = false;

    // Initialize all mpz_t variables that we'll be using in decrypt.
    // n: product of p and q (public modulus)
    // d: private key
    mpz_t n, d;
    mpz_inits(n, d, NULL);

    // Sets default input and output to stdin and stdout respectively.
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *privkey = NULL;

    // Variables to store file names specified by the user.
    char *infile_name = NULL;
    char *outfile_name = NULL;

    // The private key file is 'rsa.priv' by default.
    char *privkey_name = "rsa.priv";

    int opt = 0;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        if (opt == '?') {
            help_func();
            mpz_clears(n, d, NULL);
            return 1;
        }
        switch (opt) {
        case 'i': infile_name = optarg; break;
        case 'o': outfile_name = optarg; break;
        case 'n': privkey_name = optarg; break;
        case 'v': verbose = true; break;
        case 'h':
            help_func();
            mpz_clears(n, d, NULL);
            return 1;
        }
    }

    // Opening of files...

    privkey = fopen(privkey_name, "r");
    // If the file fails to open, print an error.
    if (!privkey) {
        fprintf(stderr, "Error: failed to open file.\n");
        mpz_clears(n, d, NULL);
        return 1;
    }

    if (infile_name != NULL) {
        infile = fopen(infile_name, "r");

        // If the file fails to open, print and error.
        if (!infile) {
            mpz_clears(n, d, NULL);
            fclose(privkey);
            fprintf(stderr, "Error: failed to open infile.\n");
            return 1;
        }
    }

    if (outfile_name != NULL) {
        outfile = fopen(outfile_name, "w");

        // If the file fails to open, print and error.
        if (!outfile) {
            mpz_clears(n, d, NULL);
            fclose(privkey);
            fclose(infile);
            fprintf(stderr, "Error: failed to open infile.\n");
            return 1;
        }
    }

    // Reads in the private key from privkey.
    rsa_read_priv(n, d, privkey);

    // If the user wants verbose output, print out all of the following to stdout...
    if (verbose) {
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    // Decrypt the infile and send the message to outfile.
    rsa_decrypt_file(infile, outfile, n, d);

    // Freeing of allocated memory.
    mpz_clears(n, d, NULL);
    fclose(privkey);
    fclose(infile);
    fclose(outfile);
    return 0;
}

// Helper function to print out manual page.
void help_func(void) {
    printf("SYNOPSIS\n"
           "  Decrypts data using RSA decryption.\n"
           "  Encrypted data is encrypted by the encrypt program.\n\n"
           "USAGE\n"
           "  ./decrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n\n"
           "OPTIONS\n"
           "  -h             Display program help and usage.\n"
           "  -v             Display verbose program output.\n"
           "  -i infile      Input file of data to decrypt (default: stdin).\n"
           "  -o outfile     Output file for decrypted data (default: stdout).\n"
           "  -n pvfile      Private key file (default: rsa.priv).\n");
    return;
}
