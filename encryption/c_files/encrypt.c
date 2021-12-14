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

    char username[1024];
    bool verbose = false;

    // Initialize all mpz_t variables that we'll be using in encrypt.
    // n: product of p and q (public modulus)
    // e: public exponent
    // s: signature
    // user: username of type mpz_t
    mpz_t n, e, s, user;
    mpz_inits(n, e, s, user, NULL);

    // Sets default input and output to stdin and stdout respectively.
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *pubkey = NULL;

    // Variables to store file names specified by the user.
    char *infile_name = NULL;
    char *outfile_name = NULL;

    // The public key file is 'rsa.pub' by default.
    char *pubkey_name = "rsa.pub";

    int opt = 0;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        if (opt == '?') {
            help_func();
            mpz_clears(n, e, s, user, NULL);
            return 1;
        }
        switch (opt) {
        case 'i': infile_name = optarg; break;
        case 'o': outfile_name = optarg; break;
        case 'n': pubkey_name = optarg; break;
        case 'v': verbose = true; break;
        case 'h':
            help_func();
            mpz_clears(n, e, s, user, NULL);
            return 1;
        }
    }

    // Opening of files...

    pubkey = fopen(pubkey_name, "r");
    // If the file fails to open, print an error.
    if (!pubkey) {
        fprintf(stderr, "Error: failed to open file.\n");
        mpz_clears(n, e, s, user, NULL);
        return 1;
    }

    if (infile_name != NULL) {
        infile = fopen(infile_name, "r");

        // If the file fails to open, print an error.
        if (!infile) {
            mpz_clears(n, e, s, user, NULL);
            fclose(pubkey);
            fprintf(stderr, "Error: failed to open infile.\n");
            return 1;
        }
    }

    if (outfile_name != NULL) {
        outfile = fopen(outfile_name, "w");

        // If the file fails to open, print an error.
        if (!outfile) {
            mpz_clears(n, e, s, user, NULL);
            fclose(pubkey);
            fprintf(stderr, "Error: failed to open infile.\n");
            return 1;
        }
    }

    // Read the public key, username, and signature from pubkey.
    rsa_read_pub(n, e, s, username, pubkey);

    // If the user wants verbose output, print out all of the following to stdout...
    if (verbose) {
        printf("user = %s\n", username);
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
    }

    // Verify the signature.
    mpz_set_str(user, username, 62);
    // If the signature isn't verified, throw an error and end the program.
    if (!rsa_verify(user, s, e, n)) {
        fprintf(stderr, "Error: Signature couldn't be verified.\n");
        mpz_clears(n, e, s, user, NULL);
        fclose(pubkey);
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    // Encrypt the infile and send the ciphertext to outfile.
    rsa_encrypt_file(infile, outfile, n, e);

    // Freeing of allocated memory.
    mpz_clears(n, e, s, user, NULL);
    fclose(pubkey);
    fclose(infile);
    fclose(outfile);
    return 0;
}

// Helper function to print out manual page.
void help_func(void) {
    printf("SYNOPSIS\n"
           "  Encrypts data using RSA encryption.\n"
           "  Encrypted data is decrypted by the decrypt program.\n\n"
           "USAGE\n"
           "  ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n\n"
           "OPTIONS\n"
           "  -h             Display program help and usage.\n"
           "  -v             Display verbose program output.\n"
           "  -i infile      Input file of data to encrypt (default: stdin).\n"
           "  -o outfile     Output file for encrypted data (default: stdout).\n"
           "  -n pbfile      Public key file (default: rsa.pub).\n");
    return;
}
