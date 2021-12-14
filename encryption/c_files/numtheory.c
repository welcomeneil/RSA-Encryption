#include "numtheory.h"
#include "randstate.h"

// Computes the greatest common divisor of two numbers "a" and "b", then stores that value in "g".
void gcd(mpz_t g, mpz_t a, mpz_t b) {
    // Declares variables "a_temp" and "b_temp" that will hold the values of "mpz_t a" and "mpz_t b" respectively.
    // Also declares a variable that will hold a temporary value.
    mpz_t a_temp, b_temp, temp_var;

    // Initializes variables that were declared above.
    mpz_inits(a_temp, b_temp, temp_var, NULL);

    // Setting values.
    mpz_set(a_temp, a);
    mpz_set(b_temp, b);

    // While b_temp is greater than 0.
    while (mpz_cmp_ui(b_temp, 0) > 0) {
        // Sets the temporary variable to the value of b_temp.
        mpz_set(temp_var, b_temp);

        // Sets b_temp to the value of a_temp mod b_temp.
        mpz_mod(b_temp, a_temp, b_temp);

        // Sets a_temp to the value of the temporary variable.
        mpz_set(a_temp, temp_var);
    }

    // Sets g to the value of the temporary variable, the gcd.
    mpz_set(g, temp_var);

    // Freeing of allocated memory.
    mpz_clears(a_temp, b_temp, temp_var, NULL);
    return;
}

// Computes the inverse of "a" mod "n", and stores that value in "o".
// If there is no modular inverse that can be found, then "o" is set to 0
void mod_inverse(mpz_t o, mpz_t a, mpz_t n) {
    // Declares variables "r", "r_temp", "r_prime", "t", "t_temp", "t_prime", and "q".
    // The variables "r" and "r_prime" will hold the values of "n" and "a" respectively.
    // The variables "t" and "t_prime" will hold the values of 0 and 1 respectively.
    // The purpose of "r_temp" and "t_temp" is to hold the values of "r" and "t" when mimicing parallel assignment.
    mpz_t r, r_temp, r_prime, t, t_temp, t_prime, q;

    // Initializes variables that were declared above.
    mpz_inits(r, r_temp, r_prime, t, t_temp, t_prime, q, NULL);

    // Sets the value of "r" to "n".
    mpz_set(r, n);
    // Sets the value of "r_prime" to "a".
    mpz_set(r_prime, a);

    // Sets the value of "t" to 0.
    mpz_set_ui(t, 0);
    // Sets the value of "t_prime" to 1.
    mpz_set_ui(t_prime, 1);

    // While r_prime is not equal to 0...
    while (mpz_cmp_ui(r_prime, 0) != 0) {
        // q = floor(r / r_prime)
        mpz_fdiv_q(q, r, r_prime);

        // Set temp variables in preparation for parallel assignment.
        mpz_set(r_temp, r);
        mpz_set(t_temp, t);

        // r = r_prime
        mpz_set(r, r_prime);
        // r_prime = r - q x r_prime
        mpz_mul(r_prime, q, r_prime);
        mpz_sub(r_prime, r_temp, r_prime);

        // t = t_prime
        mpz_set(t, t_prime);
        // t_prime = t - q x t_prime
        mpz_mul(t_prime, q, t_prime);
        mpz_sub(t_prime, t_temp, t_prime);
    }

    // If no modular inverse was found, set "o" to 0.
    if (mpz_cmp_ui(r, 1) > 0) {
        mpz_set_ui(o, 0);
        mpz_clears(r, r_temp, r_prime, t, t_temp, t_prime, q, NULL);
        return;
    }

    // If t < 0, add "n" to the end.
    if (mpz_cmp_ui(t, 0) < 0) {
        mpz_add(t, t, n);
    }

    // Sets "o" to the modular inverse.
    mpz_set(o, t);

    // Freeing of allocated memory.
    mpz_clears(r, r_temp, r_prime, t, t_temp, t_prime, q, NULL);
    return;
}

// Performs fast modular exponentiation by computing "a" rasied to the power of "d" mod "n", then stores that vlaue in "o".
void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n) {
    // Declares variables "a_temp", "d_temp", and "n_temp" that will hold the values of "mpz_t a", "mpz_t d", "mpz_t n" respectively.
    // Also declares vairables "v" and "p" that will be intermediary variables between computations.
    mpz_t a_temp, d_temp, n_temp, v, p;

    // Initializes variables that were declared above.
    mpz_inits(a_temp, d_temp, n_temp, v, p, NULL);

    // Setting values.
    mpz_set(a_temp, a);
    mpz_set(d_temp, d);
    mpz_set(n_temp, n);
    mpz_set_ui(v, 1);
    mpz_set(p, a_temp);

    // While d > 0...
    while (mpz_cmp_ui(d_temp, 0) > 0) {
        // If d is odd...
        if (mpz_odd_p(d_temp) != 0) {
            // v = (v x p) mod n
            mpz_mul(v, v, p);
            mpz_mod(v, v, n);
        }

        // p = (p x p) mod n
        mpz_mul(p, p, p);
        mpz_mod(p, p, n);

        // d = floor(d / 2)
        mpz_fdiv_q_ui(d_temp, d_temp, 2);
    }
    // Sets "o" to the exponentiation.
    mpz_set(o, v);

    // Freeing of allocated memory.
    mpz_clears(a_temp, d_temp, n_temp, v, p, NULL);
    return;
}

// Performs the Miller-Rabin Primality test.
// Returns true if "n" is prime, otherwise returns false.
bool is_prime(mpz_t n, uint64_t iters) {
    // Declares variables "n_temp", "s", "r", "j", "rand_number", "range", "power_mod", "n_min_one", "s_min_one", and "param_of_two".
    // The variable "n_temp" will hold the value of "n".
    // Variables "s" and "r" will represent the variables in the equation, n - 1 = 2^s * r such that r is odd.
    // The variable "j" will hold values during arithmetic.
    // The variable "rand_number" will hold the value of a random number found in the range [2, n - 2].
    // The variable "range" will hold the range.
    // The variable "power_mod" will hold the modular exponentiation during each iteration.
    // The variables "n_min_one" and "s_min_one" wil hold the values of n - 1 and s - 1 without affecting their values.
    // The variable "param_of_two" will hold the value of 2 and be used as a parameter when calling pow_mod().
    mpz_t n_temp, s, r, j, rand_number, range, power_mod, n_min_one, s_min_one, param_of_two;

    // Initializes variables that were declared above.
    mpz_inits(
        n_temp, s, r, j, rand_number, range, power_mod, n_min_one, s_min_one, param_of_two, NULL);

    // Sets the values.
    mpz_set(n_temp, n);
    mpz_sub_ui(r, n_temp, 1);
    mpz_sub_ui(n_min_one, n_temp, 1);
    mpz_set_ui(param_of_two, 2);

    // Sets range to n - 3 since mpz_urandomm() picks a random number from range [0 - (n - 1)].
    // When adding 2 to our generated number from range [0 - (n - 1)], we will get a number within the range [2, (n - 2)], which is what we want.
    mpz_sub_ui(range, n_temp, 3);

    // If n is 2 or 3, then it's prime.
    if (mpz_cmp_ui(n_temp, 2) == 0 || mpz_cmp_ui(n_temp, 3) == 0) {
        mpz_clears(n_temp, s, r, j, rand_number, range, power_mod, n_min_one, s_min_one,
            param_of_two, NULL);
        return true;
    }

    // If n is even or 1, then it will not be prime.
    if (mpz_even_p(n_temp) != 0 || mpz_cmp_ui(n_temp, 1) == 0) {
        mpz_clears(n_temp, s, r, j, rand_number, range, power_mod, n_min_one, s_min_one,
            param_of_two, NULL);
        return false;
    }

    // n - 1 = 2^s * r such that r is odd
    while (mpz_even_p(r) != 0) {
        mpz_fdiv_q_ui(r, r, 2);
        mpz_add_ui(s, s, 1);
    }

    mpz_sub_ui(s_min_one, s, 1);

    // For i < iters...
    for (uint64_t i = 1; i < iters; i += 1) {
        // Pick a random number rand_num in the set {2,...,(n - 2)}
        mpz_urandomm(rand_number, state, range);
        mpz_add_ui(rand_number, rand_number, 2);

        // power_mod = rand_number ^ r (mod n)
        pow_mod(power_mod, rand_number, r, n_temp);

        // If power_mod is not equal to 1 and not equal to n - 1...
        if ((mpz_cmp_ui(power_mod, 1) != 0) && (mpz_cmp(power_mod, n_min_one) != 0)) {
            mpz_set_ui(j, 1);

            // While j <= s - 1 and power_mod is not equal to n - 1...
            while ((mpz_cmp(j, s_min_one) <= 0) && (mpz_cmp(power_mod, n_min_one) != 0)) {
                // power_mod = power_mod ^ 2 (mod n)
                pow_mod(power_mod, power_mod, param_of_two, n_temp);
                // If power_mod is equal to 1, return false.
                if (mpz_cmp_ui(power_mod, 1) == 0) {
                    mpz_clears(n_temp, s, r, j, rand_number, range, power_mod, n_min_one, s_min_one,
                        param_of_two, NULL);
                    return false;
                }
                mpz_add_ui(j, j, 1);
            }

            // If power_mod is not equal to n - 1, return false.
            if (mpz_cmp(power_mod, n_min_one) != 0) {
                mpz_clears(n_temp, s, r, j, rand_number, range, power_mod, n_min_one, s_min_one,
                    param_of_two, NULL);
                return false;
            }
        }
    }

    // Freeing of allocated memory.
    mpz_clears(
        n_temp, s, r, j, rand_number, range, power_mod, n_min_one, s_min_one, param_of_two, NULL);

    return true;
}

// Generates a prime number that is at least "bits" numbers of bits long.
// Stores the prime number in "p".
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    // Generate a random number from 0 - 2^n-1 inclusive.
    // While that number isn't prime OR its size in bits is less than "bits",
    // continue generating a number until it's  prime and at least "bits" number of bits long.
    do {
        mpz_urandomb(p, state, bits + 1);
    } while (!is_prime(p, iters) || mpz_sizeinbase(p, 2) < bits + 1);
    return;
}
