#include "randstate.h"
#include <gmp.h>

gmp_randstate_t state;

// This function initializes a global random state variable and sets its random seed.
void randstate_init(uint64_t seed) {
    // Initialize global random state variable
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    return;
}

// This function clears and frees all allocated memory used by the global random state variable.
void randstate_clear(void) {
    gmp_randclear(state);
    return;
}
