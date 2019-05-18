#include <stddef.h>

/**
 * Solve function from protocol specification.
 *
 * Solves the equation system
 *   forall 0 <= i < n. sum_{j=0}^{n-1} out_messages[j]^{i+1} = sums[i]
 * in the finite prime field F_prime for out_messages[].
 *
 * \param[out] out_messages    Array of n char buffers (allocated by caller) of length at least strlen(prime) + 1
 * \param[in]  prime           Prime of the finite field (not checked for primality)
 * \param[in]  sums            Array of n power sums
 * \param[in]  n               Number of messages, must be at least 2 and not larger than prime
 *
 * \retval 0                   Success, the solution vector has been stored as hexadecimal strings in out_messages[].
 * \retval RET_INVALID         sums is not a proper array of power sums
 * \retval RET_INPUT_ERROR     Illegal input values.
 * \retval RET_INTERNAL_ERROR  An internal error occured.
 */
int solve(char **const out_messages, const char *prime, const char **const sums, size_t n);
void dum_wau(char *p, size_t nel);
