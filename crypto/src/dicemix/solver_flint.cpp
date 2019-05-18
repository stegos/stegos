#include <vector>
#include <cstring>

#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/fmpz_mod_polyxx.h>

using namespace std;
using namespace flint;

#define RET_INVALID 1
#define RET_NON_MONIC_ROOT 2
#define RET_NOT_ENOUGH_ROOTS 3

#define RET_INTERNAL_ERROR 100
#define RET_INPUT_ERROR 101

int solve_impl(vector<fmpzxx> &messages, const fmpzxx &p, const vector<fmpzxx> &sums)
{
    vector<fmpzxx>::size_type n = sums.size();
    if (n < 2)
    {
#ifdef DEBUG
        cout << "Input vector too short." << endl;
#endif
        return RET_INPUT_ERROR;
    }

    // Basic sanity check to avoid weird inputs
    if (n > 1000)
    {
#ifdef DEBUG
        cout << "You probably do not want an input vector of more than 1000 elements. " << endl;
#endif
        return RET_INPUT_ERROR;
    }

    if (messages.size() != sums.size())
    {
#ifdef DEBUG
        cout << "Output vector has wrong size." << endl;
#endif
        return RET_INPUT_ERROR;
    }

    if (p <= n)
    {
#ifdef DEBUG
        cout << "Prime must be (way) larger than the size of the input vector." << endl;
#endif
        return RET_INPUT_ERROR;
    }

    fmpz_mod_polyxx poly(p);
    fmpz_mod_poly_factorxx factors;
    factors.fit_length(n);
    vector<fmpzxx> coeff(n);

    // Set lead coefficient
    poly.set_coeff(n, 1);

    fmpzxx inv;
    // Compute other coeffients
    for (vector<fmpzxx>::size_type i = 0; i < n; i++)
    {
        coeff[i] = sums[i];

        vector<fmpzxx>::size_type k = 0;
        // for j = i-1, ..., 0
        for (vector<fmpzxx>::size_type j = i; j-- > 0;)
        {
            coeff[i] += coeff[k] * sums[j];
            k++;
        }
        inv = i;
        inv = -(inv + 1u);
        inv = inv.invmod(p);
        coeff[i] *= inv;
        poly.set_coeff(n - i - 1, coeff[i]);
    }

#if defined(DEBUG) && defined(STANDALONE)
    cout << "Polynomial: " << endl;
    print(poly);
    cout << endl
         << endl;
#endif

    // Factor
    factors.set_factor_kaltofen_shoup(poly);

#if defined(DEBUG) && defined(STANDALONE)
    cout << "Factors: " << endl;
    print(factors);
    cout << endl
         << endl;
#endif

    vector<fmpzxx>::size_type n_roots = 0;
    for (int i = 0; i < factors.size(); i++)
    {
        if (factors.p(i).degree() != 1 || factors.p(i).lead() != 1)
        {
#if defined(DEBUG) && defined(STANDALONE)
            cout << "Non-monic factor." << endl;
#endif
            return RET_NON_MONIC_ROOT;
        }
        n_roots += factors.exp(i);
    }
    if (n_roots != n)
    {
#if defined(DEBUG) && defined(STANDALONE)
        cout << "Not enough roots." << endl;
#endif
        return RET_NOT_ENOUGH_ROOTS;
    }

    // Extract roots
    int k = 0;
    for (int i = 0; i < factors.size(); i++)
    {
        for (int j = 0; j < factors.exp(i); j++)
        {
            messages[k] = factors.p(i).get_coeff(0).negmod(p);
            k++;
        }
    }

    return 0;
}

#ifdef STANDALONE
int main(int argc, char *argv[])
{
    fmpzxx p;
    p.read();

    vector<fmpzxx>::size_type n;
    cin >> n;

    vector<fmpzxx> s(n);
    vector<fmpzxx> messages(n);

    fmpzxx m;
    m.read();

    for (vector<fmpzxx>::iterator it = s.begin(); it != s.end(); it++)
    {
        it->read();
    }

    int ret = solve_impl(messages, p, s);

    if (ret == 0)
    {
        cout << "Messages:" << endl
             << "[";
        for (vector<fmpzxx>::iterator it = messages.begin(); it != messages.end(); it++)
        {
            cout << *it << ", ";
        }
        cout << "]" << endl;
    }

    return ret;
}
#endif

extern "C" int solve(char **const out_messages, const char *prime, const char **const sums, size_t n)
{
    // Exceptions should never propagate to C (undefined behavior).
    try
    {
        fmpzxx p;
        fmpzxx m;

        vector<fmpzxx> s(n);
        vector<fmpzxx> messages(n);

        // operator= is hard-coded to base 10 and does not check for errors
        if (fmpz_set_str(p._fmpz(), prime, 16))
        {
            return RET_INPUT_ERROR;
        }

        for (size_t i = 0; i < n; i++)
        {
            if (fmpz_set_str(s[i]._fmpz(), sums[i], 16))
            {
                return RET_INPUT_ERROR;
            }
        }

        for (size_t i = 0; i < n; i++)
        {
            if (out_messages[i] == NULL)
            {
                return RET_INPUT_ERROR;
            }
        }

        int ret = solve_impl(messages, p, s);

        if (ret == 0)
        {
            for (size_t i = 0; i < n; i++)
            {
                // Impossible
                if (messages[i].sizeinbase(16) > strlen(prime))
                {
                    return RET_INTERNAL_ERROR;
                }
                fmpz_get_str(out_messages[i], 16, messages[i]._fmpz());
            }
        }

        return ret;
    }
    catch (...)
    {
        return RET_INTERNAL_ERROR;
    }
}

extern "C" void dum_wau(char *p, size_t nel)
{
    // external C do-nothing stub for WAU (Wipe After Use)
    // to force Rust into not optimizing away in Drop
}
