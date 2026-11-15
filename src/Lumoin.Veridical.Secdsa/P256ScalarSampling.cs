using System;
using static Lumoin.Veridical.Core.Cryptography.ConstantTimeComparison;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Samples a uniformly distributed P-256 scalar in <c>[1, n−1]</c> from a caller-supplied entropy source, as the
/// ephemeral private keys of ECIES (Verheul Algorithm 18 step 1) and of the interactive proof need.
/// </summary>
/// <remarks>
/// <b>Rejection sampling, no bias.</b> A candidate is 32 random bytes; it is accepted when it lies in
/// <c>[1, n−1]</c> and drawn again otherwise. For P-256 a candidate is rejected with probability about
/// <c>2⁻³²</c>, so the loop almost never repeats, and the accepted value is exactly uniform. Wide reduction
/// would avoid the loop at the price of a bias; the loop is bounded so that a broken entropy source, such as one
/// that returns a constant out of range, fails instead of hanging.
/// </remarks>
internal static class P256ScalarSampling
{
    /// <summary>The number of candidates drawn before the source is declared broken.</summary>
    internal const int MaxAttempts = 64;


    /// <summary>Draws a scalar in <c>[1, n−1]</c> into <paramref name="scalar"/>.</summary>
    /// <param name="entropy">The entropy source.</param>
    /// <param name="scalar">Receives the 32-byte big-endian scalar; cleared when sampling fails.</param>
    /// <exception cref="InvalidOperationException">When no candidate in range was drawn within <see cref="MaxAttempts"/> attempts.</exception>
    internal static void Sample(SecdsaEntropySource entropy, Span<byte> scalar)
    {
        for(int attempt = 0; attempt < MaxAttempts; attempt++)
        {
            entropy(scalar);
            if(!IsZero(scalar) && IsLess(scalar, OrderBytes))
            {
                return;
            }
        }

        scalar.Clear();

        throw new InvalidOperationException("The entropy source did not produce a scalar in [1, n-1]; it is broken or not random.");
    }
}
