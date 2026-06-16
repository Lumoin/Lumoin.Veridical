using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Structural invariants for short Weierstrass curves over a prime field.
/// </summary>
/// <remarks>
/// <para>
/// A short Weierstrass curve over <c>Fp</c> is defined by the equation
/// <c>y^2 ≡ x^3 + a*x + b (mod p)</c>. For every named curve the library
/// supports, the spec fixes the canonical generator coordinates
/// <c>(x_gen, y_gen)</c> and the curve parameters <c>(a, b, p)</c>. A
/// typo in any of those five constants makes the equation fail, but only
/// at the very specific input it relates — making it an excellent
/// witness for catching transcription errors. The check has no
/// cryptographic significance and runs in microseconds, so it is suitable
/// for unconditional verification at test-class setup.
/// </para>
/// </remarks>
public static class WeierstrassDiagnostics
{
    /// <summary>
    /// Verifies that <c>(x, y)</c> satisfies the short Weierstrass curve
    /// equation <c>y^2 ≡ x^3 + a*x + b (mod p)</c>.
    /// </summary>
    /// <param name="x">The x-coordinate to test.</param>
    /// <param name="y">The y-coordinate to test.</param>
    /// <param name="a">The curve coefficient of <c>x</c>.</param>
    /// <param name="b">The curve constant term.</param>
    /// <param name="p">The field modulus. Must be greater than three.</param>
    /// <returns><see langword="true"/> if the equation holds; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="p"/> is less than or equal to three.</exception>
    /// <remarks>
    /// <para>
    /// The inputs are reduced modulo <paramref name="p"/> internally, so
    /// callers may pass either canonical-form values in <c>[0, p)</c> or
    /// the wider integer the value represents. Negative or out-of-range
    /// inputs are accepted and reduced.
    /// </para>
    /// </remarks>
    public static bool SatisfiesShortWeierstrass(
        BigInteger x,
        BigInteger y,
        BigInteger a,
        BigInteger b,
        BigInteger p)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(p, 3);

        BigInteger xMod = ReduceNonNegative(x, p);
        BigInteger yMod = ReduceNonNegative(y, p);
        BigInteger aMod = ReduceNonNegative(a, p);
        BigInteger bMod = ReduceNonNegative(b, p);

        BigInteger lhs = (yMod * yMod) % p;
        BigInteger xCubed = ((xMod * xMod) % p * xMod) % p;
        BigInteger rhs = ReduceNonNegative(xCubed + (aMod * xMod) + bMod, p);

        return lhs == rhs;
    }


    private static BigInteger ReduceNonNegative(BigInteger value, BigInteger modulus)
    {
        BigInteger result = value % modulus;
        if(result.Sign < 0)
        {
            result += modulus;
        }


        return result;
    }
}