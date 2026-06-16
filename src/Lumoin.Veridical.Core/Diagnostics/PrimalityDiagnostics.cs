using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Mathematical witnesses for declared prime constants.
/// </summary>
/// <remarks>
/// <para>
/// The library declares a number of constants — base field primes, scalar
/// field orders — that callers and the library itself rely on being prime.
/// A transcription error in any of them is overwhelmingly likely to produce
/// a composite value, and a composite value silently breaks every algebraic
/// invariant the curve depends on (Fermat's little theorem, modular
/// inversion via Fermat, square roots via the <c>p ≡ 3 (mod 4)</c>
/// shortcut, subgroup membership checks via scalar multiplication by the
/// order, and so on). The diagnostics in this class let callers verify
/// declared primes against an independent mathematical witness — one that
/// cannot agree with a transcription error by accident — so a typo
/// surfaces as a clear assertion failure at the constant rather than as a
/// downstream encode/decode failure five layers later.
/// </para>
/// <para>
/// These are diagnostic helpers, not cryptographic primitives. They are
/// suitable for verifying that a constant the library claims is prime
/// actually is prime; they are not suitable for adversarial primality
/// testing (where an opponent picks the value to fool the test), and they
/// are not on any cryptographic hot path. <see cref="BigInteger"/> usage
/// here is therefore not "managed-runtime cryptography" — it is structural
/// verification of declared constants.
/// </para>
/// </remarks>
public static class PrimalityDiagnostics
{
    /// <summary>
    /// Returns <see langword="true"/> with overwhelming probability iff
    /// <paramref name="value"/> is prime. Uses Miller-Rabin with small fixed
    /// witnesses.
    /// </summary>
    /// <param name="value">The integer to test.</param>
    /// <param name="rounds">The number of Miller-Rabin witnesses to test against (default 8).</param>
    /// <returns>
    /// <see langword="true"/> if no witness proves <paramref name="value"/>
    /// composite after the requested number of rounds; otherwise
    /// <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="rounds"/> is less than one.</exception>
    /// <remarks>
    /// <para>
    /// The witnesses are the first <paramref name="rounds"/> small primes
    /// (2, 3, 5, 7, ...). For values up to roughly <c>3 · 10^24</c> a fixed
    /// set of witnesses gives a deterministic answer; for the larger primes
    /// this library uses (BLS12-381's 381-bit base field prime, for
    /// example) the answer is probabilistic with false-positive probability
    /// bounded above by <c>4^(-rounds)</c>. The intended failure mode this
    /// catches is human transcription error, where the resulting composite
    /// is overwhelmingly likely to be caught by the first witness, so the
    /// default round count is small.
    /// </para>
    /// </remarks>
    public static bool IsLikelyPrime(BigInteger value, int rounds = 8)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(rounds, 1);

        if(value < 2)
        {
            return false;
        }

        if(value < 4)
        {
            return true;
        }

        if(value.IsEven)
        {
            return false;
        }

        //Write value - 1 = d * 2^s with d odd. Miller-Rabin then tests, for each
        //small witness a, whether a^d ≡ 1 (mod value) or a^(d * 2^i) ≡ -1 (mod
        //value) for some 0 ≤ i < s. A witness for which neither holds is a proof
        //that value is composite.
        BigInteger d = value - BigInteger.One;
        int s = 0;
        while(d.IsEven)
        {
            d >>= 1;
            s++;
        }

        ReadOnlySpan<int> witnessPool = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41];
        int testedRounds = 0;
        foreach(int witness in witnessPool)
        {
            if(testedRounds >= rounds)
            {
                break;
            }

            if(witness >= value)
            {
                //Skipping a witness larger than value is conservative: very small
                //values that exit through this branch were already handled above,
                //so this is essentially a no-op safety net.
                break;
            }

            BigInteger x = BigInteger.ModPow(witness, d, value);
            if(x == BigInteger.One || x == value - BigInteger.One)
            {
                testedRounds++;
                continue;
            }

            bool nonWitness = false;
            for(int i = 0; i < s - 1; i++)
            {
                x = (x * x) % value;
                if(x == value - BigInteger.One)
                {
                    nonWitness = true;
                    break;
                }
            }

            if(!nonWitness)
            {
                return false;
            }

            testedRounds++;
        }


        return true;
    }
}