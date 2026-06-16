using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// Deterministic full-width canonical scalar material for agreement tests and
/// benchmarks: every 4-byte word of a wide pattern is scrambled from the salt,
/// the element index, and the byte offset, then the wide value is reduced into
/// the curve's scalar field — so products exercise every limb (not just low
/// words), runs reproduce exactly, and distinct salts give distinct streams.
/// </summary>
/// <remarks>
/// The scrambling constants are classics, named here for the casual reader as
/// much as for the compiler: multiplying by the golden-ratio constants
/// scatters consecutive inputs maximally far apart in the word (Knuth's
/// multiplicative hashing, TAOCP vol. 3 §6.4), and the Fermat prime spreads
/// the byte offset without sharing factors with the power-of-two strides
/// around it.
/// </remarks>
internal static class DeterministicScalarFill
{
    //floor(2^32 / φ) where φ is the golden ratio — Knuth's 32-bit
    //multiplicative-hashing constant. Multiplying the salt by it turns small
    //consecutive salts into well-scattered word patterns.
    private const uint KnuthGoldenRatio32 = 2654435761;

    //floor(2^16 / φ) — the 16-bit counterpart, scattering the element index.
    private const int KnuthGoldenRatio16 = 40503;

    //The Fermat prime F4 = 2^16 + 1: an odd multiplier coprime to every
    //power-of-two stride, spreading the byte offset across the word.
    private const int FermatPrimeF4 = 65537;

    private const int ScalarSize = 32;
    private const int WordSize = sizeof(int);


    /// <summary>
    /// Fills <paramref name="destination"/> (a whole number of 32-byte slots)
    /// with deterministic canonical scalars derived from
    /// <paramref name="salt"/>.
    /// </summary>
    /// <param name="destination">The destination; a multiple of 32 bytes.</param>
    /// <param name="salt">The stream selector; distinct salts give distinct scalar sequences.</param>
    /// <param name="reduce">The scalar-reduce backend for <paramref name="curve"/>.</param>
    /// <param name="curve">The curve whose scalar field the values are reduced into.</param>
    public static void FillCanonical(Span<byte> destination, int salt, ScalarReduceDelegate reduce, CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(reduce);

        Span<byte> wide = stackalloc byte[ScalarSize];
        int count = destination.Length / ScalarSize;
        for(int i = 0; i < count; i++)
        {
            for(int b = 0; b < ScalarSize; b += WordSize)
            {
                //The | 1 keeps every word non-zero so no scalar degenerates
                //to small values even at salt and index zero.
                int word = unchecked(salt * (int)KnuthGoldenRatio32) ^ (i * KnuthGoldenRatio16) ^ (b * FermatPrimeF4) | 1;
                BinaryPrimitives.WriteInt32BigEndian(wide.Slice(b, WordSize), word);
            }

            reduce(wide, destination.Slice(i * ScalarSize, ScalarSize), curve);
        }
    }
}
