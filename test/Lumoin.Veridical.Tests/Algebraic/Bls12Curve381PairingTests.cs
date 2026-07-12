using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property tests for the BLS12-381 optimal-Ate pairing reference and
/// the Fp12 Frobenius / cyclotomic-square delegates. The load-bearing
/// structural checks at this layer are bilinearity
/// <c>e([a]P, Q) = e(P, [a]Q)</c> — the defining property of a pairing
/// — non-degeneracy <c>e(G1, G2) ≠ 1</c>, and the Frobenius
/// identity <c>π^12 = id</c> on Fp12. A wrong Frobenius constant or a
/// sign mistake in the Miller-loop line evaluation would surface as
/// one of these failing.
/// </summary>
/// <remarks>
/// There is no external KAT here. The IETF BBS+ test vectors that
/// arrive in batch H.5 are the external gate for the pairing
/// implementation; until then bilinearity + non-degeneracy +
/// Frobenius-identity are the strongest internal-consistency checks
/// available without hand-transcribing a known-good <c>e(G1, G2)</c>
/// hex from another implementation (a transcription gate is itself a
/// failure mode worth avoiding).
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381PairingTests
{
    private static readonly Fp12FrobeniusDelegate Frobenius = Bls12Curve381BigIntegerPairingReference.GetFrobenius();
    private static readonly Fp12CyclotomicSquareDelegate CyclotomicSquare = Bls12Curve381BigIntegerPairingReference.GetCyclotomicSquare();
    private static readonly PairingDelegate Pair = Bls12Curve381BigIntegerPairingReference.GetPairing();

    private static readonly Fp12SquareDelegate RegularSquare = Bls12Curve381BigIntegerFp12Reference.GetSquare();

    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G2ScalarMultiplyDelegate G2ScalarMul = Bls12Curve381BigIntegerG2Reference.GetScalarMultiply();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private static readonly G1IsOnCurveDelegate G1IsOnCurve = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static readonly G2IsOnCurveDelegate G2IsOnCurve = Bls12Curve381BigIntegerG2Reference.GetIsOnCurve();

    private static readonly BigInteger BaseFieldPrime = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;

    //CsCheck iteration count: kept very small because a full pairing
    //takes ~500ms in BigInteger. Frobenius-only tests run with more.
    private const long PairingIterationCount = 3;
    private const long FrobeniusIterationCount = 20;


    [TestMethod]
    public void FrobeniusTwelfthPowerIsIdentity()
    {
        //π^12 = id on Fp12 (since Fp12 has characteristic p and 12 is
        //the embedding degree). Catches any sign or value mistake in
        //the γ-constants computed from ξ at static init.
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element original = ReduceAndWrapFp12(raw);
                Fp12Element current = ReduceAndWrapFp12(raw);
                try
                {
                    for(int i = 0; i < 12; i++)
                    {
                        Fp12Element next = current.Frobenius(Frobenius, BaseMemoryPool.Shared);
                        current.Dispose();
                        current = next;
                    }

                    return current.AsReadOnlySpan().SequenceEqual(original.AsReadOnlySpan());
                }
                finally
                {
                    current.Dispose();
                }
            }, iter: FrobeniusIterationCount);
    }


    [TestMethod]
    public void FrobeniusFixesFpEmbedding()
    {
        //An Fp element lifted into Fp12 (as the (a,0) → ((a,0),0,0) → ((((a,0),0,0),0)
        //tower lift) is fixed by Frobenius because a^p = a for a ∈ Fp.
        byte[] bytes = new byte[WellKnownCurves.Bls12Curve381Fp12SizeBytes];
        bytes[WellKnownCurves.Bls12Curve381BaseFieldSizeBytes - 1] = 0x07;  //Fp value 7 in the c0.c0.c0.c0 slot.

        using Fp12Element fpElement = Fp12Element.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Fp12Element frobenius = fpElement.Frobenius(Frobenius, BaseMemoryPool.Shared);
        Assert.IsTrue(fpElement.AsReadOnlySpan().SequenceEqual(frobenius.AsReadOnlySpan()), "Frobenius must fix elements of the Fp-embedding inside Fp12.");
    }


    [TestMethod]
    public void CyclotomicSquareAgreesWithRegularSquare()
    {
        //In the reference cyclotomic-square is implemented as the
        //regular Fp12 square. This documents the contract: any
        //production backend specialising cyclotomic-square must agree
        //with regular-square byte-for-byte on inputs that lie in the
        //cyclotomic subgroup.
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrapFp12(raw);
                using Fp12Element cycSq = a.CyclotomicSquare(CyclotomicSquare, BaseMemoryPool.Shared);
                using Fp12Element regSq = a.Square(RegularSquare, BaseMemoryPool.Shared);
                return cycSq.AsReadOnlySpan().SequenceEqual(regSq.AsReadOnlySpan());
            }, iter: FrobeniusIterationCount);
    }


    [TestMethod]
    public void PairingOfGeneratorsIsNonTrivial()
    {
        //e(G1, G2) must be neither the Fp12 identity nor zero — otherwise the
        //pairing is degenerate and useless cryptographically.
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Fp12Element result = g1.PairWith(g2, Pair, BaseMemoryPool.Shared);
        Assert.IsFalse(result.IsZero, "e(G1, G2) must not be zero.");
        Assert.IsFalse(result.IsOne, "e(G1, G2) must not be the Fp12 identity (would indicate a degenerate pairing).");
    }


    [TestMethod]
    public void PairingWithG1IdentityIsOne()
    {
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Fp12Element result = identity.PairWith(g2, Pair, BaseMemoryPool.Shared);
        Assert.IsTrue(result.IsOne, "e(0, G2) must equal the Fp12 identity.");
    }


    [TestMethod]
    public void PairingWithG2IdentityIsOne()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Fp12Element result = g1.PairWith(identity, Pair, BaseMemoryPool.Shared);
        Assert.IsTrue(result.IsOne, "e(G1, 0) must equal the Fp12 identity.");
    }


    [TestMethod]
    public void CurveParameterHasCorrectMagnitudeAndSign()
    {
        //Guards against a .NET BigInteger.Parse gotcha: under
        //NumberStyles.HexNumber, a literal whose leading nibble has the
        //high bit set is read as a two's-complement negative number. The
        //BLS12-381 ate parameter |x| starts with 'd' (1101) and needs a
        //leading '0' on the literal to parse as the intended unsigned
        //value. Without it, the loop iterates 61 times instead of 63 and
        //bilinearity silently breaks.
        BigInteger expected = -BigInteger.Parse("0d201000000010000", NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        Assert.AreEqual(expected, Bls12Curve381BigIntegerPairingReference.CurveParameter);
        Assert.IsLessThan(BigInteger.Zero, Bls12Curve381BigIntegerPairingReference.CurveParameter);
        Assert.AreEqual(64, (int)BigInteger.Abs(Bls12Curve381BigIntegerPairingReference.CurveParameter).GetBitLength());
    }


    [TestMethod]
    public void PairingIsBilinearAcrossG1AndG2()
    {
        //e([a]·G1, G2) == e(G1, [a]·G2) — the defining bilinearity
        //identity. A wrong line evaluation, a wrong Miller-loop
        //iteration count, or a bad final exponentiation would all
        //break this; a flipped twist sign would too.
        Gen.Byte.Array[Scalar.SizeBytes]
            .Sample(raw =>
            {
                using Scalar a = ReduceToScalar(raw);
                using G1Point g1 = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
                using G2Point g2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
                using G1Point aG1 = g1.ScalarMultiply(a, G1ScalarMul, BaseMemoryPool.Shared);
                using G2Point aG2 = g2.ScalarMultiply(a, G2ScalarMul, BaseMemoryPool.Shared);
                using Fp12Element leftPairing = aG1.PairWith(g2, Pair, BaseMemoryPool.Shared);
                using Fp12Element rightPairing = g1.PairWith(aG2, Pair, BaseMemoryPool.Shared);
                return leftPairing.AsReadOnlySpan().SequenceEqual(rightPairing.AsReadOnlySpan());
            }, iter: PairingIterationCount);
    }


    [TestMethod]
    public void PairingRejectsOffCurveG1Point()
    {
        //The pairing-reference G1 decode must reject an off-curve abscissa rather than
        //fabricate a y with the unverified a^((p+1)/4) shortcut and pair against it.
        //The probe is pinned off-curve through the reference on-curve predicate first,
        //and the good operand is a genuine generator so no identity short-circuit can
        //hide the off-curve decode.
        byte[] offCurveG1 = BuildOffCurveG1();
        byte[] validG2 = GeneratorG2Compressed();
        Assert.IsFalse(G1IsOnCurve(offCurveG1, CurveParameterSet.Bls12Curve381), "The probe must be off-curve for the test to be meaningful.");

        Assert.ThrowsExactly<InvalidOperationException>(() => PairInto(offCurveG1, validG2));
    }


    [TestMethod]
    public void PairingRejectsOffCurveG2Point()
    {
        byte[] validG1 = GeneratorG1Compressed();
        byte[] offCurveG2 = BuildOffCurveG2();
        Assert.IsFalse(G2IsOnCurve(offCurveG2, CurveParameterSet.Bls12Curve381), "The probe must be off-curve for the test to be meaningful.");

        Assert.ThrowsExactly<InvalidOperationException>(() => PairInto(validG1, offCurveG2));
    }


    [TestMethod]
    public void PairingRejectsNonCanonicalG1XCoordinate()
    {
        //A masked x at or above the base-field prime is a non-canonical encoding; the
        //decode must reject it rather than reduce it. All-ones x bytes exceed p.
        byte[] validG2 = GeneratorG2Compressed();
        byte[] nonCanonicalG1 = new byte[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes];
        nonCanonicalG1.AsSpan().Fill(0xFF);
        nonCanonicalG1[0] = 0x9F;  //Compression set, infinity clear, low five x bits all one.

        Assert.ThrowsExactly<InvalidOperationException>(() => PairInto(nonCanonicalG1, validG2));
    }


    private static void PairInto(byte[] p, byte[] q)
    {
        Span<byte> result = stackalloc byte[WellKnownCurves.Bls12Curve381Fp12SizeBytes];
        Pair(p, q, result, CurveParameterSet.Bls12Curve381);
    }


    private static byte[] GeneratorG1Compressed()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return g1.AsReadOnlySpan().ToArray();
    }


    private static byte[] GeneratorG2Compressed()
    {
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return g2.AsReadOnlySpan().ToArray();
    }


    private static byte[] BuildOffCurveG1()
    {
        //Scan small abscissas for the first whose x³ + 4 is a quadratic non-residue,
        //ZCash-compressed with only the compression flag set.
        byte[] encoded = new byte[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes];
        for(int candidate = 1; candidate < 256; candidate++)
        {
            encoded.AsSpan().Clear();
            encoded[^1] = (byte)candidate;
            encoded[0] |= 0x80;
            if(!G1IsOnCurve(encoded, CurveParameterSet.Bls12Curve381))
            {
                return encoded;
            }
        }

        throw new InvalidOperationException("No off-curve G1 abscissa found in the scan range.");
    }


    private static byte[] BuildOffCurveG2()
    {
        //Scan small x.c0 with x.c1 = 0 for the first off the twist curve. Layout is
        //[x.c1 : 48 BE][x.c0 : 48 BE] with the flags in the leading c1 byte, so the
        //trailing byte carries x.c0.
        byte[] encoded = new byte[WellKnownCurves.Bls12Curve381G2CompressedSizeBytes];
        for(int candidate = 1; candidate < 256; candidate++)
        {
            encoded.AsSpan().Clear();
            encoded[^1] = (byte)candidate;
            encoded[0] |= 0x80;
            if(!G2IsOnCurve(encoded, CurveParameterSet.Bls12Curve381))
            {
                return encoded;
            }
        }

        throw new InvalidOperationException("No off-curve G2 abscissa found in the scan range.");
    }


    private static Fp12Element ReduceAndWrapFp12(ReadOnlySpan<byte> raw)
    {
        Span<byte> packed = stackalloc byte[WellKnownCurves.Bls12Curve381Fp12SizeBytes];
        packed.Clear();
        //12 Fp components, each 48 bytes; reduce each to canonical < p.
        for(int i = 0; i < 12; i++)
        {
            int start = i * CompSize;
            BigInteger raw_i = new(raw.Slice(start, CompSize), isUnsigned: true, isBigEndian: true);
            BigInteger reduced = raw_i % BaseFieldPrime;
            WriteCanonical(reduced, packed.Slice(start, CompSize));
        }

        return Fp12Element.FromCanonical(packed, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static Scalar ReduceToScalar(ReadOnlySpan<byte> raw)
    {
        Span<byte> bytes = stackalloc byte[Scalar.SizeBytes];
        Reduce(raw, bytes, CurveParameterSet.Bls12Curve381);
        return Scalar.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced Fp component did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}