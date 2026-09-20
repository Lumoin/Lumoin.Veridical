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
/// There is no external KAT at this layer. The IETF BBS+ test vectors
/// are the external gate for the signature scheme the pairing
/// supports; for the pairing primitive itself, bilinearity +
/// non-degeneracy + Frobenius-identity are the strongest
/// internal-consistency checks available without hand-transcribing a
/// known-good <c>e(G1, G2)</c> hex from another implementation (a
/// transcription gate is itself a failure mode worth avoiding).
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381PairingTests
{
    /// <summary>The Fp12 Frobenius endomorphism delegate under test.</summary>
    private static Fp12FrobeniusDelegate Frobenius { get; } = Bls12Curve381BigIntegerPairingReference.GetFrobenius();
    /// <summary>The Fp12 cyclotomic-square delegate under test.</summary>
    private static Fp12CyclotomicSquareDelegate CyclotomicSquare { get; } = Bls12Curve381BigIntegerPairingReference.GetCyclotomicSquare();
    /// <summary>The BLS12-381 optimal-Ate pairing delegate under test.</summary>
    private static PairingDelegate Pair { get; } = Bls12Curve381BigIntegerPairingReference.GetPairing();

    /// <summary>The regular (non-cyclotomic) Fp12 squaring delegate, used as the ground truth <see cref="CyclotomicSquare"/> must agree with.</summary>
    private static Fp12SquareDelegate RegularSquare { get; } = Bls12Curve381BigIntegerFp12Reference.GetSquare();

    /// <summary>The BLS12-381 G1 scalar multiplication delegate used to build the bilinearity test's <c>[a]G1</c>.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    /// <summary>The BLS12-381 G2 scalar multiplication delegate used to build the bilinearity test's <c>[a]G2</c>.</summary>
    private static G2ScalarMultiplyDelegate G2ScalarMul { get; } = Bls12Curve381BigIntegerG2Reference.GetScalarMultiply();
    /// <summary>The BLS12-381 scalar-field reduction delegate used to reduce sampled bytes to a canonical scalar.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 G1 on-curve predicate used to confirm the off-curve probes are actually off-curve.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    /// <summary>The BLS12-381 G2 on-curve predicate used to confirm the off-curve probes are actually off-curve.</summary>
    private static G2IsOnCurveDelegate G2IsOnCurve { get; } = Bls12Curve381BigIntegerG2Reference.GetIsOnCurve();

    /// <summary>The BLS12-381 base-field prime, used to reduce sampled Fp12 component bytes to canonical range.</summary>
    private static BigInteger BaseFieldPrime { get; } = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
    /// <summary>The byte width of one Fp12 component (an Fp element).</summary>
    private const int CompSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;

    /// <summary>The number of CsCheck samples for pairing-bilinearity property tests; kept small because a full BigInteger pairing takes about 500ms per sample.</summary>
    private const long PairingIterationCount = 3;
    /// <summary>The number of CsCheck samples for the cheaper Frobenius-only and cyclotomic-square property tests, which can afford more samples than a full pairing.</summary>
    private const long FrobeniusIterationCount = 20;


    /// <summary>Verifies that applying Frobenius twelve times to a random Fp12 element returns the original element, since Fp12 has characteristic p and 12 is the embedding degree; this catches a sign or value mistake in the γ-constants computed from ξ at static initialization.</summary>
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


    /// <summary>Verifies that an Fp element lifted into Fp12 (the tower embedding <c>(a,0) → ((a,0),0,0) → (((a,0),0,0),0)</c>) is fixed by Frobenius, since <c>a^p = a</c> for <c>a ∈ Fp</c>.</summary>
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


    /// <summary>Verifies that the reference's cyclotomic-square delegate agrees byte-for-byte with regular Fp12 squaring on random inputs, documenting the contract any production backend specializing cyclotomic-square must also satisfy.</summary>
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


    /// <summary>Verifies that <c>e(G1, G2)</c> is neither the Fp12 identity nor zero, since either would make the pairing degenerate and cryptographically useless.</summary>
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


    /// <summary>Verifies that <c>e(0, G2)</c> equals the Fp12 identity.</summary>
    [TestMethod]
    public void PairingWithG1IdentityIsOne()
    {
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Fp12Element result = identity.PairWith(g2, Pair, BaseMemoryPool.Shared);
        Assert.IsTrue(result.IsOne, "e(0, G2) must equal the Fp12 identity.");
    }


    /// <summary>Verifies that <c>e(G1, 0)</c> equals the Fp12 identity.</summary>
    [TestMethod]
    public void PairingWithG2IdentityIsOne()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Fp12Element result = g1.PairWith(identity, Pair, BaseMemoryPool.Shared);
        Assert.IsTrue(result.IsOne, "e(G1, 0) must equal the Fp12 identity.");
    }


    /// <summary>Verifies that the BLS12-381 ate parameter's magnitude and sign survive hex parsing correctly. <see cref="NumberStyles.HexNumber"/> reads a literal whose leading nibble has the high bit set as a two's-complement negative number, and the ate parameter's magnitude starts with 'd' (1101), so the literal needs a leading zero nibble to parse as the intended unsigned value; without it the Miller loop would iterate 61 times instead of 63 and bilinearity would silently break.</summary>
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


    /// <summary>Verifies the pairing's defining bilinearity identity <c>e([a]·G1, G2) = e(G1, [a]·G2)</c> for random scalars; a wrong line evaluation, a wrong Miller-loop iteration count, a bad final exponentiation, or a flipped twist sign would each break it.</summary>
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


    /// <summary>Verifies that pairing a G1 point whose abscissa is off-curve throws rather than silently fabricating a y-coordinate via the unverified <c>a^((p+1)/4)</c> shortcut. The probe is confirmed off-curve through the reference on-curve predicate first, and the other operand is a genuine generator, so no identity short-circuit can hide the off-curve decode.</summary>
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


    /// <summary>Verifies that pairing a G2 point whose abscissa is off-curve throws, confirmed off-curve through the reference on-curve predicate first.</summary>
    [TestMethod]
    public void PairingRejectsOffCurveG2Point()
    {
        byte[] validG1 = GeneratorG1Compressed();
        byte[] offCurveG2 = BuildOffCurveG2();
        Assert.IsFalse(G2IsOnCurve(offCurveG2, CurveParameterSet.Bls12Curve381), "The probe must be off-curve for the test to be meaningful.");

        Assert.ThrowsExactly<InvalidOperationException>(() => PairInto(validG1, offCurveG2));
    }


    /// <summary>Verifies that a masked G1 x-coordinate at or above the base-field prime — a non-canonical encoding — is rejected rather than silently reduced.</summary>
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


    /// <summary>Pairs <paramref name="p"/> and <paramref name="q"/> into a discarded scratch buffer, so a test can assert only on the thrown exception.</summary>
    private static void PairInto(byte[] p, byte[] q)
    {
        Span<byte> result = stackalloc byte[WellKnownCurves.Bls12Curve381Fp12SizeBytes];
        Pair(p, q, result, CurveParameterSet.Bls12Curve381);
    }


    /// <summary>Returns the compressed encoding of the BLS12-381 G1 generator.</summary>
    private static byte[] GeneratorG1Compressed()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return g1.AsReadOnlySpan().ToArray();
    }


    /// <summary>Returns the compressed encoding of the BLS12-381 G2 generator.</summary>
    private static byte[] GeneratorG2Compressed()
    {
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return g2.AsReadOnlySpan().ToArray();
    }


    /// <summary>Builds a compressed G1 encoding whose abscissa is off-curve: the first small candidate abscissa whose <c>x³ + 4</c> is a quadratic non-residue, encoded with only the compression flag set.</summary>
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


    /// <summary>Builds a compressed G2 encoding whose abscissa is off the twist curve: the first small <c>x.c0</c> (with <c>x.c1 = 0</c>) that is off-curve. The layout is <c>[x.c1 : 48 bytes big-endian][x.c0 : 48 bytes big-endian]</c> with the flags in the leading c1 byte, so the trailing byte carries <c>x.c0</c>.</summary>
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


    /// <summary>Reduces each of the twelve 48-byte Fp components of <paramref name="raw"/> to canonical range below the base-field prime and wraps the result as an <see cref="Fp12Element"/>.</summary>
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


    /// <summary>Reduces <paramref name="raw"/> to a canonical BLS12-381 scalar.</summary>
    private static Scalar ReduceToScalar(ReadOnlySpan<byte> raw)
    {
        Span<byte> bytes = stackalloc byte[Scalar.SizeBytes];
        Reduce(raw, bytes, CurveParameterSet.Bls12Curve381);
        return Scalar.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>Writes <paramref name="value"/> to <paramref name="destination"/> as a canonical big-endian scalar, zero-padded on the left.</summary>
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
