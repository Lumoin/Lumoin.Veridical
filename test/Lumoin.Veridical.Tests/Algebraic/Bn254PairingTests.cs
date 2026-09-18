using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the BN254 (alt_bn128) optimal-ate pairing reference
/// (<see cref="Bn254BigIntegerPairingReference"/>) and the Fp12 Frobenius /
/// cyclotomic-square delegates. Three layers: known-answer vectors for
/// <c>e(G1, G2)</c> and <c>e(2G1, 3G2)</c>; the defining algebraic properties
/// (bilinearity, non-degeneracy, identity, Frobenius¹² = id); and the
/// loop-count sign/magnitude guard.
/// </summary>
[TestClass]
internal sealed class Bn254PairingTests
{
    /// <summary>
    /// The Fp12 Frobenius endomorphism delegate under test.
    /// </summary>
    private static Fp12FrobeniusDelegate Frobenius { get; } = Bn254BigIntegerPairingReference.GetFrobenius();

    /// <summary>
    /// The Fp12 cyclotomic-square delegate under test.
    /// </summary>
    private static Fp12CyclotomicSquareDelegate CyclotomicSquare { get; } = Bn254BigIntegerPairingReference.GetCyclotomicSquare();

    /// <summary>
    /// The optimal-ate pairing delegate under test.
    /// </summary>
    private static PairingDelegate Pair { get; } = Bn254BigIntegerPairingReference.GetPairing();

    /// <summary>
    /// The general Fp12 squaring delegate, used as the ground truth that
    /// <see cref="CyclotomicSquare"/> must agree with on elements of the
    /// cyclotomic subgroup.
    /// </summary>
    private static Fp12SquareDelegate RegularSquare { get; } = Bn254BigIntegerFp12Reference.GetSquare();

    /// <summary>
    /// The G1 scalar-multiplication delegate used to build pairing operands.
    /// </summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>
    /// The G2 scalar-multiplication delegate used to build pairing operands.
    /// </summary>
    private static G2ScalarMultiplyDelegate G2ScalarMul { get; } = Bn254BigIntegerG2Reference.GetScalarMultiply();

    /// <summary>
    /// The G2 negation delegate used to build the EIP-197 pairing-product operand.
    /// </summary>
    private static G2NegateDelegate G2Negate { get; } = Bn254BigIntegerG2Reference.GetNegate();

    /// <summary>
    /// The Fp12 multiplication delegate used to combine pairing outputs into a product.
    /// </summary>
    private static Fp12MultiplyDelegate Fp12Mul { get; } = Bn254BigIntegerFp12Reference.GetMultiply();

    /// <summary>
    /// The scalar-reduction delegate used to fold arbitrary byte strings into
    /// canonical BN254 scalars.
    /// </summary>
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();

    /// <summary>
    /// The G1 on-curve predicate, used both to confirm a probe point is
    /// genuinely off-curve and to exercise the pairing's own rejection path.
    /// </summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bn254BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>
    /// The G2 on-curve predicate, used both to confirm a probe point is
    /// genuinely off-curve and to exercise the pairing's own rejection path.
    /// </summary>
    private static G2IsOnCurveDelegate G2IsOnCurve { get; } = Bn254BigIntegerG2Reference.GetIsOnCurve();

    /// <summary>
    /// The BN254 base-field prime <c>q</c>, used to reduce sampled bytes into
    /// canonical Fp12 components.
    /// </summary>
    private static BigInteger BaseFieldPrime { get; } = Bn254BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>
    /// The size in bytes of one Fp component, and so of one Fp12 coordinate slot.
    /// </summary>
    private const int CompSize = WellKnownCurves.Bn254BaseFieldSizeBytes;

    /// <summary>
    /// The size in bytes of a full Fp12 element: twelve Fp components.
    /// </summary>
    private const int Fp12Size = 12 * WellKnownCurves.Bn254BaseFieldSizeBytes;

    /// <summary>
    /// The number of random samples drawn by the bilinearity property test.
    /// </summary>
    private const long PairingIterationCount = 2;

    /// <summary>
    /// The number of random samples drawn by the Frobenius and
    /// cyclotomic-square property tests.
    /// </summary>
    private const long FrobeniusIterationCount = 12;

    /// <summary>
    /// The pool backing every pooled point, scalar and Fp12 element allocated
    /// in this fixture.
    /// </summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// Gets or sets the context that MSTest supplies for the running test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The Miller-loop parameter <c>6u+2</c> is positive for BN254's <c>u</c>,
    /// so the loop needs no final inversion, unlike a curve with a negative
    /// pairing parameter.
    /// </summary>
    [TestMethod]
    public void AteLoopCountIsPositiveSixUPlusTwo()
    {
        //BN254's u = 4965661367192848881 > 0, so 6u+2 is positive and the
        //Miller loop needs no final inversion (contrast BLS12-381's negative x).
        BigInteger u = new(4965661367192848881L);
        Assert.AreEqual(u, Bn254BigIntegerPairingReference.BnParameter);
        Assert.AreEqual((6 * u) + 2, Bn254BigIntegerPairingReference.AteLoopCount);
        Assert.IsGreaterThan(BigInteger.Zero, Bn254BigIntegerPairingReference.AteLoopCount);
    }


    /// <summary>
    /// The pairing of the two generators is neither the Fp12 zero nor the
    /// Fp12 identity.
    /// </summary>
    [TestMethod]
    public void PairingOfGeneratorsIsNonTrivial()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = g1.PairWith(g2, Pair, Pool);
        Assert.IsFalse(result.IsZero, "e(G1, G2) must not be zero.");
        Assert.IsFalse(result.IsOne, "e(G1, G2) must not be the Fp12 identity.");
    }


    /// <summary>
    /// <c>e(G1, G2)</c> at the BN254 generators matches the known-answer
    /// value in <see cref="ExpectedGenerators"/>.
    /// </summary>
    [TestMethod]
    public void PairingOfGeneratorsMatchesKnownAnswerVector()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = g1.PairWith(g2, Pair, Pool);
        Assert.AreEqual(ExpectedGenerators(), Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    /// <summary>
    /// The pairing of two distinct scalar multiples of the generators,
    /// <c>e(2G1, 3G2)</c>, matches the known-answer value in
    /// <see cref="ExpectedScalarMultiples"/>; by bilinearity it also equals
    /// <c>e(G1,G2)^6</c>.
    /// </summary>
    [TestMethod]
    public void PairingOfScalarMultiplesMatchesKnownAnswerVector()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);
        using Scalar two = ScalarFromByte(0x02);
        using Scalar three = ScalarFromByte(0x03);
        using G1Point twoG1 = g1.ScalarMultiply(two, G1ScalarMul, Pool);
        using G2Point threeG2 = g2.ScalarMultiply(three, G2ScalarMul, Pool);

        using Fp12Element result = twoG1.PairWith(threeG2, Pair, Pool);
        Assert.AreEqual(ExpectedScalarMultiples(), Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    /// <summary>
    /// The pairing of the G1 identity with any G2 point is the Fp12 identity.
    /// </summary>
    [TestMethod]
    public void PairingWithG1IdentityIsOne()
    {
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = identity.PairWith(g2, Pair, Pool);
        Assert.IsTrue(result.IsOne, "e(0, G2) must equal the Fp12 identity.");
    }


    /// <summary>
    /// The pairing of any G1 point with the G2 identity is the Fp12 identity.
    /// </summary>
    [TestMethod]
    public void PairingWithG2IdentityIsOne()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = g1.PairWith(identity, Pair, Pool);
        Assert.IsTrue(result.IsOne, "e(G1, 0) must equal the Fp12 identity.");
    }


    /// <summary>
    /// Scaling either operand by a scalar <c>a</c> scales the pairing the
    /// same way: <c>e([a]G1, G2) == e(G1, [a]G2)</c>.
    /// </summary>
    [TestMethod]
    public void PairingIsBilinearAcrossG1AndG2()
    {
        Gen.Byte.Array[Scalar.SizeBytes].Sample(raw =>
        {
            using Scalar a = ReduceToScalar(raw);
            using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
            using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);
            using G1Point aG1 = g1.ScalarMultiply(a, G1ScalarMul, Pool);
            using G2Point aG2 = g2.ScalarMultiply(a, G2ScalarMul, Pool);
            using Fp12Element left = aG1.PairWith(g2, Pair, Pool);
            using Fp12Element right = g1.PairWith(aG2, Pair, Pool);
            return left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());
        }, iter: PairingIterationCount);
    }


    /// <summary>
    /// The canonical EIP-197 precompile form: a product of pairings equals
    /// the Fp12 identity. Here <c>e(5G1, 7G2) &#183; e(G1, -35G2) =
    /// e(G1,G2)^(35-35) = 1</c>, which validates the pairing the way the
    /// precompile consumes it, independent of the bilinearity equality
    /// test, and is the BN254 counterpart of an EIP-197 pairing-check
    /// vector.
    /// </summary>
    [TestMethod]
    public void EipStylePairingProductIsOne()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);
        using Scalar five = ScalarFromByte(0x05);
        using Scalar seven = ScalarFromByte(0x07);
        using Scalar thirtyFive = ScalarFromByte(0x23);

        using G1Point fiveG1 = g1.ScalarMultiply(five, G1ScalarMul, Pool);
        using G2Point sevenG2 = g2.ScalarMultiply(seven, G2ScalarMul, Pool);
        using G2Point thirtyFiveG2 = g2.ScalarMultiply(thirtyFive, G2ScalarMul, Pool);
        using G2Point negThirtyFiveG2 = thirtyFiveG2.Negate(G2Negate, Pool);

        using Fp12Element left = fiveG1.PairWith(sevenG2, Pair, Pool);
        using Fp12Element right = g1.PairWith(negThirtyFiveG2, Pair, Pool);
        using Fp12Element product = left.Multiply(right, Fp12Mul, Pool);

        Assert.IsTrue(product.IsOne, "e(5G1,7G2)·e(G1,-35G2) must equal the Fp12 identity.");
    }


    /// <summary>
    /// Applying the Fp12 Frobenius endomorphism twelve times is the identity
    /// map: <c>Frobenius^12 = id</c>.
    /// </summary>
    [TestMethod]
    public void FrobeniusTwelfthPowerIsIdentity()
    {
        Gen.Byte.Array[Fp12Size].Sample(raw =>
        {
            using Fp12Element original = ReduceAndWrapFp12(raw);
            Fp12Element current = ReduceAndWrapFp12(raw);
            try
            {
                for(int i = 0; i < 12; i++)
                {
                    Fp12Element next = current.Frobenius(Frobenius, Pool);
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


    /// <summary>
    /// The cyclotomic-square delegate agrees with general Fp12 squaring on
    /// elements of the cyclotomic subgroup.
    /// </summary>
    [TestMethod]
    public void CyclotomicSquareAgreesWithRegularSquare()
    {
        Gen.Byte.Array[Fp12Size].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrapFp12(raw);
            using Fp12Element cycSq = a.CyclotomicSquare(CyclotomicSquare, Pool);
            using Fp12Element regSq = a.Square(RegularSquare, Pool);
            return cycSq.AsReadOnlySpan().SequenceEqual(regSq.AsReadOnlySpan());
        }, iter: FrobeniusIterationCount);
    }


    /// <summary>
    /// The pairing's G1 decode rejects an off-curve abscissa rather than
    /// fabricate a <c>y</c> with the unverified <c>a^((p+1)/4)</c> shortcut
    /// and pair against it. The probe is pinned off-curve through the
    /// on-curve predicate under test, and the valid operand is a generator
    /// so no identity short-circuit can hide the off-curve decode.
    /// </summary>
    [TestMethod]
    public void PairingRejectsOffCurveG1Point()
    {
        byte[] offCurveG1 = BuildOffCurveG1();
        byte[] validG2 = GeneratorG2Compressed();
        Assert.IsFalse(G1IsOnCurve(offCurveG1, CurveParameterSet.Bn254), "The probe must be off-curve for the test to be meaningful.");

        Assert.ThrowsExactly<InvalidOperationException>(() => PairInto(offCurveG1, validG2));
    }


    /// <summary>
    /// The pairing's G2 decode rejects an off-curve point, mirroring
    /// <see cref="PairingRejectsOffCurveG1Point"/> for the twist curve.
    /// </summary>
    [TestMethod]
    public void PairingRejectsOffCurveG2Point()
    {
        byte[] validG1 = GeneratorG1Compressed();
        byte[] offCurveG2 = BuildOffCurveG2();
        Assert.IsFalse(G2IsOnCurve(offCurveG2, CurveParameterSet.Bn254), "The probe must be off-curve for the test to be meaningful.");

        Assert.ThrowsExactly<InvalidOperationException>(() => PairInto(validG1, offCurveG2));
    }


    /// <summary>
    /// A masked <c>x</c> coordinate at or above the base-field prime is a
    /// non-canonical encoding; the decode rejects it rather than reduce it
    /// modulo the prime. All-ones <c>x</c> bytes exceed <c>q</c>.
    /// </summary>
    [TestMethod]
    public void PairingRejectsNonCanonicalG1XCoordinate()
    {
        byte[] validG2 = GeneratorG2Compressed();
        byte[] nonCanonicalG1 = new byte[WellKnownCurves.Bn254G1CompressedSizeBytes];
        nonCanonicalG1.AsSpan().Fill(0xFF);
        nonCanonicalG1[0] = 0xBF;  //Compressed tag (0x80), infinity clear, low six x bits all one.

        Assert.ThrowsExactly<InvalidOperationException>(() => PairInto(nonCanonicalG1, validG2));
    }


    /// <summary>
    /// Pairs two compressed, encoded points and discards the result, so a
    /// caller can assert only on the exception thrown by an invalid
    /// encoding.
    /// </summary>
    private static void PairInto(byte[] p, byte[] q)
    {
        Span<byte> result = stackalloc byte[Fp12Size];
        Pair(p, q, result, CurveParameterSet.Bn254);
    }


    /// <summary>
    /// The BN254 G1 generator, compressed-encoded.
    /// </summary>
    private static byte[] GeneratorG1Compressed()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);

        return g1.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// The BN254 G2 generator, compressed-encoded.
    /// </summary>
    private static byte[] GeneratorG2Compressed()
    {
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        return g2.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Scans small abscissas for the first whose <c>x&#179; + 3</c> is a
    /// quadratic non-residue, gnark-compressed with the smaller-root tag
    /// (<c>0x80</c>).
    /// </summary>
    private static byte[] BuildOffCurveG1()
    {
        byte[] encoded = new byte[WellKnownCurves.Bn254G1CompressedSizeBytes];
        for(int candidate = 1; candidate < 256; candidate++)
        {
            encoded.AsSpan().Clear();
            encoded[^1] = (byte)candidate;
            encoded[0] = 0x80;
            if(!G1IsOnCurve(encoded, CurveParameterSet.Bn254))
            {
                return encoded;
            }
        }

        throw new InvalidOperationException("No off-curve G1 abscissa found in the scan range.");
    }


    /// <summary>
    /// Scans small <c>x.c0</c> values with <c>x.c1 = 0</c> for the first
    /// point off the twist curve. The encoding is
    /// <c>[x.c1 : 32 BE][x.c0 : 32 BE]</c> with the tag in the leading
    /// <c>c1</c> byte, so the trailing byte carries <c>x.c0</c>.
    /// </summary>
    private static byte[] BuildOffCurveG2()
    {
        byte[] encoded = new byte[WellKnownCurves.Bn254G2CompressedSizeBytes];
        for(int candidate = 1; candidate < 256; candidate++)
        {
            encoded.AsSpan().Clear();
            encoded[^1] = (byte)candidate;
            encoded[0] = 0x80;
            if(!G2IsOnCurve(encoded, CurveParameterSet.Bn254))
            {
                return encoded;
            }
        }

        throw new InvalidOperationException("No off-curve G2 abscissa found in the scan range.");
    }


    /// <summary>
    /// The known-answer GT value for <c>e(G1, G2)</c> at the BN254 generators.
    /// </summary>
    private static string ExpectedGenerators() => PairingGeneratorsRaw;

    /// <summary>
    /// The known-answer GT value for <c>e(2G1, 3G2)</c>.
    /// </summary>
    private static string ExpectedScalarMultiples() => PairingScalarMultiplesRaw;


    /// <summary>
    /// A canonical BN254 scalar reduced from a single byte.
    /// </summary>
    private static Scalar ScalarFromByte(byte value)
    {
        ReadOnlySpan<byte> source = [value];
        return Scalar.FromBytesReduced(source, Reduce, CurveParameterSet.Bn254, Pool);
    }


    /// <summary>
    /// A canonical BN254 scalar reduced from an arbitrary byte string.
    /// </summary>
    private static Scalar ReduceToScalar(ReadOnlySpan<byte> raw)
    {
        Span<byte> bytes = stackalloc byte[Scalar.SizeBytes];
        Reduce(raw, bytes, CurveParameterSet.Bn254);
        return Scalar.FromCanonical(bytes, CurveParameterSet.Bn254, Pool);
    }


    /// <summary>
    /// An Fp12 element built from twelve arbitrary component byte strings,
    /// each reduced modulo the base-field prime before being packed into
    /// canonical form.
    /// </summary>
    private static Fp12Element ReduceAndWrapFp12(ReadOnlySpan<byte> raw)
    {
        Span<byte> packed = stackalloc byte[Fp12Size];
        packed.Clear();
        for(int i = 0; i < 12; i++)
        {
            int start = i * CompSize;
            BigInteger value = new BigInteger(raw.Slice(start, CompSize), isUnsigned: true, isBigEndian: true) % BaseFieldPrime;
            WriteCanonical(value, packed.Slice(start, CompSize));
        }

        return Fp12Element.FromCanonical(packed, CurveParameterSet.Bn254, Pool);
    }


    /// <summary>
    /// Writes a reduced field component into a fixed-width canonical
    /// big-endian span, left-padding with zero bytes as needed.
    /// </summary>
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


    /// <summary>
    /// The GT value for <c>e(G1, G2)</c> at the BN254 generators, as a
    /// lowercase hex string in the 2-3-2 nested layout (<c>C0,C1</c> /
    /// <c>A0,A1,A2</c> / <c>c0,c1</c>).
    /// </summary>
    private const string PairingGeneratorsRaw =
        "12c70e90e12b7874510cd1707e8856f71bf7f61d72631e268fca81000db9a1f5084f330485b09e866bc2f2ea2b897394deaf3f12aa31f28cb0552990967d4704"
        + "0e841c2ac18a4003ac9326b9558380e0bc27fdd375e3605f96b819a358d34bde2067586885c3318eeffa1938c754fe3c60224ee5ae15e66af6b5104c47c8c5d80"
        + "1676555de427abc409c4a394bc5426886302996919d4bf4bdd02236e14b36362b03614464f04dd772d86df88674c270ffc8747ea13e72da95e3594468f222c42c"
        + "53748bcd21a7c038fb30ddc8ac3bf0af25d7859cfbc12c30c866276c56590927ed208e7a0b55ae6e710bbfbd2fd922669c026360e37cc5b2ab8624115361041ad"
        + "9db1937fd72f4ac462173d31d3d6117411fa48dba8d499d762b47edb3b54a279db296f9d479292532c7c493d8e0722b6efae42158387564889c79fc038ee30dc2"
        + "6f240656bbe2029bd441d77c221f0ba4c70c94b29b5f17f0f6d08745a069108c19d15f9446f744d0f110405d3856d6cc3bda6c4d537663729f5257628417";

    /// <summary>
    /// The GT value for <c>e(2G1, 3G2)</c>, in the same 2-3-2 nested layout
    /// as <see cref="PairingGeneratorsRaw"/>.
    /// </summary>
    private const string PairingScalarMultiplesRaw =
        "10227b2606c11f22f4b2dec3f69cee4332ebe2e8f869ea8ca9e6d45ce15bd11027d1c9dae835182b272bb25b47b0d871382c9c2765fd1f42e07edbe852830157"
        + "1f5919cf59b218135aaeb137ac84c6ecf282feda6a8752ca291b7ec1d2f8bab42b7e44680d35a6676223538d54abcd7bc2c54281bf0f5277c81cf5b114d3a3451"
        + "7e6d213292c2aa12ef3cc75aca8cb9cbd47d05086227db2dbd1262d3e89dbf0291a53fea204b470bb901fb184155facd6e3b44fad848d536386b73d6c31fd5228"
        + "44ed362ecf2c491a471a18c2875fd727126a62c8151c356f81e02cff52f0452a8245d55a3b3f9deae9cca372912a31b88dc77cee06dfa10a717acbf758cbd5222"
        + "ff2e20c4578e886027953a035cbd8784a9764bbcd353051ba9f02c4dce8ad08532a0a75fb0acdf508c3bdd4c7700efb3a9ae403818daad5937d9ffffaca452e7e"
        + "3a4aaef17a53de3c528319b426e35f53455107f49d7fe52de95849e7dcf62ba2bc83434031012424aad830a35c459c40a0b7ce87735010db68c10b61ddcb";
}
