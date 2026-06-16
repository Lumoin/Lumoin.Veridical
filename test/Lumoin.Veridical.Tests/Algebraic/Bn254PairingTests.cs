using CsCheck;
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
/// <c>e(G1, G2)</c> and <c>e(2G1, 3G2)</c> produced by an independent CPython
/// implementation of the same 2-3-2 tower (itself cross-checked against py_ecc
/// for basis-independent pairing semantics); the defining algebraic properties
/// (bilinearity, non-degeneracy, identity, Frobenius¹² = id); and the
/// loop-count sign/magnitude guard.
/// </summary>
[TestClass]
internal sealed class Bn254PairingTests
{
    private static readonly Fp12FrobeniusDelegate Frobenius = Bn254BigIntegerPairingReference.GetFrobenius();
    private static readonly Fp12CyclotomicSquareDelegate CyclotomicSquare = Bn254BigIntegerPairingReference.GetCyclotomicSquare();
    private static readonly PairingDelegate Pair = Bn254BigIntegerPairingReference.GetPairing();

    private static readonly Fp12SquareDelegate RegularSquare = Bn254BigIntegerFp12Reference.GetSquare();

    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G2ScalarMultiplyDelegate G2ScalarMul = Bn254BigIntegerG2Reference.GetScalarMultiply();
    private static readonly G2NegateDelegate G2Negate = Bn254BigIntegerG2Reference.GetNegate();
    private static readonly Fp12MultiplyDelegate Fp12Mul = Bn254BigIntegerFp12Reference.GetMultiply();
    private static readonly ScalarReduceDelegate Reduce = Bn254BigIntegerScalarReference.GetReduce();

    private static readonly BigInteger BaseFieldPrime = Bn254BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int Fp12Size = 12 * WellKnownCurves.Bn254BaseFieldSizeBytes;

    private const long PairingIterationCount = 2;
    private const long FrobeniusIterationCount = 12;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    //GT vectors in the 2-3-2 byte layout (nested C0,C1 / A0,A1,A2 / c0,c1), from
    //an independent CPython Fp2/Fp6/Fp12 tower-arithmetic oracle (archived outside the repo),
    //which agrees with py_ecc on the basis-independent pairing-check semantics.
    //The full hex literals are PairingGeneratorsRaw / PairingScalarMultiplesRaw below.


    public TestContext TestContext { get; set; } = null!;


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


    [TestMethod]
    public void PairingOfGeneratorsIsNonTrivial()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = g1.PairWith(g2, Pair, Pool);
        Assert.IsFalse(result.IsZero, "e(G1, G2) must not be zero.");
        Assert.IsFalse(result.IsOne, "e(G1, G2) must not be the Fp12 identity.");
    }


    [TestMethod]
    public void PairingOfGeneratorsMatchesOracleVector()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = g1.PairWith(g2, Pair, Pool);
        Assert.AreEqual(OracleGenerators(), Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public void PairingOfScalarMultiplesMatchesOracleVector()
    {
        //e(2G1, 3G2) — distinct scalar multiples; equals e(G1,G2)^6 by bilinearity.
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);
        using Scalar two = ScalarFromByte(0x02);
        using Scalar three = ScalarFromByte(0x03);
        using G1Point twoG1 = g1.ScalarMultiply(two, G1ScalarMul, Pool);
        using G2Point threeG2 = g2.ScalarMultiply(three, G2ScalarMul, Pool);

        using Fp12Element result = twoG1.PairWith(threeG2, Pair, Pool);
        Assert.AreEqual(OracleScalarMultiples(), Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public void PairingWithG1IdentityIsOne()
    {
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bn254, Pool);
        using G2Point g2 = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = identity.PairWith(g2, Pair, Pool);
        Assert.IsTrue(result.IsOne, "e(0, G2) must equal the Fp12 identity.");
    }


    [TestMethod]
    public void PairingWithG2IdentityIsOne()
    {
        using G1Point g1 = G1Point.Generator(CurveParameterSet.Bn254, Pool);
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bn254, Pool);

        using Fp12Element result = g1.PairWith(identity, Pair, Pool);
        Assert.IsTrue(result.IsOne, "e(G1, 0) must equal the Fp12 identity.");
    }


    [TestMethod]
    public void PairingIsBilinearAcrossG1AndG2()
    {
        //e([a]G1, G2) == e(G1, [a]G2).
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


    [TestMethod]
    public void EipStylePairingProductIsOne()
    {
        //The canonical EIP-197 precompile form: a product of pairings equals
        //the Fp12 identity. Here e(5·G1, 7·G2) · e(G1, −35·G2) = e(G1,G2)^(35-35)
        //= 1. This validates the pairing the way the precompile consumes it —
        //independent of the bilinearity equality test — and is the BN254
        //counterpart of an EIP-197 pairing-check vector.
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


    private static string OracleGenerators() => PairingGeneratorsRaw;
    private static string OracleScalarMultiples() => PairingScalarMultiplesRaw;


    private static Scalar ScalarFromByte(byte value)
    {
        ReadOnlySpan<byte> source = [value];
        return Scalar.FromBytesReduced(source, Reduce, CurveParameterSet.Bn254, Pool);
    }


    private static Scalar ReduceToScalar(ReadOnlySpan<byte> raw)
    {
        Span<byte> bytes = stackalloc byte[Scalar.SizeBytes];
        Reduce(raw, bytes, CurveParameterSet.Bn254);
        return Scalar.FromCanonical(bytes, CurveParameterSet.Bn254, Pool);
    }


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


    private const string PairingGeneratorsRaw =
        "12c70e90e12b7874510cd1707e8856f71bf7f61d72631e268fca81000db9a1f5084f330485b09e866bc2f2ea2b897394deaf3f12aa31f28cb0552990967d4704"
        + "0e841c2ac18a4003ac9326b9558380e0bc27fdd375e3605f96b819a358d34bde2067586885c3318eeffa1938c754fe3c60224ee5ae15e66af6b5104c47c8c5d80"
        + "1676555de427abc409c4a394bc5426886302996919d4bf4bdd02236e14b36362b03614464f04dd772d86df88674c270ffc8747ea13e72da95e3594468f222c42c"
        + "53748bcd21a7c038fb30ddc8ac3bf0af25d7859cfbc12c30c866276c56590927ed208e7a0b55ae6e710bbfbd2fd922669c026360e37cc5b2ab8624115361041ad"
        + "9db1937fd72f4ac462173d31d3d6117411fa48dba8d499d762b47edb3b54a279db296f9d479292532c7c493d8e0722b6efae42158387564889c79fc038ee30dc2"
        + "6f240656bbe2029bd441d77c221f0ba4c70c94b29b5f17f0f6d08745a069108c19d15f9446f744d0f110405d3856d6cc3bda6c4d537663729f5257628417";

    private const string PairingScalarMultiplesRaw =
        "10227b2606c11f22f4b2dec3f69cee4332ebe2e8f869ea8ca9e6d45ce15bd11027d1c9dae835182b272bb25b47b0d871382c9c2765fd1f42e07edbe852830157"
        + "1f5919cf59b218135aaeb137ac84c6ecf282feda6a8752ca291b7ec1d2f8bab42b7e44680d35a6676223538d54abcd7bc2c54281bf0f5277c81cf5b114d3a3451"
        + "7e6d213292c2aa12ef3cc75aca8cb9cbd47d05086227db2dbd1262d3e89dbf0291a53fea204b470bb901fb184155facd6e3b44fad848d536386b73d6c31fd5228"
        + "44ed362ecf2c491a471a18c2875fd727126a62c8151c356f81e02cff52f0452a8245d55a3b3f9deae9cca372912a31b88dc77cee06dfa10a717acbf758cbd5222"
        + "ff2e20c4578e886027953a035cbd8784a9764bbcd353051ba9f02c4dce8ad08532a0a75fb0acdf508c3bdd4c7700efb3a9ae403818daad5937d9ffffaca452e7e"
        + "3a4aaef17a53de3c528319b426e35f53455107f49d7fe52de95849e7dcf62ba2bc83434031012424aad830a35c459c40a0b7ce87735010db68c10b61ddcb";
}
