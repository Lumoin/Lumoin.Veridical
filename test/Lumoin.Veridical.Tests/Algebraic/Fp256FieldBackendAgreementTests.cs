using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based cross-implementation tests for the P-256 base field Fp256: every
/// limb backend (Montgomery, and — appended — Solinas) must produce byte-identical
/// canonical output to the BigInteger oracle <see cref="P256BaseFieldReference"/>
/// across a random sweep, the algebraic gate <c>a·a⁻¹ ≡ 1</c>, and hand-picked
/// edge cases (0, 1, p−1, near-p). When a backend diverges, CsCheck shrinks the
/// sample to a minimal counterexample — the fastest way to localise a limb bug.
/// This is the gate the new backends are only correct if they pass.
/// </summary>
[TestClass]
internal sealed class Fp256FieldBackendAgreementTests
{
    private const long IterationCount = 500;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;
    private static readonly BigInteger P = P256BigIntegerG1Reference.BaseFieldPrime;

    private static readonly Gen<byte[]> RawBytesGen = Gen.Byte.Array[Scalar.SizeBytes];
    private static readonly Gen<byte[]> WideBytesGen = Gen.Byte.Array[64];

    private static readonly ScalarReduceDelegate ReferenceReduce = P256BaseFieldReference.GetReduce();
    private static readonly ScalarAddDelegate ReferenceAdd = P256BaseFieldReference.GetAdd();
    private static readonly ScalarSubtractDelegate ReferenceSubtract = P256BaseFieldReference.GetSubtract();
    private static readonly ScalarMultiplyDelegate ReferenceMultiply = P256BaseFieldReference.GetMultiply();
    private static readonly ScalarInvertDelegate ReferenceInvert = P256BaseFieldReference.GetInvert();

    private delegate void BinaryFieldOp(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result);
    private delegate void UnaryFieldOp(ReadOnlySpan<byte> a, Span<byte> result);


    [TestMethod]
    public void MontgomeryMultiplyAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceMultiply), Binary(P256BaseFieldMontgomeryBackend.GetMultiply()));

    [TestMethod]
    public void MontgomeryAddAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceAdd), Binary(P256BaseFieldMontgomeryBackend.GetAdd()));

    [TestMethod]
    public void MontgomerySubtractAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceSubtract), Binary(P256BaseFieldMontgomeryBackend.GetSubtract()));

    [TestMethod]
    public void MontgomeryInvertAgreesWithReference() =>
        AssertInvertAgrees(P256BaseFieldMontgomeryBackend.GetInvert());

    [TestMethod]
    public void MontgomeryReduceAgreesWithReference() =>
        AssertReduceAgrees(P256BaseFieldMontgomeryBackend.GetReduce());

    [TestMethod]
    public void MontgomeryInverseProductIsOne() =>
        AssertInverseProductIsOne(P256BaseFieldMontgomeryBackend.GetMultiply(), P256BaseFieldMontgomeryBackend.GetInvert());

    [TestMethod]
    public void MontgomeryEdgeCasesAgreeWithReference() =>
        AssertEdgeCases(P256BaseFieldMontgomeryBackend.GetMultiply(), P256BaseFieldMontgomeryBackend.GetInvert());


    [TestMethod]
    public void MontgomeryDomainMultiplyAgreesWithReference()
    {
        //Perf Increment 1: the 1-CIOS Montgomery-domain multiply must equal the canonical reference once the
        //operands are lifted in and the result dropped out, i.e. from_montgomery(montMul(to(a), to(b))) == a·b.
        ScalarMultiplyDelegate montMultiply = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();
        Gen.Select(RawBytesGen, RawBytesGen).Sample((aRaw, bRaw) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(aRaw, a, Curve);
            ReferenceReduce(bRaw, b, Curve);

            Span<byte> aMont = stackalloc byte[Scalar.SizeBytes];
            Span<byte> bMont = stackalloc byte[Scalar.SizeBytes];
            P256BaseFieldMontgomeryBackend.ToMontgomery(a, aMont);
            P256BaseFieldMontgomeryBackend.ToMontgomery(b, bMont);

            Span<byte> productMont = stackalloc byte[Scalar.SizeBytes];
            montMultiply(aMont, bMont, productMont, Curve);
            Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
            P256BaseFieldMontgomeryBackend.FromMontgomery(productMont, actual);

            Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
            ReferenceMultiply(a, b, expected, Curve);

            return expected.SequenceEqual(actual);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MontgomerySpecializedAndGenericReduceAgreeWithReference()
    {
        //The generic m·n[j] reduction (the live MultiplyMontgomery) and the P-256-specialized signed-sparse
        //reduction must agree byte-for-byte with each other and, dropped out of the domain, with the BigInteger
        //a·b mod p — Montgomery reduction is unique given (p, R), so the two reductions emit the same residue.
        ScalarMultiplyDelegate live = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();
        Gen.Select(RawBytesGen, RawBytesGen).Sample((aRaw, bRaw) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(aRaw, a, Curve);
            ReferenceReduce(bRaw, b, Curve);

            return SpecializedGenericReferenceAgree(live, a, b);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MontgomerySpecializedAndGenericReduceEdgeCasesAgree()
    {
        //Edge residues incl. 0, 1, p−1, p−2, (p−1)/2, R mod p and R² mod p, plus their cross-products: the
        //live (generic) and specialized reductions must still coincide with the BigInteger oracle at the boundaries.
        ScalarMultiplyDelegate live = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();
        BigInteger r = BigInteger.One << (Scalar.SizeBytes * 8);
        byte[][] values =
        [
            Bytes(BigInteger.Zero),
            Bytes(BigInteger.One),
            Bytes(2),
            Bytes(P - 1),
            Bytes(P - 2),
            Bytes((P - 1) / 2),
            Bytes(r % P),
            Bytes((r * r) % P)
        ];

        Span<byte> a = stackalloc byte[Scalar.SizeBytes];
        Span<byte> b = stackalloc byte[Scalar.SizeBytes];
        foreach(byte[] x in values)
        {
            foreach(byte[] y in values)
            {
                ((ReadOnlySpan<byte>)x).CopyTo(a);
                ((ReadOnlySpan<byte>)y).CopyTo(b);
                Assert.IsTrue(SpecializedGenericReferenceAgree(live, a, b), "Live (generic), specialized, and BigInteger must agree on the edge residues.");
            }
        }
    }


    //Lifts the two canonical operands into the Montgomery domain, runs the live (generic-reduce) and the
    //specialized-reduce multiplies, and asserts the residues are byte-identical to each other and, dropped out,
    //to a·b mod p.
    private static bool SpecializedGenericReferenceAgree(ScalarMultiplyDelegate live, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        Span<byte> aMont = stackalloc byte[Scalar.SizeBytes];
        Span<byte> bMont = stackalloc byte[Scalar.SizeBytes];
        P256BaseFieldMontgomeryBackend.ToMontgomery(a, aMont);
        P256BaseFieldMontgomeryBackend.ToMontgomery(b, bMont);

        Span<byte> liveMont = stackalloc byte[Scalar.SizeBytes];
        Span<byte> specializedMont = stackalloc byte[Scalar.SizeBytes];
        live(aMont, bMont, liveMont, Curve);
        P256BaseFieldMontgomeryBackend.MultiplyMontgomerySpecializedReduce(aMont, bMont, specializedMont);
        if(!liveMont.SequenceEqual(specializedMont))
        {
            return false;
        }

        Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
        P256BaseFieldMontgomeryBackend.FromMontgomery(liveMont, actual);

        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        ReferenceMultiply(a, b, expected, Curve);

        return expected.SequenceEqual(actual);
    }


    [TestMethod]
    public void MontgomeryDomainInvertAgreesWithReference()
    {
        //Perf Increment 1: the in-domain inversion (Montgomery in, Montgomery out, no R²-lift, no final drop)
        //must equal the canonical reference once dropped out: from_montgomery(montInv(to(a))) == a⁻¹.
        ScalarInvertDelegate montInvert = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();
        RawBytesGen.Sample(aRaw =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(aRaw, a, Curve);
            if(a.IndexOfAnyExcept((byte)0) < 0)
            {
                return true; //Zero is not invertible; skip.
            }

            Span<byte> aMont = stackalloc byte[Scalar.SizeBytes];
            P256BaseFieldMontgomeryBackend.ToMontgomery(a, aMont);

            Span<byte> inverseMont = stackalloc byte[Scalar.SizeBytes];
            montInvert(aMont, inverseMont, Curve);
            Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
            P256BaseFieldMontgomeryBackend.FromMontgomery(inverseMont, actual);

            Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
            ReferenceInvert(a, expected, Curve);

            return expected.SequenceEqual(actual);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MontgomeryRoundTripIsIdentity()
    {
        //from_montgomery(to_montgomery(a)) == a for every canonical a (the boundary converters are inverses).
        RawBytesGen.Sample(aRaw =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(aRaw, a, Curve);

            Span<byte> mont = stackalloc byte[Scalar.SizeBytes];
            Span<byte> back = stackalloc byte[Scalar.SizeBytes];
            P256BaseFieldMontgomeryBackend.ToMontgomery(a, mont);
            P256BaseFieldMontgomeryBackend.FromMontgomery(mont, back);

            return a.SequenceEqual(back);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SolinasMultiplyAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceMultiply), Binary(P256BaseFieldSolinasBackend.GetMultiply()));

    [TestMethod]
    public void SolinasAddAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceAdd), Binary(P256BaseFieldSolinasBackend.GetAdd()));

    [TestMethod]
    public void SolinasSubtractAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceSubtract), Binary(P256BaseFieldSolinasBackend.GetSubtract()));

    [TestMethod]
    public void SolinasInvertAgreesWithReference() =>
        AssertInvertAgrees(P256BaseFieldSolinasBackend.GetInvert());

    [TestMethod]
    public void SolinasReduceAgreesWithReference() =>
        AssertReduceAgrees(P256BaseFieldSolinasBackend.GetReduce());

    [TestMethod]
    public void SolinasInverseProductIsOne() =>
        AssertInverseProductIsOne(P256BaseFieldSolinasBackend.GetMultiply(), P256BaseFieldSolinasBackend.GetInvert());

    [TestMethod]
    public void SolinasEdgeCasesAgreeWithReference() =>
        AssertEdgeCases(P256BaseFieldSolinasBackend.GetMultiply(), P256BaseFieldSolinasBackend.GetInvert());

    [TestMethod]
    public void MontgomeryAndSolinasMultiplyAgree() =>
        AssertBinaryAgrees(Binary(P256BaseFieldMontgomeryBackend.GetMultiply()), Binary(P256BaseFieldSolinasBackend.GetMultiply()));


    //Shared agreement harness

    private static void AssertBinaryAgrees(BinaryFieldOp reference, BinaryFieldOp candidate)
    {
        Gen.Select(RawBytesGen, RawBytesGen).Sample((aRaw, bRaw) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(aRaw, a, Curve);
            ReferenceReduce(bRaw, b, Curve);

            Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
            Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
            reference(a, b, expected);
            candidate(a, b, actual);

            return expected.SequenceEqual(actual);
        }, iter: IterationCount);
    }


    private static void AssertInvertAgrees(ScalarInvertDelegate candidate)
    {
        RawBytesGen.Sample(aRaw =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(aRaw, a, Curve);
            if(a.IndexOfAnyExcept((byte)0) < 0)
            {
                return true; //Zero is not invertible in either backend; skip.
            }

            Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
            Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
            ReferenceInvert(a, expected, Curve);
            candidate(a, actual, Curve);

            return expected.SequenceEqual(actual);
        }, iter: IterationCount);
    }


    private static void AssertReduceAgrees(ScalarReduceDelegate candidate)
    {
        WideBytesGen.Sample(wide =>
        {
            Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
            Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(wide, expected, Curve);
            candidate(wide, actual, Curve);

            return expected.SequenceEqual(actual);
        }, iter: IterationCount);
    }


    private static void AssertInverseProductIsOne(ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert)
    {
        RawBytesGen.Sample(aRaw =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(aRaw, a, Curve);
            if(a.IndexOfAnyExcept((byte)0) < 0)
            {
                return true;
            }

            Span<byte> inverse = stackalloc byte[Scalar.SizeBytes];
            invert(a, inverse, Curve);
            Span<byte> product = stackalloc byte[Scalar.SizeBytes];
            multiply(a, inverse, product, Curve);

            Span<byte> one = stackalloc byte[Scalar.SizeBytes];
            one[^1] = 1;

            return product.SequenceEqual(one);
        }, iter: IterationCount);
    }


    private static void AssertEdgeCases(ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert)
    {
        byte[][] values =
        [
            Bytes(BigInteger.One),
            Bytes(2),
            Bytes(P - 1),
            Bytes(P - 2),
            Bytes((P - 1) / 2)
        ];

        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
        foreach(byte[] x in values)
        {
            foreach(byte[] y in values)
            {
                ReferenceMultiply(x, y, expected, Curve);
                multiply(x, y, actual, Curve);
                Assert.IsTrue(expected.SequenceEqual(actual), "Edge-case multiply must match the reference.");
            }

            ReferenceInvert(x, expected, Curve);
            invert(x, actual, Curve);
            Assert.IsTrue(expected.SequenceEqual(actual), "Edge-case invert must match the reference.");
        }
    }


    private static BinaryFieldOp Binary(ScalarMultiplyDelegate op) => (a, b, result) => op(a, b, result, Curve);

    private static BinaryFieldOp Binary(ScalarAddDelegate op) => (a, b, result) => op(a, b, result, Curve);

    private static BinaryFieldOp Binary(ScalarSubtractDelegate op) => (a, b, result) => op(a, b, result, Curve);


    private static byte[] Bytes(BigInteger value)
    {
        byte[] result = new byte[Scalar.SizeBytes];
        value.TryWriteBytes(result, out int written, isUnsigned: true, isBigEndian: true);
        if(written < result.Length)
        {
            int shift = result.Length - written;
            result.AsSpan(0, written).CopyTo(result.AsSpan(shift));
            result.AsSpan(0, shift).Clear();
        }

        return result;
    }


    private static byte[] Bytes(int value) => Bytes(new BigInteger(value));
}
