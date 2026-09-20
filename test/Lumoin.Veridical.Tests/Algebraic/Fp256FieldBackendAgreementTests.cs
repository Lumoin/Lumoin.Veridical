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
    /// <summary>The number of CsCheck samples per property test.</summary>
    private const long IterationCount = 500;

    /// <summary>The curve tag every delegate call in this class is stamped with; P-256 base-field operations are curve-agnostic, so <see cref="CurveParameterSet.None"/> suffices.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.None;

    /// <summary>The P-256 base-field prime, read from the BigInteger reference backend.</summary>
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>A generator of raw, unreduced scalar-width byte arrays, reduced into canonical field elements before use.</summary>
    private static Gen<byte[]> RawBytesGen { get; } = Gen.Byte.Array[Scalar.SizeBytes];

    /// <summary>A generator of 64-byte wide arrays, exercising the reduction delegates' full input range.</summary>
    private static Gen<byte[]> WideBytesGen { get; } = Gen.Byte.Array[64];

    /// <summary>The BigInteger reference scalar-reduction delegate, the oracle every candidate reduction is compared against.</summary>
    private static ScalarReduceDelegate ReferenceReduce { get; } = P256BaseFieldReference.GetReduce();

    /// <summary>The BigInteger reference addition delegate, the oracle every candidate addition is compared against.</summary>
    private static ScalarAddDelegate ReferenceAdd { get; } = P256BaseFieldReference.GetAdd();

    /// <summary>The BigInteger reference subtraction delegate, the oracle every candidate subtraction is compared against.</summary>
    private static ScalarSubtractDelegate ReferenceSubtract { get; } = P256BaseFieldReference.GetSubtract();

    /// <summary>The BigInteger reference multiplication delegate, the oracle every candidate multiplication is compared against.</summary>
    private static ScalarMultiplyDelegate ReferenceMultiply { get; } = P256BaseFieldReference.GetMultiply();

    /// <summary>The BigInteger reference inversion delegate, the oracle every candidate inversion is compared against.</summary>
    private static ScalarInvertDelegate ReferenceInvert { get; } = P256BaseFieldReference.GetInvert();

    /// <summary>A curve-bound binary field operation, adapting a scalar delegate's <see cref="CurveParameterSet"/> parameter away so <see cref="AssertBinaryAgrees"/> can compare two delegate kinds uniformly.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <param name="result">The buffer receiving the result.</param>
    private delegate void BinaryFieldOp(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result);

    /// <summary>A curve-bound unary field operation, the one-operand counterpart of <see cref="BinaryFieldOp"/>.</summary>
    /// <param name="a">The operand.</param>
    /// <param name="result">The buffer receiving the result.</param>
    private delegate void UnaryFieldOp(ReadOnlySpan<byte> a, Span<byte> result);


    /// <summary>Property-based: the Montgomery backend's multiplication agrees with the BigInteger reference across random field elements.</summary>
    [TestMethod]
    public void MontgomeryMultiplyAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceMultiply), Binary(P256BaseFieldMontgomeryBackend.GetMultiply()));

    /// <summary>Property-based: the Montgomery backend's addition agrees with the BigInteger reference across random field elements.</summary>
    [TestMethod]
    public void MontgomeryAddAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceAdd), Binary(P256BaseFieldMontgomeryBackend.GetAdd()));

    /// <summary>Property-based: the Montgomery backend's subtraction agrees with the BigInteger reference across random field elements.</summary>
    [TestMethod]
    public void MontgomerySubtractAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceSubtract), Binary(P256BaseFieldMontgomeryBackend.GetSubtract()));

    /// <summary>Property-based: the Montgomery backend's inversion agrees with the BigInteger reference across random nonzero field elements.</summary>
    [TestMethod]
    public void MontgomeryInvertAgreesWithReference() =>
        AssertInvertAgrees(P256BaseFieldMontgomeryBackend.GetInvert());

    /// <summary>Property-based: the Montgomery backend's wide-input reduction agrees with the BigInteger reference across random 64-byte inputs.</summary>
    [TestMethod]
    public void MontgomeryReduceAgreesWithReference() =>
        AssertReduceAgrees(P256BaseFieldMontgomeryBackend.GetReduce());

    /// <summary>Property-based: the Montgomery backend's <c>a · a⁻¹</c> equals the field's multiplicative identity across random nonzero field elements.</summary>
    [TestMethod]
    public void MontgomeryInverseProductIsOne() =>
        AssertInverseProductIsOne(P256BaseFieldMontgomeryBackend.GetMultiply(), P256BaseFieldMontgomeryBackend.GetInvert());

    /// <summary>Verifies that the Montgomery backend's multiplication and inversion agree with the BigInteger reference at the hand-picked edge residues (1, 2, p−1, p−2, (p−1)/2).</summary>
    [TestMethod]
    public void MontgomeryEdgeCasesAgreeWithReference() =>
        AssertEdgeCases(P256BaseFieldMontgomeryBackend.GetMultiply(), P256BaseFieldMontgomeryBackend.GetInvert());


    /// <summary>Property-based: the 1-CIOS Montgomery-domain multiply, once its operands are lifted in and its result dropped out, agrees with the canonical BigInteger reference across random field elements.</summary>
    [TestMethod]
    public void MontgomeryDomainMultiplyAgreesWithReference()
    {
        //The 1-CIOS Montgomery-domain multiply must equal the canonical reference once the
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


    /// <summary>Property-based: the generic and the P-256-specialized Montgomery reductions agree byte-for-byte with each other and, dropped out of the domain, with the BigInteger reference across random field elements.</summary>
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


    /// <summary>Verifies that the generic and specialized Montgomery reductions agree with each other and with the BigInteger reference at the hand-picked edge residues (0, 1, p−1, p−2, (p−1)/2, R mod p, R² mod p) and their cross-products.</summary>
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


    /// <summary>
    /// Lifts the two canonical operands into the Montgomery domain, runs the live (generic-reduce) and the
    /// specialized-reduce multiplies, and checks the residues are byte-identical to each other and, dropped
    /// out, to <c>a·b mod p</c>.
    /// </summary>
    /// <param name="live">The live, generic-reduce Montgomery multiply delegate.</param>
    /// <param name="a">The first canonical operand.</param>
    /// <param name="b">The second canonical operand.</param>
    /// <returns><see langword="true"/> when both reductions agree with each other and with the BigInteger reference.</returns>
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


    /// <summary>Property-based: the in-domain Montgomery inversion (Montgomery in, Montgomery out), once its result is dropped out, agrees with the canonical BigInteger reference across random nonzero field elements.</summary>
    [TestMethod]
    public void MontgomeryDomainInvertAgreesWithReference()
    {
        //The in-domain inversion (Montgomery in, Montgomery out, no R²-lift, no final drop)
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


    /// <summary>Property-based: converting a canonical field element to the Montgomery domain and back is the identity, confirming the boundary converters are inverses.</summary>
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


    /// <summary>Property-based: the Solinas backend's multiplication agrees with the BigInteger reference across random field elements.</summary>
    [TestMethod]
    public void SolinasMultiplyAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceMultiply), Binary(P256BaseFieldSolinasBackend.GetMultiply()));

    /// <summary>Property-based: the Solinas backend's addition agrees with the BigInteger reference across random field elements.</summary>
    [TestMethod]
    public void SolinasAddAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceAdd), Binary(P256BaseFieldSolinasBackend.GetAdd()));

    /// <summary>Property-based: the Solinas backend's subtraction agrees with the BigInteger reference across random field elements.</summary>
    [TestMethod]
    public void SolinasSubtractAgreesWithReference() =>
        AssertBinaryAgrees(Binary(ReferenceSubtract), Binary(P256BaseFieldSolinasBackend.GetSubtract()));

    /// <summary>Property-based: the Solinas backend's inversion agrees with the BigInteger reference across random nonzero field elements.</summary>
    [TestMethod]
    public void SolinasInvertAgreesWithReference() =>
        AssertInvertAgrees(P256BaseFieldSolinasBackend.GetInvert());

    /// <summary>Property-based: the Solinas backend's wide-input reduction agrees with the BigInteger reference across random 64-byte inputs.</summary>
    [TestMethod]
    public void SolinasReduceAgreesWithReference() =>
        AssertReduceAgrees(P256BaseFieldSolinasBackend.GetReduce());

    /// <summary>Property-based: the Solinas backend's <c>a · a⁻¹</c> equals the field's multiplicative identity across random nonzero field elements.</summary>
    [TestMethod]
    public void SolinasInverseProductIsOne() =>
        AssertInverseProductIsOne(P256BaseFieldSolinasBackend.GetMultiply(), P256BaseFieldSolinasBackend.GetInvert());

    /// <summary>Verifies that the Solinas backend's multiplication and inversion agree with the BigInteger reference at the hand-picked edge residues (1, 2, p−1, p−2, (p−1)/2).</summary>
    [TestMethod]
    public void SolinasEdgeCasesAgreeWithReference() =>
        AssertEdgeCases(P256BaseFieldSolinasBackend.GetMultiply(), P256BaseFieldSolinasBackend.GetInvert());

    /// <summary>Property-based: the Montgomery and the Solinas backends' multiplications agree with each other across random field elements, a second cross-backend check independent of the BigInteger reference.</summary>
    [TestMethod]
    public void MontgomeryAndSolinasMultiplyAgree() =>
        AssertBinaryAgrees(Binary(P256BaseFieldMontgomeryBackend.GetMultiply()), Binary(P256BaseFieldSolinasBackend.GetMultiply()));


    /// <summary>Checks a candidate binary operation against a reference binary operation across random field-element pairs.</summary>
    /// <param name="reference">The oracle operation.</param>
    /// <param name="candidate">The operation under test.</param>
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


    /// <summary>Checks a candidate inversion delegate against the BigInteger reference across random nonzero field elements, skipping zero (not invertible).</summary>
    /// <param name="candidate">The inversion delegate under test.</param>
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


    /// <summary>Checks a candidate wide-input reduction delegate against the BigInteger reference across random 64-byte inputs.</summary>
    /// <param name="candidate">The reduction delegate under test.</param>
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


    /// <summary>Checks that a candidate backend's <c>a · a⁻¹</c> equals the field's multiplicative identity across random nonzero field elements, skipping zero (not invertible).</summary>
    /// <param name="multiply">The multiplication delegate under test.</param>
    /// <param name="invert">The inversion delegate under test.</param>
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


    /// <summary>Checks a candidate backend's multiplication and inversion against the BigInteger reference at the hand-picked edge residues (1, 2, p−1, p−2, (p−1)/2) and their cross-products.</summary>
    /// <param name="multiply">The multiplication delegate under test.</param>
    /// <param name="invert">The inversion delegate under test.</param>
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


    /// <summary>Adapts a scalar multiplication delegate into a curve-bound <see cref="BinaryFieldOp"/> stamped with this class's fixed <see cref="Curve"/>.</summary>
    /// <param name="op">The multiplication delegate to adapt.</param>
    /// <returns>The adapted operation.</returns>
    private static BinaryFieldOp Binary(ScalarMultiplyDelegate op) => (a, b, result) => op(a, b, result, Curve);

    /// <summary>Adapts a scalar addition delegate into a curve-bound <see cref="BinaryFieldOp"/> stamped with this class's fixed <see cref="Curve"/>.</summary>
    /// <param name="op">The addition delegate to adapt.</param>
    /// <returns>The adapted operation.</returns>
    private static BinaryFieldOp Binary(ScalarAddDelegate op) => (a, b, result) => op(a, b, result, Curve);

    /// <summary>Adapts a scalar subtraction delegate into a curve-bound <see cref="BinaryFieldOp"/> stamped with this class's fixed <see cref="Curve"/>.</summary>
    /// <param name="op">The subtraction delegate to adapt.</param>
    /// <returns>The adapted operation.</returns>
    private static BinaryFieldOp Binary(ScalarSubtractDelegate op) => (a, b, result) => op(a, b, result, Curve);


    /// <summary>Encodes a non-negative integer as a canonical big-endian scalar, zero-padded to <see cref="Scalar.SizeBytes"/> bytes.</summary>
    /// <param name="value">The non-negative integer to encode.</param>
    /// <returns>The canonical bytes.</returns>
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


    /// <summary>Encodes a non-negative small integer as a canonical big-endian scalar, zero-padded to <see cref="Scalar.SizeBytes"/> bytes.</summary>
    /// <param name="value">The non-negative integer to encode.</param>
    /// <returns>The canonical bytes.</returns>
    private static byte[] Bytes(int value) => Bytes(new BigInteger(value));
}
