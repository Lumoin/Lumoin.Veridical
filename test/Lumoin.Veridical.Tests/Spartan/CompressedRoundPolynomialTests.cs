using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Tests for <see cref="CompressedRoundPolynomial"/> and its
/// Compress/Decompress boundary helpers. Compression must drop the
/// linear-term coefficient and Decompression must reconstruct it from
/// the running sumcheck claim such that
/// <c>poly(0) + poly(1) = claim</c>.
/// </summary>
[TestClass]
internal sealed class CompressedRoundPolynomialTests
{
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly PolynomialEvaluateDelegate Evaluate = PolynomialBigIntegerReference.GetEvaluate();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly BigInteger FieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;

    private const long IterationCount = 30;


    [TestMethod]
    public void CompressDropsLinearTermAndKeepsOtherCoefficients()
    {
        //A hand-built polynomial: f(x) = 7 + 11x + 13x^2 + 17x^3.
        int elementSize = Scalar.SizeBytes;
        const int Degree = 3;
        int coefficientBufferSize = (Degree + 1) * elementSize;

        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(coefficientBufferSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..coefficientBufferSize];
        coefficients.Clear();
        WriteCanonical(new BigInteger(7), coefficients.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(11), coefficients.Slice(1 * elementSize, elementSize));
        WriteCanonical(new BigInteger(13), coefficients.Slice(2 * elementSize, elementSize));
        WriteCanonical(new BigInteger(17), coefficients.Slice(3 * elementSize, elementSize));

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using CompressedRoundPolynomial compressed = polynomial.Compress(SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(Degree, compressed.Degree, "Compressed polynomial should carry the same algebraic degree as the source.");
        Assert.AreEqual(Degree, compressed.StoredCoefficientCount, "Stored coefficient count should equal the algebraic degree (one fewer than uncompressed).");

        //Storage slot 0 = c_0; storage slots 1, 2 = c_2, c_3. The linear term c_1 = 11 is gone.
        Assert.AreEqual(new BigInteger(7), new BigInteger(compressed.GetStoredCoefficientBytes(0), isUnsigned: true, isBigEndian: true));
        Assert.AreEqual(new BigInteger(13), new BigInteger(compressed.GetStoredCoefficientBytes(1), isUnsigned: true, isBigEndian: true));
        Assert.AreEqual(new BigInteger(17), new BigInteger(compressed.GetStoredCoefficientBytes(2), isUnsigned: true, isBigEndian: true));
    }


    [TestMethod]
    public void DecompressReconstructsLinearTermFromValidClaim()
    {
        //Same polynomial f(x) = 7 + 11x + 13x^2 + 17x^3.
        //claim = f(0) + f(1) = 7 + (7 + 11 + 13 + 17) = 7 + 48 = 55.
        int elementSize = Scalar.SizeBytes;
        const int Degree = 3;
        int coefficientBufferSize = (Degree + 1) * elementSize;

        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(coefficientBufferSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..coefficientBufferSize];
        coefficients.Clear();
        WriteCanonical(new BigInteger(7), coefficients.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(11), coefficients.Slice(1 * elementSize, elementSize));
        WriteCanonical(new BigInteger(13), coefficients.Slice(2 * elementSize, elementSize));
        WriteCanonical(new BigInteger(17), coefficients.Slice(3 * elementSize, elementSize));

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using CompressedRoundPolynomial compressed = polynomial.Compress(SensitiveMemoryPool<byte>.Shared);

        using IMemoryOwner<byte> claimOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);
        Span<byte> claimBytes = claimOwner.Memory.Span[..elementSize];
        claimBytes.Clear();
        WriteCanonical(new BigInteger(55), claimBytes);
        using Scalar claim = Scalar.FromCanonical(claimBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using Polynomial decompressed = compressed.Decompress(claim, Subtract, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(Degree, decompressed.Degree, "Decompressed polynomial should have the same storage degree.");
        for(int k = 0; k <= Degree; k++)
        {
            ReadOnlySpan<byte> originalCoefficient = polynomial.AsReadOnlySpan().Slice(k * elementSize, elementSize);
            ReadOnlySpan<byte> recoveredCoefficient = decompressed.AsReadOnlySpan().Slice(k * elementSize, elementSize);
            Assert.IsTrue(originalCoefficient.SequenceEqual(recoveredCoefficient), $"Coefficient c_{k} round-trip failed.");
        }
    }


    [TestMethod]
    public void CompressDecompressRoundTripIsIdentityWhenClaimIsHonest()
    {
        //Property-based: for any polynomial of degree in {2, 3, 4, 5} with
        //random coefficients, Compress followed by Decompress with the
        //honest claim e = f(0) + f(1) recovers the same polynomial bytes.
        Gen.Int[2, 5]
            .SelectMany(degree => Gen.Select(
                Gen.Const(degree),
                Gen.Byte.Array[Scalar.SizeBytes * (degree + 1)]))
            .Sample((degree, coefficientsRaw) =>
            {
                int elementSize = Scalar.SizeBytes;
                int coefficientBufferSize = (degree + 1) * elementSize;

                using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(coefficientBufferSize);
                Span<byte> coefficients = coefficientsOwner.Memory.Span[..coefficientBufferSize];
                ReduceSlots(coefficientsRaw, coefficients, elementSize);

                using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

                //Compute the honest claim e = f(0) + f(1) directly via the
                //BigInteger reference so the property test does not depend on
                //the Polynomial.Evaluate helper for correctness.
                BigInteger evaluationAtZero = BigInteger.Zero;
                BigInteger evaluationAtOne = BigInteger.Zero;
                for(int k = 0; k <= degree; k++)
                {
                    BigInteger c = new(coefficients.Slice(k * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
                    if(k == 0)
                    {
                        evaluationAtZero = c;
                    }
                    evaluationAtOne = (evaluationAtOne + c) % FieldOrder;
                }
                BigInteger expectedClaim = (evaluationAtZero + evaluationAtOne) % FieldOrder;

                using IMemoryOwner<byte> claimOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);
                Span<byte> claimBytes = claimOwner.Memory.Span[..elementSize];
                claimBytes.Clear();
                WriteCanonical(expectedClaim, claimBytes);
                using Scalar claim = Scalar.FromCanonical(claimBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

                using CompressedRoundPolynomial compressed = polynomial.Compress(SensitiveMemoryPool<byte>.Shared);
                using Polynomial recovered = compressed.Decompress(claim, Subtract, SensitiveMemoryPool<byte>.Shared);

                return polynomial.AsReadOnlySpan().SequenceEqual(recovered.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void DecompressedPolynomialSatisfiesSumcheckClaimAtZeroAndOne()
    {
        //An alternative invariant: the decompressed polynomial p must
        //satisfy p(0) + p(1) = claim. We construct a known polynomial,
        //compute its claim independently, compress, decompress, and then
        //verify the identity by evaluating the recovered polynomial at 0
        //and at 1.
        int elementSize = Scalar.SizeBytes;
        const int Degree = 3;
        int coefficientBufferSize = (Degree + 1) * elementSize;

        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(coefficientBufferSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..coefficientBufferSize];
        coefficients.Clear();
        WriteCanonical(new BigInteger(2), coefficients.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(3), coefficients.Slice(1 * elementSize, elementSize));
        WriteCanonical(new BigInteger(5), coefficients.Slice(2 * elementSize, elementSize));
        WriteCanonical(new BigInteger(7), coefficients.Slice(3 * elementSize, elementSize));

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        //claim = f(0) + f(1) = 2 + (2 + 3 + 5 + 7) = 2 + 17 = 19.
        using IMemoryOwner<byte> claimOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);
        Span<byte> claimBytes = claimOwner.Memory.Span[..elementSize];
        claimBytes.Clear();
        WriteCanonical(new BigInteger(19), claimBytes);
        using Scalar claim = Scalar.FromCanonical(claimBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using CompressedRoundPolynomial compressed = polynomial.Compress(SensitiveMemoryPool<byte>.Shared);
        using Polynomial recovered = compressed.Decompress(claim, Subtract, SensitiveMemoryPool<byte>.Shared);

        using IMemoryOwner<byte> zeroOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);
        using IMemoryOwner<byte> oneOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);
        Span<byte> zeroBytes = zeroOwner.Memory.Span[..elementSize];
        Span<byte> oneBytes = oneOwner.Memory.Span[..elementSize];
        zeroBytes.Clear();
        oneBytes.Clear();
        oneBytes[^1] = 1;
        using Scalar zero = Scalar.FromCanonical(zeroBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using Scalar one = Scalar.FromCanonical(oneBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using Scalar atZero = recovered.Evaluate(zero, Evaluate, SensitiveMemoryPool<byte>.Shared);
        using Scalar atOne = recovered.Evaluate(one, Evaluate, SensitiveMemoryPool<byte>.Shared);

        using IMemoryOwner<byte> sumOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);
        Span<byte> sumBytes = sumOwner.Memory.Span[..elementSize];
        Add(atZero.AsReadOnlySpan(), atOne.AsReadOnlySpan(), sumBytes, CurveParameterSet.Bls12Curve381);

        Assert.IsTrue(sumBytes.SequenceEqual(claim.AsReadOnlySpan()), "Decompressed polynomial must satisfy p(0) + p(1) = claim.");
    }


    [TestMethod]
    public void FromCompressedBytesRoundTrips()
    {
        int elementSize = Scalar.SizeBytes;
        const int Degree = 4;
        int storedBufferSize = Degree * elementSize;

        using IMemoryOwner<byte> bytesOwner = SensitiveMemoryPool<byte>.Shared.Rent(storedBufferSize);
        Span<byte> bytes = bytesOwner.Memory.Span[..storedBufferSize];
        bytes.Clear();
        WriteCanonical(new BigInteger(101), bytes.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(102), bytes.Slice(1 * elementSize, elementSize));
        WriteCanonical(new BigInteger(103), bytes.Slice(2 * elementSize, elementSize));
        WriteCanonical(new BigInteger(104), bytes.Slice(3 * elementSize, elementSize));

        using CompressedRoundPolynomial compressed = CompressedRoundPolynomial.FromCompressedBytes(
            bytes, Degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(Degree, compressed.Degree);
        Assert.IsTrue(bytes.SequenceEqual(compressed.AsReadOnlySpan()), "FromCompressedBytes should preserve the input bytes byte-for-byte.");
    }


    [TestMethod]
    public void CompressRejectsDegreeBelowTwo()
    {
        //Compression is only meaningful for degree ≥ 2 (degree-1
        //polynomials would lose all their non-constant content).
        int elementSize = Scalar.SizeBytes;
        const int Degree = 1;
        int coefficientBufferSize = (Degree + 1) * elementSize;

        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(coefficientBufferSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..coefficientBufferSize];
        coefficients.Clear();
        WriteCanonical(new BigInteger(3), coefficients.Slice(0, elementSize));
        WriteCanonical(new BigInteger(5), coefficients.Slice(elementSize, elementSize));

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        Assert.ThrowsExactly<ArgumentException>(() =>
            _ = polynomial.Compress(SensitiveMemoryPool<byte>.Shared));
    }


    [TestMethod]
    public void FromCompressedBytesRejectsDegreeBelowTwo()
    {
        byte[] bytes = new byte[Scalar.SizeBytes];
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            _ = CompressedRoundPolynomial.FromCompressedBytes(
                bytes, 1, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared));
    }


    [TestMethod]
    public void TagCarriesAlgebraicIdentityAndDegree()
    {
        int elementSize = Scalar.SizeBytes;
        const int Degree = 3;
        int coefficientBufferSize = (Degree + 1) * elementSize;

        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(coefficientBufferSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..coefficientBufferSize];
        coefficients.Clear();
        WriteCanonical(new BigInteger(1), coefficients.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(2), coefficients.Slice(1 * elementSize, elementSize));
        WriteCanonical(new BigInteger(3), coefficients.Slice(2 * elementSize, elementSize));
        WriteCanonical(new BigInteger(4), coefficients.Slice(3 * elementSize, elementSize));

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using CompressedRoundPolynomial compressed = polynomial.Compress(SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(AlgebraicRole.CompressedRoundPolynomial, compressed.Tag.Get<AlgebraicRole>(), "Tag should carry the CompressedRoundPolynomial role.");
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, compressed.Tag.Get<CurveParameterSet>(), "Tag should carry the BLS12-381 curve.");

        var degree = compressed.Tag.Get<CompressedRoundPolynomialDegree>();
        Assert.AreEqual(Degree, degree.Value, "Tag should carry the algebraic degree.");
    }


    private static void ReduceSlots(byte[] rawSource, Span<byte> destination, int elementSize)
    {
        int slotCount = destination.Length / elementSize;
        for(int i = 0; i < slotCount; i++)
        {
            Reduce(
                rawSource.AsSpan(i * elementSize, elementSize),
                destination.Slice(i * elementSize, elementSize),
                CurveParameterSet.Bls12Curve381);
        }
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}