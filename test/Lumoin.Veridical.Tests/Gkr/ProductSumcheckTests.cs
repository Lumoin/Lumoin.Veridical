using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The product sumcheck (<see cref="ProductSumcheck"/>) over the P-256 base field Fp256 — the GKR
/// layer shape (a product of multilinear factors, degree = factor count, reduced by Lagrange
/// interpolation). An honest claim that <c>H = Σ_x f(x)·g(x)</c> verifies and reduces to the
/// product of the factors' multilinear extensions at the Fiat-Shamir point (checked against an
/// independent BigInteger oracle); tampering a round polynomial is rejected.
/// </summary>
[TestClass]
internal sealed class ProductSumcheckTests
{
    private const int ScalarSize = 32;
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();

    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();

    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.product.test");

    private static FiatShamirOperationLabel ClaimLabel { get; } = new("veridical.gkr.product.claim");


    [TestMethod]
    public void HonestProductSumVerifiesAndReducesToTheFactorProduct()
    {
        const int variableCount = 6;
        const int size = 1 << variableCount;
        const int factorTableBytes = 2 * size * ScalarSize;

        BigInteger[] f = new BigInteger[size];
        BigInteger[] g = new BigInteger[size];
        using IMemoryOwner<byte> factorTablesOwner = BaseMemoryPool.Shared.Rent(factorTableBytes);
        Span<byte> factorTables = factorTablesOwner.Memory.Span[..factorTableBytes];
        BigInteger claimedSum = BigInteger.Zero;
        for(int i = 0; i < size; i++)
        {
            f[i] = RandomFieldElement(i);
            g[i] = RandomFieldElement(i + 500);
            WriteCanonical(f[i], factorTables.Slice(i * ScalarSize, ScalarSize));
            WriteCanonical(g[i], factorTables.Slice((size + i) * ScalarSize, ScalarSize));
            claimedSum = (claimedSum + (f[i] * g[i])) % P;
        }

        byte[] claimed = Canonical(claimedSum);

        using FiatShamirTranscript proverTranscript = NewTranscript(claimed);
        using FiatShamirTranscript verifierTranscript = NewTranscript(claimed);

        using ProductSumcheckProverResult result = ProductSumcheck.Prove(
            factorTables, 2, variableCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using ProductSumcheckProof proof = result.Proof;

        using MultilinearSumcheckVerification verification = ProductSumcheck.Verify(
            claimed, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsTrue(verification.Accepted, "Each round must be consistent and the final factor product must match the reduced claim.");

        //Independent oracle: the factors' multilinear extensions at the challenge point, and their product.
        BigInteger expectedF = EvaluateMultilinear(f, verification.Point.Span, variableCount);
        BigInteger expectedG = EvaluateMultilinear(g, verification.Point.Span, variableCount);
        Assert.AreEqual(expectedF, ToInteger(proof.FinalValues.Span[..ScalarSize]), "FinalValues[0] must be f evaluated at the challenge point.");
        Assert.AreEqual(expectedG, ToInteger(proof.FinalValues.Span.Slice(ScalarSize, ScalarSize)), "FinalValues[1] must be g evaluated at the challenge point.");
        Assert.AreEqual((expectedF * expectedG) % P, ToInteger(verification.FinalClaim.Span), "The reduced claim must equal f(r)·g(r).");
    }


    [TestMethod]
    public void TamperedRoundPolynomialIsRejected()
    {
        const int variableCount = 5;
        const int size = 1 << variableCount;
        const int factorTableBytes = 2 * size * ScalarSize;

        using IMemoryOwner<byte> factorTablesOwner = BaseMemoryPool.Shared.Rent(factorTableBytes);
        Span<byte> factorTables = factorTablesOwner.Memory.Span[..factorTableBytes];
        BigInteger claimedSum = BigInteger.Zero;
        for(int i = 0; i < size; i++)
        {
            BigInteger fi = RandomFieldElement(i + 7000);
            BigInteger gi = RandomFieldElement(i + 9000);
            WriteCanonical(fi, factorTables.Slice(i * ScalarSize, ScalarSize));
            WriteCanonical(gi, factorTables.Slice((size + i) * ScalarSize, ScalarSize));
            claimedSum = (claimedSum + (fi * gi)) % P;
        }

        byte[] claimed = Canonical(claimedSum);

        using FiatShamirTranscript proverTranscript = NewTranscript(claimed);
        using ProductSumcheckProverResult result = ProductSumcheck.Prove(
            factorTables, 2, variableCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using ProductSumcheckProof proof = result.Proof;

        byte[] tampered = proof.RoundPolynomials.ToArray();
        tampered[ScalarSize - 1] ^= 0x01;
        using ProductSumcheckProof tamperedProof = ProductSumcheckProof.FromParts(
            tampered, proof.FinalValues.Span, variableCount, 2, BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = NewTranscript(claimed);
        using MultilinearSumcheckVerification verification = ProductSumcheck.Verify(
            claimed, tamperedProof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verification.Accepted, "A tampered round polynomial must be rejected.");
    }


    private static FiatShamirTranscript NewTranscript(byte[] claimed)
    {
        var transcript = FiatShamirTranscript.Initialise(Domain, "veridical.gkr.product.seed"u8, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        transcript.AbsorbBytes(ClaimLabel, claimed, Hash);

        return transcript;
    }


    private static BigInteger EvaluateMultilinear(BigInteger[] values, ReadOnlySpan<byte> point, int variableCount)
    {
        BigInteger result = BigInteger.Zero;
        for(int i = 0; i < values.Length; i++)
        {
            BigInteger weight = BigInteger.One;
            for(int bit = 0; bit < variableCount; bit++)
            {
                BigInteger challenge = ToInteger(point.Slice((variableCount - 1 - bit) * ScalarSize, ScalarSize));
                BigInteger factor = ((i >> bit) & 1) == 1 ? challenge : Mod(BigInteger.One - challenge);
                weight = (weight * factor) % P;
            }

            result = (result + (values[i] * weight)) % P;
        }

        return result;
    }


    private static BigInteger RandomFieldElement(int index)
    {
        Span<byte> seed = stackalloc byte[4];
        seed[0] = (byte)(index >> 24);
        seed[1] = (byte)(index >> 16);
        seed[2] = (byte)(index >> 8);
        seed[3] = (byte)index;
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(seed, digest);

        return ToInteger(digest);
    }


    private static byte[] Canonical(BigInteger value)
    {
        byte[] bytes = new byte[ScalarSize];
        WriteCanonical(value, bytes);

        return bytes;
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger reduced = Mod(value);
        Span<byte> little = stackalloc byte[ScalarSize + 1];
        if(reduced.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
        {
            for(int i = 0; i < ScalarSize && i < written; i++)
            {
                destination[ScalarSize - 1 - i] = little[i];
            }
        }
    }


    private static BigInteger ToInteger(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static BigInteger Mod(BigInteger value) => ((value % P) + P) % P;
}
