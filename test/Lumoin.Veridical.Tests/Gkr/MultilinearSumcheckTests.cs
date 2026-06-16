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
/// The multilinear sumcheck (<see cref="MultilinearSumcheck"/>) over the P-256 base field Fp256 —
/// the foundational round-by-round binding the layered GKR prover composes. An honest prover's
/// claim that <c>H = Σ_{x} f(x)</c> verifies and the protocol reduces it to the multilinear
/// extension evaluated at the Fiat-Shamir challenge point (checked against an independent
/// BigInteger oracle); tampering a round polynomial is rejected.
/// </summary>
[TestClass]
internal sealed class MultilinearSumcheckTests
{
    private const int ScalarSize = 32;
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();

    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.sumcheck.test");

    private static FiatShamirOperationLabel ClaimLabel { get; } = new("veridical.gkr.sumcheck.claim");


    [TestMethod]
    public void HonestMultilinearSumVerifiesAndReducesToTheCorrectEvaluation()
    {
        const int variableCount = 8;
        const int size = 1 << variableCount;
        const int tableBytes = size * ScalarSize;

        BigInteger[] values = new BigInteger[size];
        using IMemoryOwner<byte> tableOwner = BaseMemoryPool.Shared.Rent(tableBytes);
        Span<byte> table = tableOwner.Memory.Span[..tableBytes];
        BigInteger claimedSum = BigInteger.Zero;
        for(int i = 0; i < size; i++)
        {
            values[i] = RandomFieldElement(i);
            WriteCanonical(values[i], table.Slice(i * ScalarSize, ScalarSize));
            claimedSum = (claimedSum + values[i]) % P;
        }

        byte[] claimed = Canonical(claimedSum);

        using FiatShamirTranscript proverTranscript = NewTranscript(claimed);
        using FiatShamirTranscript verifierTranscript = NewTranscript(claimed);

        using MultilinearSumcheckProof proof = MultilinearSumcheck.Prove(
            table, variableCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        using MultilinearSumcheckVerification verification = MultilinearSumcheck.Verify(
            claimed, proof, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsTrue(verification.Accepted, "Every round polynomial must sum to the running claim.");

        //The prover's folded f(r) must equal the claim the verifier reduced the sum to.
        Assert.IsTrue(proof.FinalValue.Span.SequenceEqual(verification.FinalClaim.Span), "The prover's f(r) must equal the verifier's reduced claim.");

        //Independent oracle: the multilinear extension at the challenge point equals the reduced claim.
        BigInteger expected = EvaluateMultilinear(values, verification.Point.Span, variableCount);
        Assert.AreEqual(expected, ToInteger(verification.FinalClaim.Span), "The reduced claim must equal the multilinear extension at the challenge point.");
    }


    [TestMethod]
    public void TamperedRoundPolynomialIsRejected()
    {
        const int variableCount = 6;
        const int size = 1 << variableCount;
        const int tableBytes = size * ScalarSize;

        using IMemoryOwner<byte> tableOwner = BaseMemoryPool.Shared.Rent(tableBytes);
        Span<byte> table = tableOwner.Memory.Span[..tableBytes];
        BigInteger claimedSum = BigInteger.Zero;
        for(int i = 0; i < size; i++)
        {
            BigInteger value = RandomFieldElement(i + 1000);
            WriteCanonical(value, table.Slice(i * ScalarSize, ScalarSize));
            claimedSum = (claimedSum + value) % P;
        }

        byte[] claimed = Canonical(claimedSum);

        using FiatShamirTranscript proverTranscript = NewTranscript(claimed);
        using MultilinearSumcheckProof proof = MultilinearSumcheck.Prove(
            table, variableCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        //Flip a byte of the first round polynomial so s(0) + s(1) no longer equals the claim.
        byte[] tampered = proof.RoundPolynomials.ToArray();
        tampered[ScalarSize - 1] ^= 0x01;
        using MultilinearSumcheckProof tamperedProof = MultilinearSumcheckProof.FromParts(
            tampered, proof.FinalValue.Span, variableCount, BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = NewTranscript(claimed);
        using MultilinearSumcheckVerification verification = MultilinearSumcheck.Verify(
            claimed, tamperedProof, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verification.Accepted, "A tampered round polynomial must be rejected.");
    }


    private static FiatShamirTranscript NewTranscript(byte[] claimed)
    {
        var transcript = FiatShamirTranscript.Initialise(Domain, "veridical.gkr.sumcheck.seed"u8, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        transcript.AbsorbBytes(ClaimLabel, claimed, Hash);

        return transcript;
    }


    //The multilinear extension Σ_i values[i]·Π_b (r_b if bit b of i is set else 1−r_b), where the
    //challenge for bit b is point[v−1−b] (the prover binds the most-significant bit first).
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
        BinaryPrimitivesWriteInt(seed, index);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(seed, digest);

        return ToInteger(digest);
    }


    private static void BinaryPrimitivesWriteInt(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 24);
        destination[1] = (byte)(value >> 16);
        destination[2] = (byte)(value >> 8);
        destination[3] = (byte)value;
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
