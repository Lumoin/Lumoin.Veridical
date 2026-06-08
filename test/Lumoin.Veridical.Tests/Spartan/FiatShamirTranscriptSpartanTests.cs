using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Tests for the Spartan-specific transcript absorb extensions: the
/// compressed-round-polynomial absorb and the sumcheck-initial-claim
/// absorb. The assertions check determinism (same inputs → same
/// post-squeeze challenge) and discrimination (different inputs →
/// different post-squeeze challenge), not raw byte equality, so the
/// tests are robust to label-string adjustments while still verifying
/// the construction wires every input bit into the state.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptSpartanTests
{
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();


    [TestMethod]
    public void AbsorbCompressedRoundPolynomialIsDeterministic()
    {
        byte[] polynomialBytes = BuildCompressedBytes([7, 11, 13]);
        using CompressedRoundPolynomial polynomial = CompressedRoundPolynomial.FromCompressedBytes(
            polynomialBytes, 3, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using Scalar a = AbsorbAndSqueeze(polynomial);
        using Scalar b = AbsorbAndSqueeze(polynomial);

        Assert.IsTrue(a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan()), "Two transcripts initialised and fed identical inputs must produce identical squeezes.");
    }


    [TestMethod]
    public void AbsorbCompressedRoundPolynomialIsSensitiveToBytes()
    {
        byte[] firstBytes = BuildCompressedBytes([7, 11, 13]);
        byte[] secondBytes = BuildCompressedBytes([7, 11, 14]); //one byte different in the last slot.
        using CompressedRoundPolynomial first = CompressedRoundPolynomial.FromCompressedBytes(
            firstBytes, 3, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using CompressedRoundPolynomial second = CompressedRoundPolynomial.FromCompressedBytes(
            secondBytes, 3, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using Scalar a = AbsorbAndSqueeze(first);
        using Scalar b = AbsorbAndSqueeze(second);

        Assert.IsFalse(a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan()), "Absorbed bytes must influence the squeezed challenge.");
    }


    [TestMethod]
    public void AbsorbSumcheckClaimDistinguishesAllThreeFields()
    {
        byte[] sumBytes = new byte[Scalar.SizeBytes];
        WriteCanonical(new BigInteger(42), sumBytes);
        using Scalar baseSum = Scalar.FromCanonical(sumBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        var baseClaim = new SumcheckClaim(baseSum, NumRounds: 5, DegreeBound: 3);
        using Scalar baseChallenge = AbsorbClaimAndSqueeze(baseClaim);

        //Vary the claimed sum and check the squeeze changes.
        byte[] differentSumBytes = new byte[Scalar.SizeBytes];
        WriteCanonical(new BigInteger(43), differentSumBytes);
        using Scalar differentSum = Scalar.FromCanonical(differentSumBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        var claimDifferentSum = new SumcheckClaim(differentSum, NumRounds: 5, DegreeBound: 3);
        using Scalar challengeDifferentSum = AbsorbClaimAndSqueeze(claimDifferentSum);
        Assert.IsFalse(baseChallenge.AsReadOnlySpan().SequenceEqual(challengeDifferentSum.AsReadOnlySpan()), "Different claimed sums must yield different squeezes.");

        //Vary the round count.
        var claimDifferentRounds = new SumcheckClaim(baseSum, NumRounds: 6, DegreeBound: 3);
        using Scalar challengeDifferentRounds = AbsorbClaimAndSqueeze(claimDifferentRounds);
        Assert.IsFalse(baseChallenge.AsReadOnlySpan().SequenceEqual(challengeDifferentRounds.AsReadOnlySpan()), "Different round counts must yield different squeezes.");

        //Vary the degree bound.
        var claimDifferentDegree = new SumcheckClaim(baseSum, NumRounds: 5, DegreeBound: 2);
        using Scalar challengeDifferentDegree = AbsorbClaimAndSqueeze(claimDifferentDegree);
        Assert.IsFalse(baseChallenge.AsReadOnlySpan().SequenceEqual(challengeDifferentDegree.AsReadOnlySpan()), "Different degree bounds must yield different squeezes.");
    }


    private static Scalar AbsorbAndSqueeze(CompressedRoundPolynomial polynomial)
    {
        byte[] seed = Encoding.UTF8.GetBytes("spartan-test-seed");
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            seed,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);

        transcript.AbsorbCompressedRoundPolynomial(polynomial, Hash);
        return transcript.SqueezeScalar(
            new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.SumcheckRoundChallenge),
            Squeeze,
            Hash,
            Reduce, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static Scalar AbsorbClaimAndSqueeze(SumcheckClaim claim)
    {
        byte[] seed = Encoding.UTF8.GetBytes("spartan-claim-seed");
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            seed,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);

        transcript.AbsorbSumcheckClaim(claim, Hash);
        return transcript.SqueezeScalar(
            new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.OuterTau),
            Squeeze,
            Hash,
            Reduce, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static byte[] BuildCompressedBytes(int[] slotValues)
    {
        int elementSize = Scalar.SizeBytes;
        byte[] bytes = new byte[slotValues.Length * elementSize];
        for(int i = 0; i < slotValues.Length; i++)
        {
            WriteCanonical(new BigInteger(slotValues[i]), bytes.AsSpan(i * elementSize, elementSize));
        }

        return bytes;
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