using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Determinism properties for <see cref="FiatShamirTranscript"/>: two
/// transcripts with identical seeds, domain labels, and absorb sequences
/// produce identical squeeze outputs; changing any input alters the
/// challenge.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptDeterminismTests
{
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly FiatShamirDomainLabel DomainLabel = new("veridical.test.determinism.v1");
    private static readonly FiatShamirOperationLabel ChallengeLabel = new("test.challenge");

    private const int SqueezeByteCount = 32;
    private const long IterationCount = 30;


    [TestMethod]
    public void SameInputsProduceSameChallenges()
    {
        Gen.Byte.Array[32].Sample(seed =>
        {
            using FiatShamirTranscript a = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
            using FiatShamirTranscript b = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

            using IMemoryOwner<byte> oA = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
            using IMemoryOwner<byte> oB = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
            Span<byte> outA = oA.Memory.Span[..SqueezeByteCount];
            Span<byte> outB = oB.Memory.Span[..SqueezeByteCount];

            a.SqueezeBytes(ChallengeLabel, outA, Squeeze, Hash);
            b.SqueezeBytes(ChallengeLabel, outB, Squeeze, Hash);

            return outA.SequenceEqual(outB);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void DifferentSeedsProduceDifferentChallenges()
    {
        Gen.Select(Gen.Byte.Array[32], Gen.Byte.Array[32])
            .Where(t => !t.Item1.AsSpan().SequenceEqual(t.Item2))
            .Sample(t =>
            {
                using FiatShamirTranscript a = FiatShamirTranscript.Initialise(DomainLabel, t.Item1, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
                using FiatShamirTranscript b = FiatShamirTranscript.Initialise(DomainLabel, t.Item2, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

                using IMemoryOwner<byte> oA = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
                using IMemoryOwner<byte> oB = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
                Span<byte> outA = oA.Memory.Span[..SqueezeByteCount];
                Span<byte> outB = oB.Memory.Span[..SqueezeByteCount];

                a.SqueezeBytes(ChallengeLabel, outA, Squeeze, Hash);
                b.SqueezeBytes(ChallengeLabel, outB, Squeeze, Hash);

                return !outA.SequenceEqual(outB);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultipleSqueezesProduceDistinctChallenges()
    {
        //Two squeezes with the same label on the same transcript must
        //differ because the squeeze counter advances between them, and
        //the post-squeeze state update further perturbs the input to the
        //second squeeze.
        ReadOnlySpan<byte> seed = stackalloc byte[16];
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> o1 = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        using IMemoryOwner<byte> o2 = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        Span<byte> first = o1.Memory.Span[..SqueezeByteCount];
        Span<byte> second = o2.Memory.Span[..SqueezeByteCount];

        transcript.SqueezeBytes(ChallengeLabel, first, Squeeze, Hash);
        transcript.SqueezeBytes(ChallengeLabel, second, Squeeze, Hash);

        Assert.IsFalse(first.SequenceEqual(second), "Two squeezes with the same label must differ; counter and state-update should perturb the output.");
        Assert.AreEqual(2, transcript.SqueezeCount);
    }


    [TestMethod]
    public void AbsorbOrderMatters()
    {
        ReadOnlySpan<byte> seed = stackalloc byte[8];
        ReadOnlySpan<byte> dataA = "first-message"u8;
        ReadOnlySpan<byte> dataB = "second-message"u8;
        FiatShamirOperationLabel labelA = new("test.a");
        FiatShamirOperationLabel labelB = new("test.b");

        using FiatShamirTranscript x = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        x.AbsorbBytes(labelA, dataA, Hash);
        x.AbsorbBytes(labelB, dataB, Hash);

        using FiatShamirTranscript y = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        y.AbsorbBytes(labelB, dataB, Hash);
        y.AbsorbBytes(labelA, dataA, Hash);

        using IMemoryOwner<byte> oX = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        using IMemoryOwner<byte> oY = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        Span<byte> outX = oX.Memory.Span[..SqueezeByteCount];
        Span<byte> outY = oY.Memory.Span[..SqueezeByteCount];

        x.SqueezeBytes(ChallengeLabel, outX, Squeeze, Hash);
        y.SqueezeBytes(ChallengeLabel, outY, Squeeze, Hash);

        Assert.IsFalse(outX.SequenceEqual(outY), "Different absorb orders must produce different challenges.");
    }


    [TestMethod]
    public void SqueezeCountStartsAtZeroAndIncrementsBySqueeze()
    {
        ReadOnlySpan<byte> seed = stackalloc byte[16];
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        Assert.AreEqual(0, transcript.SqueezeCount);

        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        Span<byte> output = owner.Memory.Span[..SqueezeByteCount];

        transcript.SqueezeBytes(ChallengeLabel, output, Squeeze, Hash);
        Assert.AreEqual(1, transcript.SqueezeCount);

        transcript.SqueezeBytes(ChallengeLabel, output, Squeeze, Hash);
        Assert.AreEqual(2, transcript.SqueezeCount);

        //Absorb does not increment SqueezeCount.
        transcript.AbsorbBytes(ChallengeLabel, "absorbed"u8, Hash);
        Assert.AreEqual(2, transcript.SqueezeCount);
    }
}