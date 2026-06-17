using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Domain-separation properties for <see cref="FiatShamirTranscript"/>:
/// different protocol identities or different operation labels produce
/// disjoint challenges.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptDomainSeparationTests
{
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();

    private const int SqueezeByteCount = 32;


    [TestMethod]
    public void DifferentDomainLabelsProduceDifferentChallenges()
    {
        FiatShamirDomainLabel domainA = new("veridical.protocol.a.v1");
        FiatShamirDomainLabel domainB = new("veridical.protocol.b.v1");
        ReadOnlySpan<byte> seed = stackalloc byte[16];
        FiatShamirOperationLabel label = new("test.challenge");

        using FiatShamirTranscript a = FiatShamirTranscript.Initialise(domainA, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using FiatShamirTranscript b = FiatShamirTranscript.Initialise(domainB, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> oA = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        using IMemoryOwner<byte> oB = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        Span<byte> outA = oA.Memory.Span[..SqueezeByteCount];
        Span<byte> outB = oB.Memory.Span[..SqueezeByteCount];

        a.SqueezeBytes(label, outA, Squeeze, Hash);
        b.SqueezeBytes(label, outB, Squeeze, Hash);

        Assert.IsFalse(outA.SequenceEqual(outB), "Distinct domain labels must produce distinct challenges from identical seeds + absorbs.");
    }


    [TestMethod]
    public void DifferentOperationLabelsProduceDifferentStatesPostAbsorb()
    {
        FiatShamirDomainLabel domain = new("veridical.test.labels.v1");
        ReadOnlySpan<byte> seed = stackalloc byte[16];
        ReadOnlySpan<byte> data = "shared-bytes"u8;

        using FiatShamirTranscript a = FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using FiatShamirTranscript b = FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        a.AbsorbBytes(new FiatShamirOperationLabel("label.alpha"), data, Hash);
        b.AbsorbBytes(new FiatShamirOperationLabel("label.beta"), data, Hash);

        ReadOnlySpan<byte> stateA = a.AsReadOnlySpan();
        ReadOnlySpan<byte> stateB = b.AsReadOnlySpan();

        Assert.IsFalse(stateA.SequenceEqual(stateB), "Same bytes absorbed under different labels must produce different states.");
    }


    [TestMethod]
    public void EmptyAbsorbWithDifferentLabelsStillProducesDifferentStates()
    {
        //Subtle property: even an absorb of zero data bytes must be
        //distinguishable across labels. Without label-in-hash, a zero-data
        //absorb would be a no-op; with label-in-hash, the label alone
        //changes the state.
        FiatShamirDomainLabel domain = new("veridical.test.emptyabsorb.v1");
        ReadOnlySpan<byte> seed = stackalloc byte[8];

        using FiatShamirTranscript a = FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using FiatShamirTranscript b = FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        a.AbsorbBytes(new FiatShamirOperationLabel("phase.one"), ReadOnlySpan<byte>.Empty, Hash);
        b.AbsorbBytes(new FiatShamirOperationLabel("phase.two"), ReadOnlySpan<byte>.Empty, Hash);

        Assert.IsFalse(a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan()),
            "Empty absorbs with different labels must produce different post-absorb states.");
    }


    [TestMethod]
    public void DifferentSqueezeLabelsProduceDifferentChallenges()
    {
        FiatShamirDomainLabel domain = new("veridical.test.squeezelabels.v1");
        ReadOnlySpan<byte> seed = stackalloc byte[16];

        using FiatShamirTranscript a = FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using FiatShamirTranscript b = FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> oA = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        using IMemoryOwner<byte> oB = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        Span<byte> outA = oA.Memory.Span[..SqueezeByteCount];
        Span<byte> outB = oB.Memory.Span[..SqueezeByteCount];

        a.SqueezeBytes(new FiatShamirOperationLabel("squeeze.x"), outA, Squeeze, Hash);
        b.SqueezeBytes(new FiatShamirOperationLabel("squeeze.y"), outB, Squeeze, Hash);

        Assert.IsFalse(outA.SequenceEqual(outB), "Different squeeze labels must produce different challenges.");
    }
}