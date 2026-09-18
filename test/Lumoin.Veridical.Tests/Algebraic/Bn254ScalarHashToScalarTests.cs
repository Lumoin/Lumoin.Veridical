using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for BN254 hash-to-scalar
/// (<see cref="Bn254BigIntegerScalarReference.GetHashToScalar"/>): RFC 9380
/// <c>expand_message_xmd</c> with SHA-256 to <c>L = 48</c> uniform bytes,
/// reduced modulo the scalar-field order <c>r</c>.
/// </summary>
/// <remarks>
/// <para>
/// The hash enters through an injected <see cref="ExpandMessageDelegate"/>,
/// not a hardcoded call; the tests wire the SHA-256
/// <c>expand_message_xmd</c> the library provides (backed by the platform
/// <c>SHA256</c>). BN254 has no IETF BBS+ ciphersuite, so there are no
/// primary-source vectors; the known-answer vectors here were produced by an
/// independent CPython <c>expand_message_xmd</c> (the same one whose output was
/// already shown to match the library's in <see cref="Bn254G1HashToCurveTests"/>)
/// followed by a big-integer reduction modulo <c>r</c>, and locked as internal
/// regression vectors.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bn254ScalarHashToScalarTests
{
    /// <summary>The RFC 9380 <c>expand_message_xmd</c> delegate (SHA-256) this test injects into the hash-to-scalar delegate.</summary>
    private static ExpandMessageDelegate ExpandSha256 { get; } = Rfc9380ExpandMessage.ExpandMessageXmdSha256;
    /// <summary>The BN254 hash-to-scalar delegate under test, built from <see cref="ExpandSha256"/>.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bn254BigIntegerScalarReference.GetHashToScalar(ExpandSha256);

    /// <summary>The BN254 scalar-field order, used to check that every produced scalar is canonical.</summary>
    private static BigInteger Order { get; } = Bn254BigIntegerG1Reference.ScalarFieldOrder;

    /// <summary>The fixed message length the property sweep samples at; the hash-to-scalar properties under test (determinism, canonical range) are independent of message size.</summary>
    private const int PropertyMessageBytes = 32;

    /// <summary>The number of CsCheck-sampled messages the determinism/canonical property sweep checks.</summary>
    private const long PropertyIterationCount = 200;

    /// <summary>The number of deterministically indexed messages the coarse uniformity guard hashes.</summary>
    private const int UniformitySampleCount = 512;
    /// <summary>The minimum count of <see cref="UniformitySampleCount"/> scalars expected in the lower half of <c>[0, r)</c>: a loose 3σ binomial envelope (σ ≈ 11 for n = 512, so ±56 covers &gt;4σ) sized never to flake while still catching gross bias.</summary>
    private const int UniformityLowerBound = 200;
    /// <summary>The maximum count of <see cref="UniformitySampleCount"/> scalars expected in the lower half of <c>[0, r)</c>, mirroring <see cref="UniformityLowerBound"/>'s envelope.</summary>
    private const int UniformityUpperBound = 312;

    /// <summary>The memory pool this test's scalars are allocated from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The domain-separation tag this test's hash-to-scalar calls use.</summary>
    private static ReadOnlySpan<byte> Dst => "VERIDICAL-BN254-H2S-XMD-SHA256-V1"u8;


    /// <summary>The MSTest-supplied context for this test class.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Verifies that hashing four known messages to a BN254 scalar matches the independently computed known-answer vectors.</summary>
    [TestMethod]
    public void MatchesIndependentVectors()
    {
        //(message, scalar) known-answer vectors from the independent CPython path.
        AssertVector(""u8, "2beb9915b3043538773768e58ecbc327bb0e7bbb3207c013207f7c1e099fbd66");
        AssertVector("abc"u8, "243b6e7d4090b2402b51b3d5e979d2ad7caeabce3c0a2aade85fb458f6429eb5");
        AssertVector("sample message"u8, "0e9a49c4b7ef7549c57e1470736f0302b447dd8b171420c81f3cc85e23964960");
        AssertVector([0x00, 0xff, 0x10], "2e5ca47ebd33e6077e981c2c7b69daa1a24e2e44e4827a9e84a642a8172fd1c8");
    }


    /// <summary>Hashes a message to a scalar and asserts its canonical big-endian hex matches the expected known-answer value.</summary>
    private static void AssertVector(ReadOnlySpan<byte> message, string expectedScalarHex)
    {
        using Scalar scalar = Scalar.FromHashToScalar(message, Dst, HashToScalar, CurveParameterSet.Bn254, Pool);
        Assert.AreEqual(expectedScalarHex, Convert.ToHexStringLower(scalar.AsReadOnlySpan()));
    }


    /// <summary>Verifies, across sampled random messages, that hashing the same message and DST twice yields identical scalars, and that every produced scalar is strictly less than the scalar-field order.</summary>
    [TestMethod]
    public void OutputIsCanonicalAndDeterministic()
    {
        Gen.Byte.Array[PropertyMessageBytes].Sample(messageBytes =>
        {
            using Scalar first = Scalar.FromHashToScalar(messageBytes, Dst, HashToScalar, CurveParameterSet.Bn254, Pool);
            using Scalar second = Scalar.FromHashToScalar(messageBytes, Dst, HashToScalar, CurveParameterSet.Bn254, Pool);

            //Deterministic: same (message, DST) yields the same scalar.
            if(!first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()))
            {
                return false;
            }

            //Canonical: strictly less than the scalar-field order.
            BigInteger value = new(first.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
            return value < Order;
        }, iter: PropertyIterationCount);
    }


    /// <summary>Verifies, over a deterministic spread of messages, that roughly half the produced scalars fall in the lower half of <c>[0, r)</c>, as a coarse guard against gross bias.</summary>
    [TestMethod]
    public void OutputIsApproximatelyUniform()
    {
        //A coarse uniformity sanity check: over a deterministic spread of
        //messages, roughly half the scalars should fall in the lower half of
        //[0, r). A gross bias (a stuck reduction, a truncated expand, a
        //constant high byte) would push the count well outside the band. This
        //is not a rigorous statistical test — just a guard against obvious
        //non-uniformity, sized loosely enough never to flake.
        BigInteger half = Order >> 1;
        int lowerHalf = 0;

        Span<byte> message = stackalloc byte[sizeof(int)];
        for(int i = 0; i < UniformitySampleCount; i++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(message, i);
            using Scalar scalar = Scalar.FromHashToScalar(message, Dst, HashToScalar, CurveParameterSet.Bn254, Pool);
            BigInteger value = new(scalar.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
            if(value < half)
            {
                lowerHalf++;
            }
        }

        Assert.IsGreaterThanOrEqualTo(UniformityLowerBound, lowerHalf, "Too few scalars in the lower half — suspect bias.");
        Assert.IsLessThanOrEqualTo(UniformityUpperBound, lowerHalf, "Too many scalars in the lower half — suspect bias.");
    }


    /// <summary>Verifies that a hash-to-scalar result carries provenance tags naming the producing reference, the scalar algebraic role, and the BN254 curve.</summary>
    [TestMethod]
    public void ProducesScalarsCarryingProvenance()
    {
        using Scalar scalar = Scalar.FromHashToScalar("provenance"u8, Dst, HashToScalar, CurveParameterSet.Bn254, Pool);

        Assert.IsTrue(scalar.Tag.TryGet(out ProviderClass providerClass),
            "Provenance entries should be present after a boundary operation.");
        Assert.AreEqual(nameof(Bn254BigIntegerScalarReference), providerClass.Name);
        Assert.AreEqual(AlgebraicRole.Scalar, scalar.Tag.Get<AlgebraicRole>());
        Assert.AreEqual(CurveParameterSet.Bn254, scalar.Tag.Get<CurveParameterSet>());
    }
}
