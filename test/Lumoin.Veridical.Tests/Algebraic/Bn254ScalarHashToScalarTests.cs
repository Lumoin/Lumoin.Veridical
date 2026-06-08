using CsCheck;
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
/// already shown to match the library's in the U.3b hash-to-curve vectors)
/// followed by a big-integer reduction modulo <c>r</c>, and locked as internal
/// regression vectors.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bn254ScalarHashToScalarTests
{
    private static readonly ExpandMessageDelegate ExpandSha256 = Rfc9380ExpandMessage.ExpandMessageXmdSha256;
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bn254BigIntegerScalarReference.GetHashToScalar(ExpandSha256);

    private static readonly BigInteger Order = Bn254BigIntegerG1Reference.ScalarFieldOrder;

    //Arbitrary fixed message length for the property sweep; the hash-to-scalar
    //properties (determinism, canonical range) are independent of message size.
    private const int PropertyMessageBytes = 32;

    //CsCheck iterations for the determinism/canonical property.
    private const long PropertyIterationCount = 200;

    //Coarse uniformity guard: count how many of this many scalars land in the
    //lower half of [0, r). Expected ~half; the band is a loose 3σ binomial
    //envelope (σ = sqrt(n·0.25) ≈ 11 for n = 512, so ±56 covers >4σ) sized
    //never to flake while still catching gross bias.
    private const int UniformitySampleCount = 512;
    private const int UniformityLowerBound = 200;
    private const int UniformityUpperBound = 312;

    private static SensitiveMemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static ReadOnlySpan<byte> Dst => "VERIDICAL-BN254-H2S-XMD-SHA256-V1"u8;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void MatchesIndependentVectors()
    {
        //(message, scalar) known-answer vectors from the independent CPython path.
        AssertVector(""u8, "2beb9915b3043538773768e58ecbc327bb0e7bbb3207c013207f7c1e099fbd66");
        AssertVector("abc"u8, "243b6e7d4090b2402b51b3d5e979d2ad7caeabce3c0a2aade85fb458f6429eb5");
        AssertVector("sample message"u8, "0e9a49c4b7ef7549c57e1470736f0302b447dd8b171420c81f3cc85e23964960");
        AssertVector([0x00, 0xff, 0x10], "2e5ca47ebd33e6077e981c2c7b69daa1a24e2e44e4827a9e84a642a8172fd1c8");
    }


    private static void AssertVector(ReadOnlySpan<byte> message, string expectedScalarHex)
    {
        using Scalar scalar = Scalar.FromHashToScalar(message, Dst, HashToScalar, CurveParameterSet.Bn254, Pool);
        Assert.AreEqual(expectedScalarHex, Convert.ToHexStringLower(scalar.AsReadOnlySpan()));
    }


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
