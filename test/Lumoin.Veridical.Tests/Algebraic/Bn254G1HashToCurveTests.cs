using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for BN254 (alt_bn128) G1 hash-to-curve
/// (<see cref="Bn254BigIntegerG1Reference.GetHashToCurve"/>), the RFC 9380
/// random-oracle construction with <c>expand_message_xmd</c> over SHA-256 and
/// the Shallue–van de Woestijne map.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9380 (final) does not register a BN254 suite, so there are no
/// primary-source BN254 hash-to-curve vectors. Per the batch's test-vector
/// policy the byte-faithful vectors here were produced by an independent
/// CPython implementation of the same pipeline — <c>expand_message_xmd</c>
/// (§5.3.1), <c>hash_to_field</c> with <c>L = 48</c> (§5.2), the SvdW map
/// (§6.6.1) with <c>Z = 1</c>, point addition, and the gnark compressed
/// encoding — which shares no code with this library's
/// <see cref="System.Numerics.BigInteger"/> backend. The two agreeing
/// byte-for-byte cross-validates both the map and this library's
/// <c>expand_message_xmd</c>.
/// </para>
/// <para>
/// The structural post-conditions (on-curve, in-subgroup, determinism) are
/// strong evidence on their own for BN254: the cofactor is 1, so a correct
/// SvdW output plus point addition lands in the prime-order subgroup with no
/// cofactor-clearing step that could mask an error.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bn254G1HashToCurveTests
{
    private static readonly G1HashToCurveDelegate HashToCurveDelegate =
        Bn254BigIntegerG1Reference.GetHashToCurve();

    private static readonly G1IsOnCurveDelegate IsOnCurveDelegate =
        Bn254BigIntegerG1Reference.GetIsOnCurve();

    private static readonly G1IsInPrimeOrderSubgroupDelegate IsInPrimeOrderSubgroupDelegate =
        Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();


    private static SensitiveMemoryPool<byte> Pool { get; } = SensitiveMemoryPool<byte>.Shared;


    private static ReadOnlySpan<byte> Dst => "VERIDICAL-BN254G1-SVDW-SHA256-V1"u8;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void HashToCurveMatchesIndependentVectors()
    {
        //(message, expected gnark-compressed output) pairs from the independent
        //CPython SvdW pipeline. The empty message is included deliberately —
        //expand_message_xmd has a distinct b_0 path for it.
        AssertHashToCurve([], "92278a29e1d5a075c60a41cdfe472e587ceded358a750f3b0a3019893ed75aac");
        AssertHashToCurve("abc"u8, "c15ba21089f2040e52eb622cc20e2c0e76e8125d7dd188b6053348c210fbbbd2");
        AssertHashToCurve("alpha"u8, "d68aebfa394bcd36d32cc15389c0474b483cb5e5189e23b00a33a5ccab97fe59");
        AssertHashToCurve([0x01, 0x02, 0x03], "e4f425eaa4a514f7c371a07d059a6fef53a85c830a0d23c50b78a06bd2cb343c");
    }


    private static void AssertHashToCurve(ReadOnlySpan<byte> message, string expectedHex)
    {
        using G1Point point = G1Point.FromHashToCurve(message, Dst, HashToCurveDelegate, CurveParameterSet.Bn254, Pool);
        Assert.AreEqual(expectedHex, Convert.ToHexStringLower(point.AsReadOnlySpan()));
    }


    [TestMethod]
    public void HashToCurveResultIsOnCurve()
    {
        using G1Point point = G1Point.FromHashToCurve("on-curve"u8, Dst, HashToCurveDelegate, CurveParameterSet.Bn254, Pool);
        Assert.IsTrue(point.IsOnCurve(IsOnCurveDelegate));
    }


    [TestMethod]
    public void HashToCurveResultIsInPrimeOrderSubgroup()
    {
        //Cofactor 1: a correct SvdW output is in the subgroup with no clearing.
        using G1Point point = G1Point.FromHashToCurve("subgroup"u8, Dst, HashToCurveDelegate, CurveParameterSet.Bn254, Pool);
        Assert.IsTrue(point.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroupDelegate));
    }


    [TestMethod]
    public void HashToCurveIsDeterministic()
    {
        using G1Point first = G1Point.FromHashToCurve("delta"u8, Dst, HashToCurveDelegate, CurveParameterSet.Bn254, Pool);
        using G1Point second = G1Point.FromHashToCurve("delta"u8, Dst, HashToCurveDelegate, CurveParameterSet.Bn254, Pool);

        Assert.IsTrue(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()));
    }


    [TestMethod]
    public void HashToCurveProducesPointsCarryingProvenance()
    {
        ReadOnlySpan<byte> message = [0x0a, 0x0b, 0x0c];
        using G1Point point = G1Point.FromHashToCurve(message, Dst, HashToCurveDelegate, CurveParameterSet.Bn254, Pool);

        Assert.IsTrue(point.Tag.TryGet(out ProviderClass providerClass),
            "Provenance entries should be present after a boundary operation.");
        Assert.AreEqual(nameof(Bn254BigIntegerG1Reference), providerClass.Name);

        Assert.AreEqual(AlgebraicRole.G1Point, point.Tag.Get<AlgebraicRole>());
        Assert.AreEqual(CurveParameterSet.Bn254, point.Tag.Get<CurveParameterSet>());
    }
}
