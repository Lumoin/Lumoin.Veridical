using Lumoin.Base;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for <see cref="WellKnownAlgebraicTags"/>, the per-curve algebraic-identity tag cache the broad leaf
/// types consult at construction. P-256 is a first-class curve (its arithmetic backends are wired and the
/// <c>Lumoin.Veridical.Secdsa</c> package targets it), so its scalar and G1-point tags must be cached: without
/// them every broad-carrier boundary factory (<see cref="Scalar.FromRandom"/>, <see cref="G1Point.Generator"/>,
/// <see cref="G1Point.FromCanonical(System.ReadOnlySpan{byte}, CurveParameterSet, BaseMemoryPool, Tag?)"/> with a
/// null tag) throws for P-256. P-256 is not pairing-friendly, so it deliberately has no G2 or field-tower entry.
/// </summary>
[TestClass]
internal sealed class WellKnownAlgebraicTagsTests
{
    [TestMethod]
    public void P256ScalarAndG1TagsAreCachedSoBroadCarriersConstruct()
    {
        using BaseMemoryPool pool = new();

        //Regression: P-256 was wired as a first-class arithmetic curve, but its cached scalar and
        //G1-point tags were initially absent, so every tagged P-256 carrier mint threw. Each of the
        //three boundary factories below routes through the cache and must now resolve for P-256.
        using G1Point generator = G1Point.Generator(CurveParameterSet.P256, pool);
        Assert.AreEqual(CurveParameterSet.P256, generator.Curve);

        using Scalar random = Scalar.FromRandom(P256BigIntegerScalarReference.GetRandom(), CurveParameterSet.P256, pool);
        Assert.AreEqual(CurveParameterSet.P256, random.Curve);

        using G1Point roundTrip = G1Point.FromCanonical(generator.AsReadOnlySpan(), CurveParameterSet.P256, pool);
        Assert.AreEqual(CurveParameterSet.P256, roundTrip.Curve);
    }


    [TestMethod]
    public void P256HasNoG2OrExtensionFieldTags()
    {
        //P-256 is not pairing-friendly: it has no G2 group nor field-tower extension. Those lookups
        //must stay deliberately unwired and throw, rather than silently returning a mismatched tag.
        Assert.ThrowsExactly<ArgumentException>(() => WellKnownAlgebraicTags.G2PointFor(CurveParameterSet.P256));
        Assert.ThrowsExactly<ArgumentException>(() => WellKnownAlgebraicTags.ExtensionFieldElementFor(CurveParameterSet.P256));
    }
}
