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
    /// <summary>
    /// Verifies that P-256's cached scalar and G1-point tags let every tagged broad-carrier boundary
    /// factory resolve for P-256: the G1 generator, a random scalar, and a canonical-bytes round trip.
    /// </summary>
    [TestMethod]
    public void P256ScalarAndG1TagsAreCachedSoBroadCarriersConstruct()
    {
        using BaseMemoryPool pool = new();

        //P-256's scalar and G1-point tags are cached so every tagged carrier mint resolves for it;
        //each of the three boundary factories below routes through the cache and must succeed for P-256.
        using G1Point generator = G1Point.Generator(CurveParameterSet.P256, pool);
        Assert.AreEqual(CurveParameterSet.P256, generator.Curve);

        using Scalar random = Scalar.FromRandom(P256BigIntegerScalarReference.GetRandom(), CurveParameterSet.P256, pool);
        Assert.AreEqual(CurveParameterSet.P256, random.Curve);

        using G1Point roundTrip = G1Point.FromCanonical(generator.AsReadOnlySpan(), CurveParameterSet.P256, pool);
        Assert.AreEqual(CurveParameterSet.P256, roundTrip.Curve);
    }


    /// <summary>Verifies that P-256, not being pairing-friendly, has no cached G2-point or extension-field-element tag and throws for both lookups.</summary>
    [TestMethod]
    public void P256HasNoG2OrExtensionFieldTags()
    {
        //P-256 is not pairing-friendly: it has no G2 group nor field-tower extension. Those lookups
        //must stay deliberately unwired and throw, rather than silently returning a mismatched tag.
        Assert.ThrowsExactly<ArgumentException>(() => WellKnownAlgebraicTags.G2PointFor(CurveParameterSet.P256));
        Assert.ThrowsExactly<ArgumentException>(() => WellKnownAlgebraicTags.ExtensionFieldElementFor(CurveParameterSet.P256));
    }
}
