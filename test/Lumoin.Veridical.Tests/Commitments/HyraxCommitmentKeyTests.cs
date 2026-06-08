using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Tests for <see cref="HyraxCommitmentKey"/> derivation.
/// Key invariants:
/// </summary>
/// <list type="bullet">
///   <item><description>Same (seed, vectorLength) produces byte-identical keys.</description></item>
///   <item><description>Different seeds produce different keys.</description></item>
///   <item><description>Every derived generator is in the prime-order subgroup of G1.</description></item>
/// </list>
[TestClass]
internal sealed class HyraxCommitmentKeyTests
{
    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1IsInPrimeOrderSubgroupDelegate IsInSubgroup = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    private static readonly G1IsOnCurveDelegate IsOnCurve = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();


    [TestMethod]
    public void DeriveIsDeterministic()
    {
        using HyraxCommitmentKey first = HyraxCommitmentKey.Derive(8, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);
        using HyraxCommitmentKey second = HyraxCommitmentKey.Derive(8, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Two derivations with the same seed and vector length must produce byte-identical keys.");
    }


    [TestMethod]
    public void DifferentSeedsProduceDifferentKeys()
    {
        using HyraxCommitmentKey first = HyraxCommitmentKey.Derive(4, "veridical.test.protocolA.v1", CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);
        using HyraxCommitmentKey second = HyraxCommitmentKey.Derive(4, "veridical.test.protocolB.v1", CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        Assert.IsFalse(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Different seeds must produce different generator bytes.");
    }


    [TestMethod]
    public void GeneratorsAreInPrimeOrderSubgroup()
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(4, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        for(int i = 0; i < key.VectorLength; i++)
        {
            Assert.IsTrue(IsOnCurve(key.GetGenerator(i), CurveParameterSet.Bls12Curve381), $"Generator {i} should be on the curve.");
            Assert.IsTrue(IsInSubgroup(key.GetGenerator(i), CurveParameterSet.Bls12Curve381), $"Generator {i} should be in the prime-order subgroup.");
        }

        Assert.IsTrue(IsOnCurve(key.GetBlindingGenerator(), CurveParameterSet.Bls12Curve381), "Blinding generator H should be on the curve.");
        Assert.IsTrue(IsInSubgroup(key.GetBlindingGenerator(), CurveParameterSet.Bls12Curve381), "Blinding generator H should be in the prime-order subgroup.");

        Assert.IsTrue(IsOnCurve(key.GetValueGenerator(), CurveParameterSet.Bls12Curve381), "Value generator U should be on the curve.");
        Assert.IsTrue(IsInSubgroup(key.GetValueGenerator(), CurveParameterSet.Bls12Curve381), "Value generator U should be in the prime-order subgroup.");
    }


    [TestMethod]
    public void BlindingAndValueGeneratorsAreDistinct()
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(4, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        Assert.IsFalse(key.GetBlindingGenerator().SequenceEqual(key.GetValueGenerator()),
            "H and U must be distinct points to keep the IPA's binding generator independent of the Pedersen blinding generator.");
    }


    [TestMethod]
    public void VectorGeneratorsAreDistinct()
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(8, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        for(int i = 0; i < key.VectorLength; i++)
        {
            for(int j = i + 1; j < key.VectorLength; j++)
            {
                Assert.IsFalse(key.GetGenerator(i).SequenceEqual(key.GetGenerator(j)),
                    $"Generators {i} and {j} must be distinct (otherwise the commitment is not binding).");
            }
        }
    }
}