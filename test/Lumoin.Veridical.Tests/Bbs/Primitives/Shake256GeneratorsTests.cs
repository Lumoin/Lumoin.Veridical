using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Bbs.IetfVectors;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Lumoin.Veridical.Tests.Bbs.Primitives;

/// <summary>
/// Byte-equality tests for the BLS12-381-SHAKE-256 generator
/// derivation: the ciphersuite-fixed <c>P_1</c> via
/// <c>BbsP1Generator.GetForCiphersuite</c> and the derived
/// <c>Q_1, H_1, ..., H_L</c> via <c>BbsAlgorithm.CreateGenerators</c>,
/// matched against the upstream <c>generators.json</c> fixture.
/// </summary>
[TestClass]
internal sealed class Shake256GeneratorsTests
{
    public static IEnumerable<object[]> VectorsData =>
        Shake256GeneratorsVectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(VectorsData))]
    public void Generators_Bls12Curve381Shake256(GeneratorsVector vector)
    {
        BbsCiphersuite ciphersuite = BbsCiphersuite.Bls12Curve381Shake256;
        byte[] expectedP1 = Convert.FromHexString(vector.P1);
        byte[] expectedQ1 = Convert.FromHexString(vector.Q1);
        byte[][] expectedH = vector.MessageGenerators.Select(Convert.FromHexString).ToArray();

        using G1Point p1 = BbsP1Generator.GetForCiphersuite(ciphersuite, TestSetup.Pool);
        Assert.IsTrue(p1.AsReadOnlySpan().SequenceEqual(expectedP1),
            $"P_1 mismatch for '{vector.Id}'.\n  expected: {vector.P1}\n  got:      {Convert.ToHexStringLower(p1.AsReadOnlySpan())}");

        int totalCount = 1 + expectedH.Length;
        ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(
            totalCount,
            ciphersuite.Identifier,
            TestSetup.Shake256.ExpandMessage,
            TestSetup.Shake256.G1HashToCurve,
            TestSetup.Pool);

        try
        {
            Assert.HasCount(totalCount, generators, $"create_generators length mismatch for '{vector.Id}'.");
            Assert.IsTrue(generators[0].AsReadOnlySpan().SequenceEqual(expectedQ1),
                $"Q_1 mismatch for '{vector.Id}'.\n  expected: {vector.Q1}\n  got:      {Convert.ToHexStringLower(generators[0].AsReadOnlySpan())}");
            for(int i = 0; i < expectedH.Length; i++)
            {
                Assert.IsTrue(generators[1 + i].AsReadOnlySpan().SequenceEqual(expectedH[i]),
                    $"H_{i + 1} mismatch for '{vector.Id}'.\n  expected: {vector.MessageGenerators[i]}\n  got:      {Convert.ToHexStringLower(generators[1 + i].AsReadOnlySpan())}");
            }
        }
        finally
        {
            foreach(G1Point generator in generators)
            {
                generator.Dispose();
            }
        }
    }
}