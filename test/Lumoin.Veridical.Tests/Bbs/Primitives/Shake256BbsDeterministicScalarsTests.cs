using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Tests.Bbs.IetfVectors;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Lumoin.Veridical.Tests.Bbs.Primitives;

/// <summary>
/// Byte-equality tests for the IETF
/// <c>mocked_calculate_random_scalars</c> deterministic scalar source for
/// the BLS12-381-SHAKE-256 ciphersuite, matched against the upstream
/// <c>mockedRng.json</c> fixture.
/// </summary>
[TestClass]
internal sealed class Shake256BbsDeterministicScalarsTests
{
    public static IEnumerable<object[]> VectorsData =>
        Shake256BbsDeterministicScalarsVectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(VectorsData))]
    public void BbsDeterministicScalars_Bls12Curve381Shake256(BbsDeterministicScalarsVector vector)
    {
        byte[] seed = Convert.FromHexString(vector.Seed);
        byte[][] expected = vector.ExpectedScalars.Select(Convert.FromHexString).ToArray();

        ScalarRandomDelegate deterministic = BbsDeterministicScalars.FromSeed(
            seed,
            BbsCiphersuite.Bls12Curve381Shake256,
            vector.Count,
            TestSetup.ScalarReduce);

        Assert.AreEqual(expected.Length, vector.Count, $"Vector self-consistency: count must equal ExpectedScalars.Count for '{vector.Id}'.");
        for(int i = 0; i < vector.Count; i++)
        {
            byte[] actual = new byte[Scalar.SizeBytes];
            deterministic(actual, CurveParameterSet.Bls12Curve381, Tag.Empty);
            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected[i]),
                $"deterministic scalar #{i + 1} mismatch for '{vector.Id}'.\n  expected: {vector.ExpectedScalars[i]}\n  got:      {Convert.ToHexStringLower(actual)}");
        }
    }
}
