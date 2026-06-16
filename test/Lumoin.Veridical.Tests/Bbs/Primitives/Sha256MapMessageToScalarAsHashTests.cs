using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Bbs.IetfVectors;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Sha256;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Lumoin.Veridical.Tests.Bbs.Primitives;

/// <summary>
/// Byte-equality tests for the BLS12-381-SHA-256
/// <c>messages_to_scalars</c> BBS+ wrapper against the upstream
/// <c>MapMessageToScalarAsHash.json</c> fixture.
/// </summary>
[TestClass]
internal sealed class Sha256MapMessageToScalarAsHashTests
{
    public static IEnumerable<object[]> VectorsData =>
        Sha256MapMessageToScalarAsHashVectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(VectorsData))]
    public void MessagesToScalars_Bls12Curve381Sha256(MapMessageToScalarAsHashVector vector)
    {
        BbsMessage[] messages = vector.Cases
            .Select(c => new BbsMessage(c.Message.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(c.Message)))
            .ToArray();
        byte[][] expected = vector.Cases
            .Select(c => Convert.FromHexString(c.ExpectedScalar))
            .ToArray();

        ImmutableArray<Scalar> scalars = BbsAlgorithm.MessagesToScalars(
            messages,
            BbsCiphersuite.Bls12Curve381Sha256.Identifier,
            TestSetup.Sha256.HashToScalar,
            TestSetup.Pool);

        try
        {
            Assert.HasCount(expected.Length, scalars, $"messages_to_scalars output count mismatch for '{vector.Id}'.");
            for(int i = 0; i < expected.Length; i++)
            {
                Assert.IsTrue(scalars[i].AsReadOnlySpan().SequenceEqual(expected[i]),
                    $"messages_to_scalars scalar #{i + 1} mismatch for '{vector.Id}'.\n  expected: {vector.Cases[i].ExpectedScalar}\n  got:      {Convert.ToHexStringLower(scalars[i].AsReadOnlySpan())}");
            }
        }
        finally
        {
            foreach(Scalar scalar in scalars)
            {
                scalar.Dispose();
            }
        }
    }
}