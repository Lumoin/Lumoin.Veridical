using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Bbs.IetfVectors;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Sha256;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Lumoin.Veridical.Tests.Bbs.Primitives;

/// <summary>
/// Byte-equality tests for the BLS12-381-SHA-256 hash-to-scalar
/// primitive against the upstream <c>h2s.json</c> fixture.
/// </summary>
[TestClass]
internal sealed class Sha256HashToScalarTests
{
    public static IEnumerable<object[]> VectorsData =>
        Sha256HashToScalarVectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(VectorsData))]
    public void HashToScalar_Bls12Curve381Sha256(HashToScalarVector vector)
    {
        byte[] message = Convert.FromHexString(vector.Message);
        byte[] dst = Convert.FromHexString(vector.Dst);
        byte[] expected = Convert.FromHexString(vector.ExpectedScalar);

        using Scalar scalar = Scalar.FromHashToScalar(
            message,
            dst,
            TestSetup.Sha256.HashToScalar, CurveParameterSet.Bls12Curve381, TestSetup.Pool);

        Assert.IsTrue(scalar.AsReadOnlySpan().SequenceEqual(expected),
            $"hash_to_scalar mismatch for '{vector.Id}'.\n  expected: {vector.ExpectedScalar}\n  got:      {Convert.ToHexStringLower(scalar.AsReadOnlySpan())}");
    }
}