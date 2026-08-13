using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Tests the scheme-agnostic polynomial-commitment surface: the broad leaf
/// types carry the curve and scheme identity on their tag, and the provider
/// bundle holds a scheme's operations. This class guards only the surface's
/// own shape; per-scheme adapters, such as the Hyrax provider, wire real
/// consumers against it and are validated separately.
/// </summary>
[TestClass]
internal sealed class PolynomialCommitmentSurfaceTests
{
    private const int SampleByteLength = 48;


    [TestMethod]
    public void CommitmentCarriesCurveAndScheme()
    {
        Span<byte> bytes = stackalloc byte[SampleByteLength];
        bytes.Clear();

        using PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
            bytes, CurveParameterSet.Bls12Curve381, CommitmentScheme.Hyrax, BaseMemoryPool.Shared);

        Assert.AreEqual(CurveParameterSet.Bls12Curve381.Code, commitment.Curve.Code, "curve");
        Assert.AreEqual(CommitmentScheme.Hyrax, commitment.Scheme, "scheme");
        Assert.HasCount(SampleByteLength, commitment.AsReadOnlySpan(), "byte length preserved");
    }


    [TestMethod]
    public void OpeningCarriesCurveAndScheme()
    {
        Span<byte> bytes = stackalloc byte[SampleByteLength];
        bytes.Clear();

        using PolynomialOpening opening = PolynomialOpening.FromBytes(
            bytes, CurveParameterSet.Bn254, CommitmentScheme.Hyrax, BaseMemoryPool.Shared);

        Assert.AreEqual(CurveParameterSet.Bn254.Code, opening.Curve.Code, "curve");
        Assert.AreEqual(CommitmentScheme.Hyrax, opening.Scheme, "scheme");
    }


    [TestMethod]
    public void ProviderHoldsItsOperationsAndIdentity()
    {
        PolynomialCommitDelegate commit = (polynomial, pool) => throw new NotSupportedException();
        PolynomialOpenDelegate open = (commitment, blind, polynomial, point, transcript, pool) => throw new NotSupportedException();
        PolynomialVerifyEvaluationDelegate verify = (commitment, point, value, opening, transcript, pool) => throw new NotSupportedException();

        using var provider = new PolynomialCommitmentProvider(
            CommitmentScheme.Hyrax, CurveParameterSet.Bls12Curve381, commit, open, verify);

        Assert.AreEqual(CommitmentScheme.Hyrax, provider.Scheme, "scheme");
        Assert.AreEqual(CurveParameterSet.Bls12Curve381.Code, provider.Curve.Code, "curve");
        Assert.AreSame(commit, provider.Commit, "commit delegate held");
        Assert.AreSame(open, provider.Open, "open delegate held");
        Assert.AreSame(verify, provider.VerifyEvaluation, "verify delegate held");
    }


    [TestMethod]
    public void ProviderRejectsNullOperations()
    {
        PolynomialOpenDelegate open = (commitment, blind, polynomial, point, transcript, pool) => throw new NotSupportedException();
        PolynomialVerifyEvaluationDelegate verify = (commitment, point, value, opening, transcript, pool) => throw new NotSupportedException();

        Assert.ThrowsExactly<ArgumentNullException>(
            () => new PolynomialCommitmentProvider(CommitmentScheme.Hyrax, CurveParameterSet.Bls12Curve381, null!, open, verify));
    }
}
