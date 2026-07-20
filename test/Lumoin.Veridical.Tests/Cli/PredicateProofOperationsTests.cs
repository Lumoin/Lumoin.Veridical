using Lumoin.Base;
using Lumoin.Veridical.Cli;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Json;
using System;
using System.Globalization;

namespace Lumoin.Veridical.Tests.Cli;

/// <summary>
/// End-to-end gate for the <c>prove</c> and <c>verify</c> edge verbs, exercised the
/// way a library user (or the CLI/MCP surfaces) drives them: build a request, take it
/// through the <see cref="VeridicalPredicateProofJson"/> serializer, prove, then
/// verify the resulting artifact — with no witness on the verify side. It confirms
/// the happy path, that a false statement is unprovable, and that tampering with the
/// proof, the revealed public inputs' bound, a baked constant, or the commitment
/// parameters is caught.
/// </summary>
[TestClass]
internal sealed class PredicateProofOperationsTests
{
    private const string TranscriptDomain = "veridical.supplychain.batterypassport.test.v1";

    //A compliant constant-bound artifact, proven once and shared by the tests that
    //tamper with an otherwise-valid artifact. Lazy is thread-safe by default.
    private static readonly Lazy<string> CompliantArtifactJson = new(
        () => Prove(CompliantConstantRequest()));


    [TestMethod]
    public void CompliantBundleProvesAndVerifies()
    {
        VerificationResult result = Verify(CompliantArtifactJson.Value);

        Assert.AreEqual(VerificationStatus.Valid, result.Status, result.Message);
        Assert.IsTrue(result.Message.Contains("recycled_content >= 30.0 (constant)", StringComparison.Ordinal), result.Message);
        Assert.IsTrue(result.Message.Contains("carbon_footprint <= 12.50 (constant)", StringComparison.Ordinal), result.Message);
    }


    [TestMethod]
    public void SubThresholdRecycledContentIsNotProvable()
    {
        PredicateProofRequest request = Request(recycled: 28.0m, carbon: 11.20m, recycledBound: "constant");

        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => Prove(request));
    }


    [TestMethod]
    public void OverCapCarbonFootprintIsNotProvable()
    {
        PredicateProofRequest request = Request(recycled: 32.5m, carbon: 13.75m, recycledBound: "constant");

        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => Prove(request));
    }


    [TestMethod]
    public void TamperedProofIsRejected()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        byte[] proof = Convert.FromBase64String(artifact.Proof);
        proof[^1] ^= 0x01;
        string tampered = VeridicalPredicateProofJson.Serialize(artifact with { Proof = Convert.ToBase64String(proof) });

        Assert.AreEqual(VerificationStatus.Rejected, Verify(tampered).Status);
    }


    [TestMethod]
    public void TamperedConstantThresholdIsRejected()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        PredicateProofClaim[] claims = [.. artifact.Claims];
        claims[0] = claims[0] with { Value = "25.0" };
        string altered = VeridicalPredicateProofJson.Serialize(artifact with { Claims = claims });

        //The constant threshold is baked into the circuit matrices, so lowering it in
        //the descriptor rebuilds a different circuit and the proof no longer verifies.
        Assert.AreEqual(VerificationStatus.Rejected, Verify(altered).Status);
    }


    [TestMethod]
    public void TruncatedProofIsMalformed()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string truncated = VeridicalPredicateProofJson.Serialize(artifact with { Proof = artifact.Proof[..100] });

        Assert.AreEqual(VerificationStatus.Malformed, Verify(truncated).Status);
    }


    [TestMethod]
    public void DowngradedQueryCountIsMalformed()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string downgraded = VeridicalPredicateProofJson.Serialize(artifact with { QueryCount = 8 });

        VerificationResult result = Verify(downgraded);
        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("query count", StringComparison.Ordinal), result.Message);
    }


    [TestMethod]
    public void MalformedJsonIsMalformed()
    {
        Assert.AreEqual(VerificationStatus.Malformed, PredicateProofOperations.VerifyFromJson("{ not json", BaseMemoryPool.Shared).Status);
    }


    [TestMethod]
    public void NullClaimsArtifactIsMalformed()
    {
        const string json = """
        { "format": "veridical-supply-chain-predicate-proof/1", "curve": "bls12-381", "transcriptDomain": "d", "queryCount": 32, "digestBytes": 32, "claims": null, "publicInputs": "", "proof": "" }
        """;

        Assert.AreEqual(VerificationStatus.Malformed, PredicateProofOperations.VerifyFromJson(json, BaseMemoryPool.Shared).Status);
    }


    [TestMethod]
    public void NullClaimElementArtifactIsMalformed()
    {
        const string json = """
        { "format": "veridical-supply-chain-predicate-proof/1", "curve": "bls12-381", "transcriptDomain": "d", "queryCount": 32, "digestBytes": 32, "claims": [ null ], "publicInputs": "", "proof": "" }
        """;

        Assert.AreEqual(VerificationStatus.Malformed, PredicateProofOperations.VerifyFromJson(json, BaseMemoryPool.Shared).Status);
    }


    [TestMethod]
    public void PublicInputBoundIsDeterministicAndVerifies()
    {
        PredicateProofRequest request = Request(recycled: 32.5m, carbon: 11.20m, recycledBound: "public");

        PredicateProofArtifact first = VeridicalPredicateProofJson.DeserializeArtifact(Prove(request));
        PredicateProofArtifact second = VeridicalPredicateProofJson.DeserializeArtifact(Prove(request));

        Assert.AreNotEqual(string.Empty, first.PublicInputs, "A public-input bound reveals the encoded bound.");
        Assert.AreEqual(first.PublicInputs, second.PublicInputs, "The revealed public inputs are deterministic across proofs.");

        VerificationResult result = Verify(VeridicalPredicateProofJson.Serialize(first));
        Assert.AreEqual(VerificationStatus.Valid, result.Status, result.Message);
        Assert.IsTrue(result.Message.Contains("recycled_content >= 30.0 (public input)", StringComparison.Ordinal), result.Message);
    }


    private static string Prove(PredicateProofRequest request)
    {
        return PredicateProofOperations.ProveToJson(VeridicalPredicateProofJson.Serialize(request), BaseMemoryPool.Shared);
    }


    private static VerificationResult Verify(string artifactJson)
    {
        return PredicateProofOperations.VerifyFromJson(artifactJson, BaseMemoryPool.Shared);
    }


    private static PredicateProofRequest CompliantConstantRequest()
    {
        return Request(recycled: 32.5m, carbon: 11.20m, recycledBound: "constant");
    }


    private static PredicateProofRequest Request(decimal recycled, decimal carbon, string recycledBound)
    {
        return new PredicateProofRequest
        {
            Format = PredicateProofOperations.RequestFormat,
            Curve = PredicateProofOperations.CurveId,
            TranscriptDomain = TranscriptDomain,
            QueryCount = PredicateProofOperations.WiredQueryCount,
            DigestBytes = PredicateProofOperations.WiredDigestBytes,
            Claims =
            [
                new PredicateProofRequestClaim
                {
                    Name = "recycled_content",
                    Direction = "atLeast",
                    FractionalDigits = 1,
                    InclusiveMaximum = "100.0",
                    Bound = recycledBound,
                    BoundValue = "30.0",
                    Measured = recycled.ToString(CultureInfo.InvariantCulture),
                },
                new PredicateProofRequestClaim
                {
                    Name = "carbon_footprint",
                    Direction = "atMost",
                    FractionalDigits = 2,
                    InclusiveMaximum = "100.00",
                    Bound = "constant",
                    BoundValue = "12.50",
                    Measured = carbon.ToString(CultureInfo.InvariantCulture),
                },
            ],
        };
    }
}
