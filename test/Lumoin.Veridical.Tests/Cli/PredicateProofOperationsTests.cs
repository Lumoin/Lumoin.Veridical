using Lumoin.Base;
using Lumoin.Veridical.Cli;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
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
/// the happy path for range, memberOf and mixed bundles, that a false statement is
/// unprovable, and that tampering with a proof, the revealed public inputs' bound, a
/// baked constant, an allowed-value list, or the commitment parameters is caught.
/// </summary>
[TestClass]
internal sealed class PredicateProofOperationsTests
{
    /// <summary>The Fiat-Shamir domain label shared by every request and artifact in the suite.</summary>
    private const string TranscriptDomain = "veridical.supplychain.batterypassport.test.v1";

    /// <summary>The wired 128-bit-classical target the lookup ledger pin checks against.</summary>
    private const double ClassicalTargetBits = 128.0;

    /// <summary>
    /// The pinned lookup opened-column count: <c>⌈(128 + log2 3) / 2⌉</c> at
    /// rate 1/16 under the Johnson regime — the union bound over the
    /// argument's three openings adds one column over the Spartan path's 64.
    /// </summary>
    private const int ExpectedLookupQueryCount = 65;

    /// <summary>
    /// A compliant artifact over two range claims and one <c>memberOf</c>
    /// claim, proven once and shared by the tests that tamper with an
    /// otherwise-valid artifact. <see cref="Lazy{T}"/> is thread-safe by
    /// default.
    /// </summary>
    private static Lazy<string> CompliantArtifactJson { get; } = new(
        () => Prove(CompliantConstantRequest()));


    [TestMethod]
    public void CompliantBundleProvesAndVerifies()
    {
        VerificationResult result = Verify(CompliantArtifactJson.Value);

        Assert.AreEqual(VerificationStatus.Valid, result.Status, result.Message);
        Assert.IsTrue(result.Message.Contains("recycled_content >= 30.0 (constant)", StringComparison.Ordinal), result.Message);
        Assert.IsTrue(result.Message.Contains("carbon_footprint <= 12.50 (constant)", StringComparison.Ordinal), result.Message);
        Assert.IsTrue(result.Message.Contains("material_code in {3, 7, 42, 1001} (4 allowed value(s))", StringComparison.Ordinal), result.Message);
    }


    [TestMethod]
    public void LookupOnlyBundleProvesAndVerifies()
    {
        PredicateProofRequest request = LookupOnlyRequest(measured: "7");

        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(Prove(request));

        Assert.AreEqual(string.Empty, artifact.Proof, "A bundle without range claims carries no Spartan proof.");
        Assert.AreEqual(string.Empty, artifact.PublicInputs, "A bundle without range claims reveals no public inputs.");
        Assert.HasCount(1, artifact.LookupProofs);

        VerificationResult result = Verify(VeridicalPredicateProofJson.Serialize(artifact));
        Assert.AreEqual(VerificationStatus.Valid, result.Status, result.Message);
        Assert.IsTrue(result.Message.Contains("material_code in {3, 7, 42, 1001}", StringComparison.Ordinal), result.Message);
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
    public void NonMemberMeasuredValueIsNotProvable()
    {
        //8 is absent from the allowed list, so the multiplicity count fails
        //before any commitment work — the lookup unprovability fast path.
        PredicateProofRequest request = LookupOnlyRequest(measured: "8");

        Assert.ThrowsExactly<ArgumentException>(() => Prove(request));
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
    public void TamperedLookupProofIsRejected()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        byte[] lookupProof = Convert.FromBase64String(artifact.LookupProofs[0]);
        lookupProof[^1] ^= 0x01;
        string tampered = VeridicalPredicateProofJson.Serialize(artifact with { LookupProofs = [Convert.ToBase64String(lookupProof)] });

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
    public void TamperedAllowedValuesAreRejected()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        PredicateProofClaim[] claims = [.. artifact.Claims];
        claims[2] = claims[2] with { AllowedValues = ["3", "7", "43", "1001"] };
        string altered = VeridicalPredicateProofJson.Serialize(artifact with { Claims = claims });

        //The allowed values determine the lookup table the transcript absorbed,
        //so substituting a member rebuilds a different table and the lookup
        //proof no longer verifies.
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
    public void TruncatedLookupProofIsMalformed()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string truncated = VeridicalPredicateProofJson.Serialize(artifact with { LookupProofs = [artifact.LookupProofs[0][..100]] });

        Assert.AreEqual(VerificationStatus.Malformed, Verify(truncated).Status);
    }


    [TestMethod]
    public void LookupProofCountMismatchIsMalformed()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string missing = VeridicalPredicateProofJson.Serialize(artifact with { LookupProofs = [] });

        VerificationResult result = Verify(missing);
        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("lookup proof", StringComparison.Ordinal), result.Message);
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
    public void DowngradedLookupQueryCountIsMalformed()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string downgraded = VeridicalPredicateProofJson.Serialize(artifact with { LookupQueryCount = PredicateProofOperations.WiredQueryCount });

        //The Spartan query count of 64 falls short of the lookup path's
        //union-bounded target, so the header pin rejects it outright.
        VerificationResult result = Verify(downgraded);
        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("lookup query count", StringComparison.Ordinal), result.Message);
    }


    [TestMethod]
    public void DowngradedInverseRateIsMalformed()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string downgraded = VeridicalPredicateProofJson.Serialize(artifact with { InverseRate = 4 });

        VerificationResult result = Verify(downgraded);
        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("inverse rate", StringComparison.Ordinal), result.Message);
    }


    [TestMethod]
    public void PriorFormatVersionIsMalformed()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string downgraded = VeridicalPredicateProofJson.Serialize(artifact with { Format = "veridical-supply-chain-predicate-proof/2" });

        //Version 3 introduced the kind discriminator; a version-2 stamp is
        //rejected loudly instead of being reinterpreted.
        VerificationResult result = Verify(downgraded);
        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("format", StringComparison.OrdinalIgnoreCase), result.Message);
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
        { "format": "veridical-supply-chain-predicate-proof/3", "curve": "bls12-381", "transcriptDomain": "d", "queryCount": 64, "lookupQueryCount": 65, "inverseRate": 16, "digestBytes": 32, "claims": null, "publicInputs": "", "proof": "", "lookupProofs": [] }
        """;

        Assert.AreEqual(VerificationStatus.Malformed, PredicateProofOperations.VerifyFromJson(json, BaseMemoryPool.Shared).Status);
    }


    [TestMethod]
    public void NullClaimElementArtifactIsMalformed()
    {
        const string json = """
        { "format": "veridical-supply-chain-predicate-proof/3", "curve": "bls12-381", "transcriptDomain": "d", "queryCount": 64, "lookupQueryCount": 65, "inverseRate": 16, "digestBytes": 32, "claims": [ null ], "publicInputs": "", "proof": "", "lookupProofs": [] }
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


    [TestMethod]
    public void WiredLookupQueryCountIsDerivedAtSixtyFive()
    {
        //The lookup path opens three independently forgeable columns, so its
        //proximity target is 128 + log2(3) bits: 65 columns at 2 bits each,
        //one more than the Spartan path's 64.
        Assert.AreEqual(ExpectedLookupQueryCount, PredicateProofOperations.LookupQueryCount);
        Assert.AreEqual(PredicateProofOperations.WiredQueryCount + 1, PredicateProofOperations.LookupQueryCount);
    }


    [TestMethod]
    public void LookupLedgerMeetsClassicalTargetAcrossWiredTableSizes()
    {
        for(int variableCount = PredicateProofOperations.MinimumLookupTableVariableCount;
            variableCount <= PredicateProofOperations.MaximumLookupTableVariableCount;
            variableCount++)
        {
            SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeLogUpOverLigero(
                CurveParameterSet.Bls12Curve381,
                variableCount,
                PredicateProofOperations.LookupWitnessColumnCount,
                PredicateProofOperations.WiredInverseRate,
                PredicateProofOperations.LookupQueryCount);

            Assert.IsGreaterThanOrEqualTo(ClassicalTargetBits, ledger.EffectiveBits, $"The lookup ledger must meet the classical target at {variableCount} table variables.");
        }
    }


    [TestMethod]
    public void SpartanQueryCountFallsShortOfLookupTarget()
    {
        //The union bound over the three openings prices the Spartan count at
        //128 − log2(3) ≈ 126.42 realised bits — the reason the lookup path
        //carries its own derived query count.
        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeLogUpOverLigero(
            CurveParameterSet.Bls12Curve381,
            PredicateProofOperations.MinimumLookupTableVariableCount,
            PredicateProofOperations.LookupWitnessColumnCount,
            PredicateProofOperations.WiredInverseRate,
            PredicateProofOperations.WiredQueryCount);

        Assert.IsLessThan(ClassicalTargetBits, ledger.EffectiveBits);
        Assert.AreEqual(ClassicalTargetBits - Math.Log2(3.0), ledger.EffectiveBits, 1e-9, "The realised bits pin the union-bounded shortfall exactly.");
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


    private static PredicateProofRequestClaim MaterialCodeClaim(string measured)
    {
        return new PredicateProofRequestClaim
        {
            Name = "material_code",
            Kind = "memberOf",
            FractionalDigits = 0,
            InclusiveMaximum = "9999",
            AllowedValues = ["3", "7", "42", "1001"],
            Measured = measured,
        };
    }


    private static PredicateProofRequest LookupOnlyRequest(string measured)
    {
        return new PredicateProofRequest
        {
            Format = PredicateProofOperations.RequestFormat,
            Curve = PredicateProofOperations.CurveId,
            TranscriptDomain = TranscriptDomain,
            QueryCount = PredicateProofOperations.WiredQueryCount,
            LookupQueryCount = PredicateProofOperations.LookupQueryCount,
            InverseRate = PredicateProofOperations.WiredInverseRate,
            DigestBytes = PredicateProofOperations.WiredDigestBytes,
            Claims = [MaterialCodeClaim(measured)],
        };
    }


    private static PredicateProofRequest Request(decimal recycled, decimal carbon, string recycledBound)
    {
        return new PredicateProofRequest
        {
            Format = PredicateProofOperations.RequestFormat,
            Curve = PredicateProofOperations.CurveId,
            TranscriptDomain = TranscriptDomain,
            QueryCount = PredicateProofOperations.WiredQueryCount,
            LookupQueryCount = PredicateProofOperations.LookupQueryCount,
            InverseRate = PredicateProofOperations.WiredInverseRate,
            DigestBytes = PredicateProofOperations.WiredDigestBytes,
            Claims =
            [
                new PredicateProofRequestClaim
                {
                    Name = "recycled_content",
                    Kind = "range",
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
                    Kind = "range",
                    Direction = "atMost",
                    FractionalDigits = 2,
                    InclusiveMaximum = "100.00",
                    Bound = "constant",
                    BoundValue = "12.50",
                    Measured = carbon.ToString(CultureInfo.InvariantCulture),
                },
                MaterialCodeClaim("7"),
            ],
        };
    }
}
