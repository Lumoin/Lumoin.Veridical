using Lumoin.Base;
using Lumoin.Veridical.Cli;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Json;
using System;
using System.Collections.Generic;
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


    /// <summary>An unrecognised, garbage or empty <c>kind</c> string is rejected before any claim shape or proving work; the guard runs on the claim-parsing path both surfaces share.</summary>
    [TestMethod]
    public void UnrecognisedClaimKindsAreRejected()
    {
        string[] unrecognisedKinds = ["unrecognisedKind", "!!!garbage!!!", ""];
        foreach(string kind in unrecognisedKinds)
        {
            ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => Prove(RequestWithClaimKind(kind)), $"Kind '{kind}' must be rejected.");
            Assert.IsTrue(exception.Message.Contains("Unknown predicate kind", StringComparison.Ordinal), exception.Message);
        }
    }


    /// <summary>A <c>memberOf</c> claim carrying a range claim's comparison fields is rejected: the two kinds keep disjoint field sets so one cannot smuggle the other's parameters.</summary>
    [TestMethod]
    public void MemberOfClaimCarryingRangeFieldsIsRejected()
    {
        PredicateProofRequestClaim claim = RawClaim("material_code", "memberOf", direction: "atLeast", bound: "constant", boundValue: "3", allowedValues: ["3", "7"], measured: "3");

        Assert.ThrowsExactly<ArgumentException>(() => Prove(RequestWithSingleClaim(claim)));
    }


    /// <summary>A <c>range</c> claim carrying an <c>allowedValues</c> list is rejected: a range claim's field set has no room for it.</summary>
    [TestMethod]
    public void RangeClaimCarryingAllowedValuesIsRejected()
    {
        PredicateProofRequestClaim claim = RawClaim("recycled_content", "range", direction: "atLeast", bound: "constant", boundValue: "30.0", allowedValues: ["3", "7"], measured: "32.5");

        Assert.ThrowsExactly<ArgumentException>(() => Prove(RequestWithSingleClaim(claim)));
    }


    /// <summary>A <c>range</c> claim missing its <c>direction</c> and <c>bound</c> fields is rejected rather than defaulted.</summary>
    [TestMethod]
    public void RangeClaimMissingComparisonFieldsIsRejected()
    {
        PredicateProofRequestClaim claim = RawClaim("recycled_content", "range", direction: null, bound: null, boundValue: null, allowedValues: null, measured: "32.5");

        Assert.ThrowsExactly<ArgumentException>(() => Prove(RequestWithSingleClaim(claim)));
    }


    /// <summary>Two claims sharing a name are rejected on the prove side before any proving starts — claim names identify claims within a bundle.</summary>
    [TestMethod]
    public void ProveRejectsDuplicateClaimNames()
    {
        PredicateProofRequest request = CompliantConstantRequest();
        PredicateProofRequestClaim[] claims = [.. request.Claims];
        claims[1] = claims[1] with { Name = claims[0].Name };
        PredicateProofRequest duplicated = request with { Claims = claims };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => Prove(duplicated));
        Assert.IsTrue(exception.Message.Contains("more than once", StringComparison.Ordinal), exception.Message);
    }


    /// <summary>Two claims sharing a name are rejected on the verify side too — a distinct guard from the prove-side one, reached through artifact-claim parsing.</summary>
    [TestMethod]
    public void VerifyRejectsDuplicateClaimNames()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        PredicateProofClaim[] claims = [.. artifact.Claims];
        claims[1] = claims[1] with { Name = claims[0].Name };
        string duplicated = VeridicalPredicateProofJson.Serialize(artifact with { Claims = claims });

        VerificationResult result = Verify(duplicated);
        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("more than once", StringComparison.Ordinal), result.Message);
    }


    /// <summary>
    /// The allowed-value list is accepted at exactly the wired
    /// <see cref="PredicateProofOperations.MaximumAllowedValueCount"/> cap. The
    /// artifact is deliberately shipped with no lookup proof, so verification
    /// fails at the cheap proof-count check right after claim parsing succeeds
    /// — proving the cap guard passed without paying for a real 4096-entry
    /// lookup proof.
    /// </summary>
    [TestMethod]
    public void MaximumAllowedValueCountIsAccepted()
    {
        PredicateProofClaim claim = MemberOfArtifactClaim("material_code", SequentialAllowedValues(PredicateProofOperations.MaximumAllowedValueCount));
        PredicateProofArtifact artifact = LookupOnlyArtifact(claim, lookupProofs: []);

        VerificationResult result = PredicateProofOperations.Verify(artifact, BaseMemoryPool.Shared);

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("lookup proof", StringComparison.Ordinal), result.Message);
    }


    /// <summary>One allowed value past <see cref="PredicateProofOperations.MaximumAllowedValueCount"/> is rejected outright, on the prove side, before any proving work.</summary>
    [TestMethod]
    public void AboveMaximumAllowedValueCountIsRejected()
    {
        PredicateProofRequest request = LookupOnlyRequestWithAllowedValues(SequentialAllowedValues(PredicateProofOperations.MaximumAllowedValueCount + 1), measured: "0");

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => Prove(request));
        Assert.IsTrue(exception.Message.Contains("wired maximum", StringComparison.Ordinal), exception.Message);
    }


    /// <summary>An empty <c>allowedValues</c> list is rejected: a <c>memberOf</c> claim must name at least one member.</summary>
    [TestMethod]
    public void EmptyAllowedValuesListIsRejected()
    {
        PredicateProofRequest request = LookupOnlyRequestWithAllowedValues([], measured: "0");

        Assert.ThrowsExactly<ArgumentException>(() => Prove(request));
    }


    /// <summary>An allowed value carrying finer resolution than the claim's fixed-point scale fails domain encoding and is rejected.</summary>
    [TestMethod]
    public void AllowedValueFailingDomainEncodingIsRejected()
    {
        PredicateProofRequest request = LookupOnlyRequestWithAllowedValues(["3", "3.5"], measured: "3");

        Assert.ThrowsExactly<ArgumentException>(() => Prove(request));
    }


    /// <summary>
    /// Duplicate entries within one <c>allowedValues</c> list are accepted, not
    /// rejected: LogUp tables tolerate duplicate members by design, and the
    /// claim parser applies no distinctness check of its own. The artifact
    /// carries no lookup proof, so this is observed at the cheap proof-count
    /// check, without a real lookup proof.
    /// </summary>
    [TestMethod]
    public void DuplicateAllowedValuesAreAccepted()
    {
        PredicateProofClaim claim = MemberOfArtifactClaim("material_code", ["3", "3", "7"]);
        PredicateProofArtifact artifact = LookupOnlyArtifact(claim, lookupProofs: []);

        VerificationResult result = PredicateProofOperations.Verify(artifact, BaseMemoryPool.Shared);

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("lookup proof", StringComparison.Ordinal), result.Message);
    }


    /// <summary>A range-only bundle under format <c>/3</c> proves and verifies end to end, carrying no lookup proof — the zero-lookup code paths this bundle shape exercises.</summary>
    [TestMethod]
    public void RangeOnlyBundleProvesAndVerifies()
    {
        PredicateProofRequest request = Request(recycled: 32.5m, carbon: 11.20m, recycledBound: "constant", includeMemberOfClaim: false);

        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(Prove(request));

        Assert.AreNotEqual(string.Empty, artifact.Proof, "A range-only bundle carries a Spartan proof.");
        Assert.HasCount(0, artifact.LookupProofs);

        VerificationResult result = Verify(VeridicalPredicateProofJson.Serialize(artifact));
        Assert.AreEqual(VerificationStatus.Valid, result.Status, result.Message);
        Assert.IsTrue(result.Message.Contains("recycled_content >= 30.0 (constant)", StringComparison.Ordinal), result.Message);
        Assert.IsFalse(result.Message.Contains("material_code", StringComparison.Ordinal), result.Message);
    }


    /// <summary>Every format other than the wired <c>/3</c> version is rejected on the prove side too — not just at verify, where the header guard is already pinned.</summary>
    [TestMethod]
    public void ProveRejectsUnsupportedRequestFormats()
    {
        string[] unsupportedFormats =
        [
            "veridical-supply-chain-predicate-request/1",
            "veridical-supply-chain-predicate-request/2",
            "veridical-supply-chain-predicate-request/4",
            "not-a-format-string",
        ];

        foreach(string format in unsupportedFormats)
        {
            PredicateProofRequest request = CompliantConstantRequest() with { Format = format };

            Assert.ThrowsExactly<ArgumentException>(() => Prove(request), $"Format '{format}' must be rejected before proving starts.");
        }
    }


    /// <summary>
    /// Swapping two <c>memberOf</c> claims' names between prove and verify does
    /// not throw: each lookup proof was produced on a transcript that absorbed
    /// the original name first, so the swap only diverges the transcript, and
    /// verification comes back <see cref="VerificationStatus.Rejected"/> rather
    /// than raising an exception.
    /// </summary>
    [TestMethod]
    public void SwappedMemberOfClaimNamesAreRejectedNotThrown()
    {
        PredicateProofRequest request = TwoMemberOfClaimsRequest();
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(Prove(request));

        PredicateProofClaim[] claims = [.. artifact.Claims];
        string firstName = claims[0].Name;
        string secondName = claims[1].Name;
        claims[0] = claims[0] with { Name = secondName };
        claims[1] = claims[1] with { Name = firstName };
        string swapped = VeridicalPredicateProofJson.Serialize(artifact with { Claims = claims });

        Assert.AreEqual(VerificationStatus.Rejected, Verify(swapped).Status);
    }


    /// <summary>The <c>kind</c> discriminator matches case-insensitively: a mixed-case spelling reaches the same kind-specific shape guard as the canonical spelling, rather than the unknown-kind guard.</summary>
    [TestMethod]
    public void ClaimKindMatchingIsCaseInsensitive()
    {
        ArgumentException rangeException = Assert.ThrowsExactly<ArgumentException>(() => Prove(RequestWithClaimKind("RANGE")));
        Assert.IsTrue(rangeException.Message.Contains("direction", StringComparison.Ordinal), rangeException.Message);

        ArgumentException memberOfException = Assert.ThrowsExactly<ArgumentException>(() => Prove(RequestWithClaimKind("MEMBEROF")));
        Assert.IsTrue(memberOfException.Message.Contains("allowedValues", StringComparison.Ordinal), memberOfException.Message);
    }


    /// <summary>The artifact <c>format</c> identifier matches by ordinal comparison, not case-insensitively: a differently-cased spelling of the wired format is rejected.</summary>
    [TestMethod]
    public void FormatMatchingIsCaseSensitive()
    {
        PredicateProofArtifact artifact = VeridicalPredicateProofJson.DeserializeArtifact(CompliantArtifactJson.Value);
        string upperFormat = VeridicalPredicateProofJson.Serialize(artifact with { Format = artifact.Format.ToUpperInvariant() });

        VerificationResult result = Verify(upperFormat);

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsTrue(result.Message.Contains("format", StringComparison.OrdinalIgnoreCase), result.Message);
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


    /// <summary>
    /// Builds a range bundle over <c>recycled_content</c> and
    /// <c>carbon_footprint</c>, appending the <c>material_code</c>
    /// <c>memberOf</c> claim by default so existing callers keep exercising the
    /// mixed-kind bundle; <paramref name="includeMemberOfClaim"/> lets a caller
    /// opt into the range-only shape instead.
    /// </summary>
    private static PredicateProofRequest Request(decimal recycled, decimal carbon, string recycledBound, bool includeMemberOfClaim = true)
    {
        var claims = new List<PredicateProofRequestClaim>
        {
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
        };

        if(includeMemberOfClaim)
        {
            claims.Add(MaterialCodeClaim("7"));
        }

        return new PredicateProofRequest
        {
            Format = PredicateProofOperations.RequestFormat,
            Curve = PredicateProofOperations.CurveId,
            TranscriptDomain = TranscriptDomain,
            QueryCount = PredicateProofOperations.WiredQueryCount,
            LookupQueryCount = PredicateProofOperations.LookupQueryCount,
            InverseRate = PredicateProofOperations.WiredInverseRate,
            DigestBytes = PredicateProofOperations.WiredDigestBytes,
            Claims = claims,
        };
    }


    /// <summary>A single-claim request built from an already-shaped <see cref="PredicateProofRequestClaim"/>, for the claim-parsing guard pins that never reach proving.</summary>
    private static PredicateProofRequest RequestWithSingleClaim(PredicateProofRequestClaim claim)
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
            Claims = [claim],
        };
    }


    /// <summary>
    /// A claim carrying whichever mix of <c>kind</c>, comparison fields and
    /// allowed-value list a shape-guard pin needs — including combinations no
    /// well-formed claim ever carries, since the guards under test exist to
    /// reject exactly those combinations.
    /// </summary>
    private static PredicateProofRequestClaim RawClaim(
        string name,
        string kind,
        string? direction,
        string? bound,
        string? boundValue,
        IReadOnlyList<string>? allowedValues,
        string measured)
    {
        return new PredicateProofRequestClaim
        {
            Name = name,
            Kind = kind,
            Direction = direction,
            FractionalDigits = 0,
            InclusiveMaximum = "9999",
            Bound = bound,
            BoundValue = boundValue,
            AllowedValues = allowedValues,
            Measured = measured,
        };
    }


    /// <summary>A request whose one claim carries <paramref name="kind"/> and no other field, for pins about the <c>kind</c> discriminator itself.</summary>
    private static PredicateProofRequest RequestWithClaimKind(string kind)
    {
        return RequestWithSingleClaim(RawClaim("quantity", kind, direction: null, bound: null, boundValue: null, allowedValues: null, measured: "1"));
    }


    /// <summary>A well-formed <c>memberOf</c> claim over <paramref name="allowedValues"/>, for pins that vary the allowed-value list itself.</summary>
    private static PredicateProofRequestClaim MemberOfRequestClaim(string name, IReadOnlyList<string> allowedValues, string measured)
    {
        return RawClaim(name, "memberOf", direction: null, bound: null, boundValue: null, allowedValues: allowedValues, measured: measured);
    }


    /// <summary>A single-claim <c>memberOf</c> request over <paramref name="allowedValues"/>, for the allowed-value-list guard pins.</summary>
    private static PredicateProofRequest LookupOnlyRequestWithAllowedValues(IReadOnlyList<string> allowedValues, string measured)
    {
        return RequestWithSingleClaim(MemberOfRequestClaim("material_code", allowedValues, measured));
    }


    /// <summary>The invariant-culture decimal strings <c>0</c> through <c>count - 1</c>, distinct and within the claim helpers' shared domain.</summary>
    private static string[] SequentialAllowedValues(int count)
    {
        var values = new string[count];
        for(int i = 0; i < count; i++)
        {
            values[i] = i.ToString(CultureInfo.InvariantCulture);
        }

        return values;
    }


    /// <summary>A well-formed artifact-side <c>memberOf</c> claim descriptor over <paramref name="allowedValues"/>, for verify-side allowed-value-list guard pins.</summary>
    private static PredicateProofClaim MemberOfArtifactClaim(string name, IReadOnlyList<string> allowedValues)
    {
        return new PredicateProofClaim
        {
            Name = name,
            Kind = "memberOf",
            FractionalDigits = 0,
            InclusiveMaximum = "9999",
            AllowedValues = allowedValues,
        };
    }


    /// <summary>
    /// A single-claim artifact carrying <paramref name="lookupProofs"/> verbatim
    /// (deliberately left empty by the guard pins that only need to observe
    /// claim parsing succeed, never a real lookup proof check).
    /// </summary>
    private static PredicateProofArtifact LookupOnlyArtifact(PredicateProofClaim claim, IReadOnlyList<string> lookupProofs)
    {
        return new PredicateProofArtifact
        {
            Format = PredicateProofOperations.ArtifactFormat,
            Curve = PredicateProofOperations.CurveId,
            TranscriptDomain = TranscriptDomain,
            QueryCount = PredicateProofOperations.WiredQueryCount,
            LookupQueryCount = PredicateProofOperations.LookupQueryCount,
            InverseRate = PredicateProofOperations.WiredInverseRate,
            DigestBytes = PredicateProofOperations.WiredDigestBytes,
            Claims = [claim],
            PublicInputs = string.Empty,
            Proof = string.Empty,
            LookupProofs = lookupProofs,
        };
    }


    /// <summary>A request over two independent <c>memberOf</c> claims, small enough (both pad to the wired minimum table) to stay cheap while still exercising two distinct claim-name-separated transcripts.</summary>
    private static PredicateProofRequest TwoMemberOfClaimsRequest()
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
                MaterialCodeClaim("7"),
                MemberOfRequestClaim("batch_code", ["11", "22", "33"], "22"),
            ],
        };
    }
}
