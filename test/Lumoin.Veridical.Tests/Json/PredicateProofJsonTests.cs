using Lumoin.Veridical.Json;
using System.Text.Json;

namespace Lumoin.Veridical.Tests.Json;

/// <summary>
/// Exercises <see cref="VeridicalPredicateProofJson"/> exactly as a consumer would:
/// round-tripping the request and artifact envelopes through the source-generated
/// serializer and confirming it rejects malformed or incomplete input. These are the
/// serializer defaults the CLI and other callers wire in.
/// </summary>
[TestClass]
internal sealed class PredicateProofJsonTests
{
    [TestMethod]
    public void ArtifactRoundTripsThroughJson()
    {
        PredicateProofArtifact artifact = SampleArtifact();

        string json = VeridicalPredicateProofJson.Serialize(artifact);
        PredicateProofArtifact restored = VeridicalPredicateProofJson.DeserializeArtifact(json);

        Assert.AreEqual(json, VeridicalPredicateProofJson.Serialize(restored), "Re-serializing the round-tripped artifact must reproduce the original JSON.");
        Assert.AreEqual(artifact.Curve, restored.Curve);
        Assert.AreEqual(artifact.QueryCount, restored.QueryCount);
        Assert.AreEqual(artifact.LookupQueryCount, restored.LookupQueryCount);
        Assert.AreEqual(artifact.InverseRate, restored.InverseRate);
        Assert.AreEqual(artifact.Proof, restored.Proof);
        Assert.HasCount(artifact.Claims.Count, restored.Claims);
        Assert.AreEqual(artifact.Claims[0].Name, restored.Claims[0].Name);
        Assert.AreEqual(artifact.Claims[0].Kind, restored.Claims[0].Kind);
        Assert.AreEqual(artifact.Claims[0].Value, restored.Claims[0].Value);
        Assert.IsNull(restored.Claims[1].Value, "A public-bound claim omits its value, which must round-trip as null.");
        Assert.AreEqual(artifact.Claims[2].Kind, restored.Claims[2].Kind);
        Assert.IsNotNull(restored.Claims[2].AllowedValues);
        Assert.HasCount(artifact.Claims[2].AllowedValues!.Count, restored.Claims[2].AllowedValues!);
        Assert.AreEqual(artifact.Claims[2].AllowedValues![0], restored.Claims[2].AllowedValues![0]);
        Assert.IsNull(restored.Claims[2].Direction, "A memberOf claim omits its comparison fields, which must round-trip as null.");
        Assert.HasCount(artifact.LookupProofs.Count, restored.LookupProofs);
        Assert.AreEqual(artifact.LookupProofs[0], restored.LookupProofs[0]);
    }


    [TestMethod]
    public void RequestRoundTripsThroughJson()
    {
        PredicateProofRequest request = SampleRequest();

        string json = VeridicalPredicateProofJson.Serialize(request);
        PredicateProofRequest restored = VeridicalPredicateProofJson.DeserializeRequest(json);

        Assert.AreEqual(json, VeridicalPredicateProofJson.Serialize(restored));
        Assert.AreEqual(request.TranscriptDomain, restored.TranscriptDomain);
        Assert.AreEqual(request.LookupQueryCount, restored.LookupQueryCount);
        Assert.AreEqual(request.Claims[0].Measured, restored.Claims[0].Measured);
        Assert.AreEqual(request.Claims[1].Kind, restored.Claims[1].Kind);
        Assert.IsNotNull(restored.Claims[1].AllowedValues);
        Assert.AreEqual(request.Claims[1].AllowedValues![1], restored.Claims[1].AllowedValues![1]);
    }


    [TestMethod]
    public void MalformedJsonThrows()
    {
        Assert.ThrowsExactly<JsonException>(() => VeridicalPredicateProofJson.DeserializeArtifact("{ not valid json"));
    }


    [TestMethod]
    public void MissingRequiredMemberThrows()
    {
        //A syntactically valid artifact object missing the required "proof" member.
        const string json = """
        { "format": "veridical-supply-chain-predicate-proof/3", "curve": "bls12-381", "transcriptDomain": "d", "queryCount": 64, "lookupQueryCount": 65, "inverseRate": 16, "digestBytes": 32, "claims": [], "publicInputs": "", "lookupProofs": [] }
        """;

        Assert.ThrowsExactly<JsonException>(() => VeridicalPredicateProofJson.DeserializeArtifact(json));
    }


    [TestMethod]
    public void MissingClaimKindThrows()
    {
        //A claim without the required "kind" discriminator is rejected at the
        //serializer boundary, before any statement interpretation.
        const string json = """
        { "format": "veridical-supply-chain-predicate-proof/3", "curve": "bls12-381", "transcriptDomain": "d", "queryCount": 64, "lookupQueryCount": 65, "inverseRate": 16, "digestBytes": 32, "claims": [ { "name": "c", "direction": "atLeast", "fractionalDigits": 1, "inclusiveMaximum": "100.0", "bound": "constant", "value": "30.0" } ], "publicInputs": "", "proof": "", "lookupProofs": [] }
        """;

        Assert.ThrowsExactly<JsonException>(() => VeridicalPredicateProofJson.DeserializeArtifact(json));
    }


    [TestMethod]
    public void NullNonNullableMemberThrows()
    {
        //A null for a non-nullable member is rejected (RespectNullableAnnotations),
        //so it cannot reach the operations as a null reference.
        const string json = """
        { "format": null, "curve": "bls12-381", "transcriptDomain": "d", "queryCount": 64, "lookupQueryCount": 65, "inverseRate": 16, "digestBytes": 32, "claims": [], "publicInputs": "", "proof": "", "lookupProofs": [] }
        """;

        Assert.ThrowsExactly<JsonException>(() => VeridicalPredicateProofJson.DeserializeArtifact(json));
    }


    private static PredicateProofArtifact SampleArtifact()
    {
        return new PredicateProofArtifact
        {
            Format = "veridical-supply-chain-predicate-proof/3",
            Curve = "bls12-381",
            TranscriptDomain = "veridical.supplychain.batterypassport.test.v1",
            QueryCount = 64,
            LookupQueryCount = 65,
            InverseRate = 16,
            DigestBytes = 32,
            Claims =
            [
                new PredicateProofClaim { Name = "recycled_content", Kind = "range", Direction = "atLeast", FractionalDigits = 1, InclusiveMaximum = "100.0", Bound = "constant", Value = "30.0" },
                new PredicateProofClaim { Name = "carbon_footprint", Kind = "range", Direction = "atMost", FractionalDigits = 2, InclusiveMaximum = "100.00", Bound = "public", Value = null },
                new PredicateProofClaim { Name = "material_code", Kind = "memberOf", FractionalDigits = 0, InclusiveMaximum = "9999", AllowedValues = ["3", "7", "42"] },
            ],
            PublicInputs = "AAECAw==",
            Proof = "BAUGBw==",
            LookupProofs = ["CAkKCw=="],
        };
    }


    private static PredicateProofRequest SampleRequest()
    {
        return new PredicateProofRequest
        {
            Format = "veridical-supply-chain-predicate-request/3",
            Curve = "bls12-381",
            TranscriptDomain = "veridical.supplychain.batterypassport.test.v1",
            QueryCount = 64,
            LookupQueryCount = 65,
            InverseRate = 16,
            DigestBytes = 32,
            Claims =
            [
                new PredicateProofRequestClaim { Name = "recycled_content", Kind = "range", Direction = "atLeast", FractionalDigits = 1, InclusiveMaximum = "100.0", Bound = "constant", BoundValue = "30.0", Measured = "32.5" },
                new PredicateProofRequestClaim { Name = "material_code", Kind = "memberOf", FractionalDigits = 0, InclusiveMaximum = "9999", AllowedValues = ["3", "7", "42"], Measured = "7" },
            ],
        };
    }
}
