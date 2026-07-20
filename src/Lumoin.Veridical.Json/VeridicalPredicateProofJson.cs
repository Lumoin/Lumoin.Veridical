using System;
using System.Text.Json;

namespace Lumoin.Veridical.Json;

/// <summary>
/// The default serializer for the predicate-proof request and artifact envelopes.
/// Every method routes through the source-generated
/// <see cref="VeridicalPredicateProofJsonContext"/>, so serialization is AOT- and
/// trim-safe and produces indented, camel-cased JSON. This is the reference
/// implementation a consumer wires in: the CLI uses it at its command and MCP
/// boundaries, and tests exercise it exactly as a library user would.
/// </summary>
public static class VeridicalPredicateProofJson
{
    /// <summary>Serializes a proof artifact to JSON.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="artifact"/> is null.</exception>
    public static string Serialize(PredicateProofArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        return JsonSerializer.Serialize(artifact, VeridicalPredicateProofJsonContext.Default.PredicateProofArtifact);
    }


    /// <summary>Deserializes a proof artifact from JSON.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="json"/> is null.</exception>
    /// <exception cref="JsonException">When <paramref name="json"/> is not well-formed or deserializes to null.</exception>
    public static PredicateProofArtifact DeserializeArtifact(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        return JsonSerializer.Deserialize(json, VeridicalPredicateProofJsonContext.Default.PredicateProofArtifact)
            ?? throw new JsonException("The JSON deserialized to a null predicate-proof artifact.");
    }


    /// <summary>Serializes a proof request to JSON.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/> is null.</exception>
    public static string Serialize(PredicateProofRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        return JsonSerializer.Serialize(request, VeridicalPredicateProofJsonContext.Default.PredicateProofRequest);
    }


    /// <summary>Deserializes a proof request from JSON.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="json"/> is null.</exception>
    /// <exception cref="JsonException">When <paramref name="json"/> is not well-formed or deserializes to null.</exception>
    public static PredicateProofRequest DeserializeRequest(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        return JsonSerializer.Deserialize(json, VeridicalPredicateProofJsonContext.Default.PredicateProofRequest)
            ?? throw new JsonException("The JSON deserialized to a null predicate-proof request.");
    }
}
