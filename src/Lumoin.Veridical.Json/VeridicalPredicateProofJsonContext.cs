using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lumoin.Veridical.Json;

/// <summary>
/// The source-generated <see cref="JsonSerializerContext"/> for the predicate-proof
/// request and artifact envelopes. Source generation is what makes this serializer
/// AOT- and trim-safe: the metadata for each type is emitted at compile time, so no
/// reflection-based serialization runs at execution — the property the CLI's
/// native-AOT packaging depends on. This context, wrapped by
/// <see cref="VeridicalPredicateProofJson"/>, is the library's default (and only)
/// serialization implementation.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    RespectNullableAnnotations = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(PredicateProofArtifact))]
[JsonSerializable(typeof(PredicateProofRequest))]
internal sealed partial class VeridicalPredicateProofJsonContext: JsonSerializerContext
{
}
