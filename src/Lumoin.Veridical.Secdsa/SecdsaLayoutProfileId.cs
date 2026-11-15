using System.Diagnostics;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The stable name of a <see cref="SecdsaLayoutProfile"/>. A value that was hashed or signed under a profile carries
/// the profile's identifier as a tag entry, so a verifier rebuilds the exact signed bytes from the typed value plus
/// the recorded profile even when the value arrived in a different transport layout.
/// </summary>
/// <param name="Identifier">The non-empty, stable name of the profile.</param>
[DebuggerDisplay("{Identifier,nq}")]
public readonly record struct SecdsaLayoutProfileId(string Identifier);
