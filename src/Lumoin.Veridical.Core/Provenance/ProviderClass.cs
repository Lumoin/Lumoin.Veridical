using System.Diagnostics;

namespace Lumoin.Veridical.Core.Provenance;

/// <summary>
/// Identifies the static class within the <see cref="ProviderLibrary"/> that
/// produced a tagged cryptographic value.
/// </summary>
/// <param name="Name">The class name, typically resolved at class initialization via <c>nameof</c>.</param>
/// <remarks>
/// <para>
/// Backends typically organise their operations into a small number of
/// static classes — entropy functions, key material creators, signing
/// functions, hash functions, prover phases. <see cref="ProviderClass"/>
/// records which one was responsible for the value at hand, narrowing the
/// scope of investigation when tracing a value's lineage in CBOM-style
/// audits.
/// </para>
/// </remarks>
[DebuggerDisplay("{Name,nq}")]
public readonly record struct ProviderClass(string Name)
{
    /// <summary>
    /// The taxonomic class for any signature-scheme producer (BBS+,
    /// Ed25519, ECDSA, …). Distinguishes signature-scheme operations
    /// from commitment-scheme, proof-system, or hash-function operations
    /// inside CBOM-style provenance audits.
    /// </summary>
    public static ProviderClass SignatureScheme { get; } = new(nameof(SignatureScheme));
}