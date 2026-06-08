using System.Diagnostics;

namespace Lumoin.Veridical.Core.Provenance;

/// <summary>
/// Identifies the specific method within the <see cref="ProviderClass"/> that
/// produced a tagged cryptographic value.
/// </summary>
/// <param name="Name">The method name, typically resolved at the call site via <c>nameof</c>.</param>
/// <remarks>
/// <para>
/// <see cref="ProviderOperation"/> is the finest-grained provenance dimension.
/// It pinpoints the exact factory or producer method — for example
/// <c>GenerateNonce</c>, <c>CommitPolynomial</c>, <c>Prove</c> — that minted
/// the value. Combined with the other three dimensions
/// (<see cref="ProviderLibrary"/>, <see cref="CryptoLibrary"/>,
/// <see cref="ProviderClass"/>), this gives a fully-qualified provenance
/// label for any cryptographic artifact crossing an API boundary.
/// </para>
/// <para>
/// To avoid per-call allocation pressure, backends that produce large numbers
/// of values per second commonly cache a <see cref="ProviderOperation"/>
/// instance per method as a <c>private static readonly</c> field rather than
/// constructing one on each call.
/// </para>
/// </remarks>
[DebuggerDisplay("{Name,nq}")]
public readonly record struct ProviderOperation(string Name)
{
    /// <summary>The signature-scheme key-generation operation (a Signer-side key derivation that produces both a secret and a public key).</summary>
    public static ProviderOperation SignatureKeyGeneration { get; } = new(nameof(SignatureKeyGeneration));

    /// <summary>The signature-scheme signing operation (a Signer-side production of a signature over a header and message vector).</summary>
    public static ProviderOperation SignatureSign { get; } = new(nameof(SignatureSign));

    /// <summary>The signature-scheme verification operation (a Verifier-side check that a signature was produced under a public key over a given header and messages).</summary>
    public static ProviderOperation SignatureVerify { get; } = new(nameof(SignatureVerify));

    /// <summary>The signature-scheme selective-disclosure proof-generation operation (a Prover-side production of a zero-knowledge proof of knowledge of a signature, disclosing a chosen subset of messages).</summary>
    public static ProviderOperation SignatureGenerateProof { get; } = new(nameof(SignatureGenerateProof));

    /// <summary>The signature-scheme selective-disclosure proof-verification operation (a Verifier-side check that a proof is valid for the disclosed messages under a public key).</summary>
    public static ProviderOperation SignatureVerifyProof { get; } = new(nameof(SignatureVerifyProof));
}