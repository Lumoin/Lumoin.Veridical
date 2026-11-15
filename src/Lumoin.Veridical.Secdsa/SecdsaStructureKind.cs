using System.Diagnostics;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Identifies the protocol structure a SECDSA value is an instance of. The kind is a tag entry on every
/// protocol-level value of this package, so a value taken out of a container or passed between components can be
/// told apart from a different structure of the same byte length and curve.
/// </summary>
/// <param name="Identifier">The stable name of the structure.</param>
[DebuggerDisplay("{Identifier,nq}")]
public readonly record struct SecdsaStructureKind(string Identifier)
{
    /// <summary>The signature-result record <c>(R, G'', Q_U'', π)</c> of the zero-knowledge conformity check.</summary>
    public static SecdsaStructureKind SignatureResultRecord { get; } = new("secdsa-signature-result-record");

    /// <summary>The ECIES ciphertext <c>(E, C, T)</c>.</summary>
    public static SecdsaStructureKind EciesCiphertext { get; } = new("secdsa-ecies-ciphertext");

    /// <summary>The ECIES shared secret <c>Z_AB</c>, the x-coordinate of the Diffie-Hellman point.</summary>
    public static SecdsaStructureKind SharedSecret { get; } = new("secdsa-shared-secret");

    /// <summary>The key material a key-derivation function produced from a shared secret, before it is split into an AEAD key and IV.</summary>
    public static SecdsaStructureKind DerivedKeyMaterial { get; } = new("secdsa-derived-key-material");

    /// <summary>A vector of compressed P-256 points, such as the generators or public keys of statement (9).</summary>
    public static SecdsaStructureKind PointVector { get; } = new("secdsa-point-vector");

    /// <summary>A vector of P-256 scalars, such as the ephemeral private keys of a transferable challenge.</summary>
    public static SecdsaStructureKind ScalarVector { get; } = new("secdsa-scalar-vector");

    /// <summary>The 256-bit seed the ephemeral private keys of a transferable challenge are derived from.</summary>
    public static SecdsaStructureKind ProofSeed { get; } = new("secdsa-proof-seed");

    /// <summary>A hash of the transferable proof: the primary hash <c>H1</c> or the secondary hash <c>H2</c>.</summary>
    public static SecdsaStructureKind ProofDigest { get; } = new("secdsa-proof-digest");

    /// <summary>Additional data carried with a transferable challenge: authenticated data <c>AAD</c> or secret data <c>ASD</c>.</summary>
    public static SecdsaStructureKind AdditionalData { get; } = new("secdsa-additional-data");

    /// <summary>The challenge <c>(E, H2, AAD, Sig)</c> of a transferable proof.</summary>
    public static SecdsaStructureKind TransferableChallenge { get; } = new("secdsa-transferable-challenge");

    /// <summary>The response <c>(H1, SigP)</c> of a transferable proof.</summary>
    public static SecdsaStructureKind TransferableResponse { get; } = new("secdsa-transferable-response");

    /// <summary>The PIN-key scalar <c>P</c> of split ECDSA.</summary>
    public static SecdsaStructureKind PinKey { get; } = new("secdsa-pin-key");

    /// <summary>A P-256 private scalar in <c>[1, n−1]</c>.</summary>
    public static SecdsaStructureKind PrivateScalar { get; } = new("secdsa-private-scalar");

    /// <summary>The message representative <c>e = H(M)</c>.</summary>
    public static SecdsaStructureKind MessageHash { get; } = new("secdsa-message-hash");

    /// <summary>The blinded representative <c>e' = P⁻¹·e</c>.</summary>
    public static SecdsaStructureKind BlindedHash { get; } = new("secdsa-blinded-hash");

    /// <summary>The key holder's raw signature <c>(r, s₀)</c>.</summary>
    public static SecdsaStructureKind RawSignature { get; } = new("secdsa-raw-signature");

    /// <summary>The key of an ECDH-MAC.</summary>
    public static SecdsaStructureKind MacKey { get; } = new("secdsa-mac-key");

    /// <summary>The tag of an ECDH-MAC.</summary>
    public static SecdsaStructureKind MacTag { get; } = new("secdsa-mac-tag");

    /// <summary>The shared info an ECDH-MAC key derivation binds.</summary>
    public static SecdsaStructureKind SharedInfo { get; } = new("secdsa-shared-info");

    /// <summary>The salt of an ECDH-MAC key derivation.</summary>
    public static SecdsaStructureKind MacSalt { get; } = new("secdsa-mac-salt");
}
