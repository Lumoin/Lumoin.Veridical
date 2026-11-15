using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The parameters of an ECIES instantiation (Verheul Annex A.4: "both the key derivation function and the
/// authenticated encryption are parameters of the scheme"): how the key-derivation output is split into the AEAD
/// key and the initialisation vector, the tag length, and whether the additional authenticated data also enters the
/// key derivation as shared data. The value is passed explicitly to every ECIES operation and is recorded in the
/// tag of every ciphertext and derived key material, so a ciphertext made under one parameter set is never
/// processed under another.
/// </summary>
/// <param name="Identifier">The stable name of the parameter set, recorded in the tag of values produced under it.</param>
/// <param name="KeySizeBytes">The AEAD key length in bytes; the first bytes of the derived key material.</param>
/// <param name="IvSizeBytes">The initialisation vector length in bytes; the bytes of the derived key material that follow the key.</param>
/// <param name="TagSizeBytes">The authentication tag length in bytes.</param>
/// <param name="AssociatedDataIsKdfSharedData">Whether the additional authenticated data <c>A</c> is passed to the key derivation as its shared data. The paper's ANSI X9.63 instantiation does so; when <see langword="false"/> the derivation receives empty shared data.</param>
/// <remarks>
/// The derived key material is <c>KeySizeBytes + IvSizeBytes</c> bytes long: the key first, then the IV. A set is
/// public configuration, not a secret. Construct one with <see cref="Create"/>, which validates the sizes; the
/// algorithms validate again, so a default or hand-built value is rejected rather than trusted.
/// </remarks>
[DebuggerDisplay("{Identifier,nq}")]
public readonly record struct EciesParameterSet(
    string Identifier,
    int KeySizeBytes,
    int IvSizeBytes,
    int TagSizeBytes,
    bool AssociatedDataIsKdfSharedData)
{
    /// <summary>The largest key material an ECIES operation derives, bounding the stack space the algorithms use for it.</summary>
    public const int MaxKeyMaterialSizeBytes = 128;

    /// <summary>The largest tag an ECIES operation accepts.</summary>
    public const int MaxTagSizeBytes = 64;

    //AES-256 key, in bytes.
    private const int Aes256KeySizeBytes = 32;

    //The 96-bit IV NIST SP 800-38D recommends for GCM, in bytes.
    private const int Gcm96BitIvSizeBytes = 12;

    //The 128-bit GCM authentication tag, in bytes.
    private const int Gcm128BitTagSizeBytes = 16;


    /// <summary>
    /// The parameter set the paper describes as typical: an ANSI X9.63 key derivation over SHA-256 (the PKCS#11
    /// <c>CKD_SHA256_KDF</c> shape) with <c>A</c> as its shared data, producing a 256-bit AES key followed by a 96-bit
    /// GCM IV, and AES-256-GCM with a 128-bit tag (NIST SP 800-38D). The set names the shape only; the caller binds
    /// the matching <see cref="EciesKeyDerivationDelegate"/> (<see cref="X963KeyDerivation"/>) and AEAD delegates.
    /// </summary>
    public static EciesParameterSet X963Sha256Aes256Gcm { get; } = new(
        "ecies-x963-sha256-aes256gcm-iv96-tag128",
        Aes256KeySizeBytes,
        Gcm96BitIvSizeBytes,
        Gcm128BitTagSizeBytes,
        AssociatedDataIsKdfSharedData: true);


    /// <summary>The length of the derived key material: the key followed by the IV.</summary>
    public int KeyMaterialSizeBytes => KeySizeBytes + IvSizeBytes;


    /// <summary>Creates a validated parameter set.</summary>
    /// <param name="identifier">The stable, non-empty name of the set.</param>
    /// <param name="keySizeBytes">The AEAD key length in bytes, positive.</param>
    /// <param name="ivSizeBytes">The IV length in bytes, positive.</param>
    /// <param name="tagSizeBytes">The tag length in bytes, positive.</param>
    /// <param name="associatedDataIsKdfSharedData">Whether <c>A</c> is the key derivation's shared data.</param>
    /// <returns>The parameter set.</returns>
    /// <exception cref="ArgumentException">When the identifier is empty or a size is not positive or exceeds its bound.</exception>
    public static EciesParameterSet Create(
        string identifier,
        int keySizeBytes,
        int ivSizeBytes,
        int tagSizeBytes,
        bool associatedDataIsKdfSharedData)
    {
        EciesParameterSet set = new(identifier, keySizeBytes, ivSizeBytes, tagSizeBytes, associatedDataIsKdfSharedData);
        set.Validate();

        return set;
    }


    /// <summary>Throws when the set is not usable: an empty identifier, or a non-positive or oversized length.</summary>
    /// <exception cref="ArgumentException">When the set is invalid.</exception>
    public void Validate()
    {
        if(string.IsNullOrEmpty(Identifier))
        {
            throw new ArgumentException("An ECIES parameter set needs a non-empty identifier.", nameof(Identifier));
        }

        if(KeySizeBytes <= 0 || IvSizeBytes <= 0 || KeyMaterialSizeBytes > MaxKeyMaterialSizeBytes)
        {
            throw new ArgumentException($"The key and IV lengths must be positive and total at most {MaxKeyMaterialSizeBytes} bytes.", nameof(KeySizeBytes));
        }

        if(TagSizeBytes <= 0 || TagSizeBytes > MaxTagSizeBytes)
        {
            throw new ArgumentException($"The tag length must be between 1 and {MaxTagSizeBytes} bytes.", nameof(TagSizeBytes));
        }
    }
}
