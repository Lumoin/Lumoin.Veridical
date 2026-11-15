using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The challenge <c>Chal(AAD) = (E, H2, AAD, Sig)</c> of a transferable proof (Verheul Algorithm 22 step 13): the
/// ephemeral public key <c>E = Σ eᵢ·Gᵢ</c>, the secondary hash <c>H2 = H(H(e₀ ‖ … ‖ eₙ))</c>, the additional
/// authenticated data in plaintext, and the signature <c>Sig</c> of the challenger <c>T</c> over them and the
/// statement. The canonical in-memory bytes are <c>E ‖ H2 ‖ len(AAD) ‖ AAD ‖ Sig</c> with <c>len</c> a 4-byte
/// big-endian integer; that packing is the value's canonical form, not a transport layout.
/// </summary>
/// <remarks>
/// <para>
/// <b>What may cross a trust boundary.</b> The whole challenge is public and is recorded with the transaction
/// data. The ciphertext and tag are not part of the signature scope, so verifying the challenge does not need
/// them.
/// </para>
/// <para>
/// <b>Profile.</b> The tag records the identifier of the <see cref="SecdsaLayoutProfile"/> under which the signature
/// was formed. A verifier rebuilds the signed bytes with exactly that profile; a challenge and a response that
/// disagree on the profile are rejected.
/// </para>
/// </remarks>
public sealed class TransferableChallenge: SensitiveMemory
{
    /// <summary>The byte length of the ephemeral public key <c>E</c>.</summary>
    public const int EphemeralPublicKeySizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    /// <summary>The byte offset of the secondary hash <c>H2</c>.</summary>
    public const int SecondaryDigestOffset = EphemeralPublicKeySizeBytes;

    /// <summary>The byte offset of the additional-data length field.</summary>
    public const int AdditionalDataLengthOffset = SecondaryDigestOffset + ProofDigest.SizeBytes;

    /// <summary>The byte offset of the additional authenticated data.</summary>
    public const int AdditionalDataOffset = AdditionalDataLengthOffset + sizeof(uint);


    /// <summary>The layout profile the challenge was signed under, from its tag.</summary>
    public SecdsaLayoutProfileId Profile => Tag.Get<SecdsaLayoutProfileId>();


    /// <summary>Wraps an already-populated, already-validated rental; only <see cref="FromParts"/> constructs a challenge.</summary>
    internal TransferableChallenge(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Assembles a challenge from its four parts into a pool-rented buffer.</summary>
    /// <param name="ephemeralPublicKey">The ephemeral public key <c>E</c>.</param>
    /// <param name="secondaryDigest">The secondary hash <c>H2</c>.</param>
    /// <param name="additionalAuthenticatedData">The additional authenticated data <c>AAD</c>.</param>
    /// <param name="signature">The challenger signature <c>Sig</c>, between 1 and <see cref="TransferableProofAlgorithm.MaxSignatureSizeBytes"/> bytes.</param>
    /// <param name="profile">The layout profile the signature was formed under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>A challenge wrapping a pool-rented copy of the parts.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="ephemeralPublicKey"/> is not a finite compressed point, <paramref name="secondaryDigest"/> is not a secondary digest, the data does not have the authenticated role, the signature length is out of range or the profile identifier is empty.</exception>
    public static TransferableChallenge FromParts(
        G1Point ephemeralPublicKey,
        ProofDigest secondaryDigest,
        AdditionalData additionalAuthenticatedData,
        ReadOnlySpan<byte> signature,
        SecdsaLayoutProfileId profile,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
        ArgumentNullException.ThrowIfNull(secondaryDigest);
        ArgumentNullException.ThrowIfNull(additionalAuthenticatedData);
        ArgumentNullException.ThrowIfNull(pool);
        if(!HasFinitePointShape(ephemeralPublicKey.AsReadOnlySpan()))
        {
            throw new ArgumentException("The ephemeral public key must be a finite SEC1 compressed point.", nameof(ephemeralPublicKey));
        }

        if(secondaryDigest.Kind != ProofDigestKind.Secondary)
        {
            throw new ArgumentException("The challenge carries the secondary hash H2.", nameof(secondaryDigest));
        }

        if(additionalAuthenticatedData.Role != AdditionalDataRole.Authenticated)
        {
            throw new ArgumentException("The challenge carries additional authenticated data.", nameof(additionalAuthenticatedData));
        }

        if(signature.IsEmpty || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
        {
            throw new ArgumentException($"The signature must be between 1 and {TransferableProofAlgorithm.MaxSignatureSizeBytes} bytes.", nameof(signature));
        }

        if(string.IsNullOrEmpty(profile.Identifier))
        {
            throw new ArgumentException("The layout profile identifier must not be empty.", nameof(profile));
        }

        ReadOnlySpan<byte> data = additionalAuthenticatedData.GetBytes();
        IMemoryOwner<byte> owner = pool.Rent(AdditionalDataOffset + data.Length + signature.Length);
        Span<byte> destination = owner.Memory.Span;
        ephemeralPublicKey.AsReadOnlySpan().CopyTo(destination);
        secondaryDigest.GetBytes().CopyTo(destination[SecondaryDigestOffset..]);
        BinaryPrimitives.WriteUInt32BigEndian(destination[AdditionalDataLengthOffset..], (uint)data.Length);
        data.CopyTo(destination[AdditionalDataOffset..]);
        signature.CopyTo(destination[(AdditionalDataOffset + data.Length)..]);

        Tag baseTag = tag ?? Tag.Empty;

        return new TransferableChallenge(owner, baseTag.With(SecdsaStructureKind.TransferableChallenge).With(profile));
    }


    /// <summary>Returns the ephemeral public key <c>E</c>, SEC1 compressed.</summary>
    public ReadOnlySpan<byte> GetEphemeralPublicKeyBytes() => AsReadOnlySpan()[..EphemeralPublicKeySizeBytes];


    /// <summary>Returns the secondary hash <c>H2</c>.</summary>
    public ReadOnlySpan<byte> GetSecondaryDigestBytes() => AsReadOnlySpan().Slice(SecondaryDigestOffset, ProofDigest.SizeBytes);


    /// <summary>Returns the additional authenticated data <c>AAD</c>.</summary>
    public ReadOnlySpan<byte> GetAdditionalAuthenticatedDataBytes() => AsReadOnlySpan().Slice(AdditionalDataOffset, AdditionalDataLength);


    /// <summary>Returns the challenger signature <c>Sig</c>.</summary>
    public ReadOnlySpan<byte> GetSignatureBytes() => AsReadOnlySpan()[(AdditionalDataOffset + AdditionalDataLength)..];


    /// <summary>Copies the ephemeral public key into its own typed value.</summary>
    /// <param name="pool">The pool to rent the buffer from.</param>
    /// <returns>The point, owned by the caller.</returns>
    public G1Point GetEphemeralPublicKey(BaseMemoryPool pool) => G1Point.FromCanonical(GetEphemeralPublicKeyBytes(), CurveParameterSet.P256, pool);


    /// <summary>Copies the secondary hash into its own typed value.</summary>
    /// <param name="pool">The pool to rent the buffer from.</param>
    /// <returns>The digest, owned by the caller.</returns>
    public ProofDigest GetSecondaryDigest(BaseMemoryPool pool) => ProofDigest.FromCanonical(GetSecondaryDigestBytes(), ProofDigestKind.Secondary, pool);


    /// <summary>Copies the additional authenticated data into its own typed value.</summary>
    /// <param name="pool">The pool to rent the buffer from.</param>
    /// <returns>The data, owned by the caller.</returns>
    public AdditionalData GetAdditionalAuthenticatedData(BaseMemoryPool pool) => AdditionalData.FromCanonical(GetAdditionalAuthenticatedDataBytes(), AdditionalDataRole.Authenticated, pool);


    private int AdditionalDataLength => (int)BinaryPrimitives.ReadUInt32BigEndian(AsReadOnlySpan().Slice(AdditionalDataLengthOffset, sizeof(uint)));
}
