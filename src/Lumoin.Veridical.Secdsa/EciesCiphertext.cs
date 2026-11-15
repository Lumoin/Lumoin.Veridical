using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The ECIES ciphertext <c>(E, C, T)</c> (Verheul Algorithms 18 and 19): the ephemeral public key <c>E</c>, the
/// encrypted data <c>C</c> and the authentication tag <c>T</c>. The canonical in-memory bytes are
/// <c>E ‖ T ‖ C</c>, with <c>E</c> 33-byte SEC1 compressed, <c>T</c> as long as the parameter set's tag length and
/// <c>C</c> the remainder. That packing is the value's canonical in-memory form, not a transport layout; the three parts are
/// exposed separately through their accessors so a transport can frame them as it needs.
/// </summary>
/// <remarks>
/// <para>
/// <b>What may cross a trust boundary.</b> The whole ciphertext is public: it is what the sender transmits. Its
/// confidentiality rests on the recipient's private key and its integrity on the tag, which also covers the
/// additional authenticated data the decryption is given; the caller authenticates that data.
/// </para>
/// <para>
/// <b>Validation.</b> <see cref="FromParts"/> checks that <c>E</c> has the shape of a finite compressed point
/// and that the tag has the parameter set's length. On-curve membership of <c>E</c> is checked when the decryption
/// is prepared. The parameter set the ciphertext was made under is recorded in the tag and checked against the
/// set the decryption is given.
/// </para>
/// </remarks>
public sealed class EciesCiphertext: SensitiveMemory
{
    /// <summary>The byte length of the ephemeral public key <c>E</c>.</summary>
    public const int EphemeralPublicKeySizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    /// <summary>The byte offset of the authentication tag <c>T</c>.</summary>
    public const int TagOffset = EphemeralPublicKeySizeBytes;


    /// <summary>The parameter set this ciphertext was made under, from its tag.</summary>
    public EciesParameterSet Parameters => Tag.Get<EciesParameterSet>();


    /// <summary>Wraps an already-populated, already-validated rental; only <see cref="FromParts"/> and the algorithms construct a ciphertext.</summary>
    internal EciesCiphertext(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Assembles a ciphertext from its three parts into a pool-rented buffer.</summary>
    /// <param name="ephemeralPublicKey">The ephemeral public key <c>E</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="authenticationTag">The tag <c>T</c>, exactly <see cref="EciesParameterSet.TagSizeBytes"/> bytes.</param>
    /// <param name="encryptedData">The encrypted data <c>C</c>; may be empty.</param>
    /// <param name="parameters">The parameter set the ciphertext was made under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>A ciphertext wrapping a pool-rented copy of the parts.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="parameters"/> is invalid, <paramref name="ephemeralPublicKey"/> does not have the shape of a finite compressed point, or the tag has the wrong length.</exception>
    public static EciesCiphertext FromParts(
        ReadOnlySpan<byte> ephemeralPublicKey,
        ReadOnlySpan<byte> authenticationTag,
        ReadOnlySpan<byte> encryptedData,
        EciesParameterSet parameters,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        parameters.Validate();
        if(!HasFinitePointShape(ephemeralPublicKey))
        {
            throw new ArgumentException("The ephemeral public key must be a finite SEC1 compressed point.", nameof(ephemeralPublicKey));
        }

        if(authenticationTag.Length != parameters.TagSizeBytes)
        {
            throw new ArgumentException(
                $"The tag must be exactly {parameters.TagSizeBytes} bytes for this parameter set; received {authenticationTag.Length}.",
                nameof(authenticationTag));
        }

        IMemoryOwner<byte> owner = pool.Rent(EphemeralPublicKeySizeBytes + authenticationTag.Length + encryptedData.Length);
        Span<byte> destination = owner.Memory.Span;
        ephemeralPublicKey.CopyTo(destination);
        authenticationTag.CopyTo(destination[TagOffset..]);
        encryptedData.CopyTo(destination[(TagOffset + authenticationTag.Length)..]);

        return new EciesCiphertext(owner, TagFor(parameters, tag));
    }


    /// <summary>Returns the ephemeral public key <c>E</c>, SEC1 compressed.</summary>
    public ReadOnlySpan<byte> GetEphemeralPublicKeyBytes() => AsReadOnlySpan()[..EphemeralPublicKeySizeBytes];


    /// <summary>Returns the authentication tag <c>T</c>.</summary>
    public ReadOnlySpan<byte> GetAuthenticationTagBytes() => AsReadOnlySpan().Slice(TagOffset, Parameters.TagSizeBytes);


    /// <summary>Returns the encrypted data <c>C</c>.</summary>
    public ReadOnlySpan<byte> GetEncryptedBytes() => AsReadOnlySpan()[(TagOffset + Parameters.TagSizeBytes)..];


    /// <summary>Builds the tag of a ciphertext under <paramref name="parameters"/>, merged with an optional provenance tag.</summary>
    internal static Tag TagFor(EciesParameterSet parameters, Tag? tag)
    {
        Tag baseTag = tag ?? Tag.Empty;

        return baseTag.With(SecdsaStructureKind.EciesCiphertext).With(parameters);
    }
}
