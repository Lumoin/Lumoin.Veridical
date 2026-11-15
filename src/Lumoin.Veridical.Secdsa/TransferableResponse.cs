using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The response <c>Resp = (H1, SigP)</c> of a transferable proof (Verheul Algorithm 23 step 15): the primary hash
/// <c>H1 = H(e₀ ‖ … ‖ eₙ)</c> and the prover signature <c>SigP</c> over the challenge's signed structure and
/// <c>H1</c>, which commits the prover to the response and makes the proof attributable. The canonical in-memory
/// bytes are <c>H1 ‖ SigP</c>; that packing is the value's canonical form, not a transport layout.
/// </summary>
/// <remarks>
/// <para>
/// <b>What may cross a trust boundary.</b> The response is public and is recorded with the transaction data.
/// Revealing <c>H1</c> does not reveal the ephemeral keys, and a third party checks <c>H(H1) = H2</c> without them.
/// </para>
/// <para>
/// <b>Profile.</b> The tag records the identifier of the <see cref="SecdsaLayoutProfile"/> under which the signature
/// was formed; it must equal the challenge's.
/// </para>
/// </remarks>
public sealed class TransferableResponse: SensitiveMemory
{
    /// <summary>The byte offset of the response signature <c>SigP</c>.</summary>
    public const int SignatureOffset = ProofDigest.SizeBytes;


    /// <summary>The layout profile the signature was formed under, from its tag.</summary>
    public SecdsaLayoutProfileId Profile => Tag.Get<SecdsaLayoutProfileId>();


    /// <summary>Wraps an already-populated, already-validated rental; only <see cref="FromParts"/> constructs a response.</summary>
    internal TransferableResponse(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Assembles a response from its two parts into a pool-rented buffer.</summary>
    /// <param name="primaryDigest">The primary hash <c>H1</c>.</param>
    /// <param name="signature">The prover signature <c>SigP</c>, between 1 and <see cref="TransferableProofAlgorithm.MaxSignatureSizeBytes"/> bytes.</param>
    /// <param name="profile">The layout profile the signature was formed under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>A response wrapping a pool-rented copy of the parts.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="primaryDigest"/> is not a primary digest, the signature length is out of range or the profile identifier is empty.</exception>
    public static TransferableResponse FromParts(
        ProofDigest primaryDigest,
        ReadOnlySpan<byte> signature,
        SecdsaLayoutProfileId profile,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(primaryDigest);
        ArgumentNullException.ThrowIfNull(pool);
        if(primaryDigest.Kind != ProofDigestKind.Primary)
        {
            throw new ArgumentException("The response carries the primary hash H1.", nameof(primaryDigest));
        }

        if(signature.IsEmpty || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
        {
            throw new ArgumentException($"The signature must be between 1 and {TransferableProofAlgorithm.MaxSignatureSizeBytes} bytes.", nameof(signature));
        }

        if(string.IsNullOrEmpty(profile.Identifier))
        {
            throw new ArgumentException("The layout profile identifier must not be empty.", nameof(profile));
        }

        IMemoryOwner<byte> owner = pool.Rent(SignatureOffset + signature.Length);
        primaryDigest.GetBytes().CopyTo(owner.Memory.Span);
        signature.CopyTo(owner.Memory.Span[SignatureOffset..]);

        Tag baseTag = tag ?? Tag.Empty;

        return new TransferableResponse(owner, baseTag.With(SecdsaStructureKind.TransferableResponse).With(profile));
    }


    /// <summary>Returns the primary hash <c>H1</c>.</summary>
    public ReadOnlySpan<byte> GetPrimaryDigestBytes() => AsReadOnlySpan()[..ProofDigest.SizeBytes];


    /// <summary>Returns the prover signature <c>SigP</c>.</summary>
    public ReadOnlySpan<byte> GetSignatureBytes() => AsReadOnlySpan()[SignatureOffset..];


    /// <summary>Copies the primary hash into its own typed value.</summary>
    /// <param name="pool">The pool to rent the buffer from.</param>
    /// <returns>The digest, owned by the caller.</returns>
    public ProofDigest GetPrimaryDigest(BaseMemoryPool pool) => ProofDigest.FromCanonical(GetPrimaryDigestBytes(), ProofDigestKind.Primary, pool);
}
