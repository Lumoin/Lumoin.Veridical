using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The signature-result record <c>(R, G'', Q_U'', π)</c> a wallet provider places in a transaction record in place
/// of an ECDSA signature (Verheul Annex F, Algorithms 40 and 41). It carries the nonce point <c>R</c> of the
/// signature in its full representation <c>(R, s)</c>, the blinded pair <c>G'' = s⁻¹·G</c> and
/// <c>Q_U'' = s⁻¹·Q_U</c>, and the discrete-logarithm-equality proof <c>π</c> that both share one scalar. The
/// canonical bytes are <c>R ‖ G'' ‖ Q_U'' ‖ r ‖ s_π</c> with each point 33-byte SEC1 compressed and the proof 64 bytes.
/// </summary>
/// <remarks>
/// <para>
/// <b>What may cross a trust boundary.</b> Every component is public by design: the record exists so that a
/// monitoring service can check a signature result without holding the signature. The signature scalar <c>s</c>
/// itself is not in the record and cannot be recovered from it, so a holder of the record cannot present the
/// signature in the user's place.
/// </para>
/// <para>
/// <b>What the container validates.</b> <see cref="FromCanonical"/> checks length, that each point has the shape of
/// a finite compressed point, and that the proof response lies in <c>[1, n−1]</c>. On-curve membership and the
/// relation itself are checked by <see cref="SecdsaSignatureResultConformity.Check"/>.
/// </para>
/// </remarks>
public sealed class SignatureResultRecord: SensitiveMemory
{
    /// <summary>The byte length of one SEC1 compressed P-256 point.</summary>
    public const int PointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    /// <summary>The byte offset of the nonce point <c>R</c>.</summary>
    public const int NoncePointOffset = 0;

    /// <summary>The byte offset of the blinded generator <c>G'' = s⁻¹·G</c>.</summary>
    public const int BlindedGeneratorOffset = NoncePointOffset + PointSizeBytes;

    /// <summary>The byte offset of the blinded user public key <c>Q_U'' = s⁻¹·Q_U</c>.</summary>
    public const int BlindedPublicKeyOffset = BlindedGeneratorOffset + PointSizeBytes;

    /// <summary>The byte offset of the proof <c>π</c>.</summary>
    public const int ProofOffset = BlindedPublicKeyOffset + PointSizeBytes;

    /// <summary>The canonical byte length of a complete record.</summary>
    public const int SizeBytes = ProofOffset + DlEqualityProof.SizeBytes;


    /// <summary>The tag every signature-result record carries: proof role, P-256 curve, and the record structure kind.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.P256)
        .With(SecdsaStructureKind.SignatureResultRecord);


    /// <summary>Wraps an already-populated, already-validated rental; only <see cref="FromCanonical"/> constructs a record.</summary>
    internal SignatureResultRecord(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies caller-supplied canonical bytes into a pool-rented buffer and returns a record wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes: <c>R ‖ G'' ‖ Q_U'' ‖ r ‖ s</c>.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the record's identity entries.</param>
    /// <returns>A record wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the length is wrong, a point does not have the shape of a finite compressed point, or the proof response is outside <c>[1, n−1]</c>.</exception>
    public static SignatureResultRecord FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"A signature-result record must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        if(!HasFinitePointShape(canonicalBytes.Slice(NoncePointOffset, PointSizeBytes))
            || !HasFinitePointShape(canonicalBytes.Slice(BlindedGeneratorOffset, PointSizeBytes))
            || !HasFinitePointShape(canonicalBytes.Slice(BlindedPublicKeyOffset, PointSizeBytes)))
        {
            throw new ArgumentException(
                "Each point of a signature-result record must be a finite SEC1 compressed point.",
                nameof(canonicalBytes));
        }

        ReadOnlySpan<byte> responseScalar = canonicalBytes.Slice(ProofOffset + DlEqualityProof.SOffset, DlEqualityProof.SSizeBytes);
        if(!WellKnownCurves.IsCanonicalScalar(responseScalar, CurveParameterSet.P256) || responseScalar.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The proof response scalar of a signature-result record must be in [1, n-1].",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null ? AlgebraicTag : MergeWithAlgebraicTag(tag);

        return new SignatureResultRecord(owner, effectiveTag);
    }


    /// <summary>Returns the nonce point <c>R</c> of the signature, SEC1 compressed.</summary>
    public ReadOnlySpan<byte> GetNoncePointBytes() => AsReadOnlySpan().Slice(NoncePointOffset, PointSizeBytes);


    /// <summary>Returns the blinded generator <c>G'' = s⁻¹·G</c>, SEC1 compressed.</summary>
    public ReadOnlySpan<byte> GetBlindedGeneratorBytes() => AsReadOnlySpan().Slice(BlindedGeneratorOffset, PointSizeBytes);


    /// <summary>Returns the blinded user public key <c>Q_U'' = s⁻¹·Q_U</c>, SEC1 compressed.</summary>
    public ReadOnlySpan<byte> GetBlindedPublicKeyBytes() => AsReadOnlySpan().Slice(BlindedPublicKeyOffset, PointSizeBytes);


    /// <summary>Returns the full-width Fiat–Shamir value <c>r</c> of the proof <c>π</c>.</summary>
    public ReadOnlySpan<byte> GetProofRBytes() => AsReadOnlySpan().Slice(ProofOffset + DlEqualityProof.ROffset, DlEqualityProof.RSizeBytes);


    /// <summary>Returns the response scalar <c>s</c> of the proof <c>π</c>.</summary>
    public ReadOnlySpan<byte> GetProofSBytes() => AsReadOnlySpan().Slice(ProofOffset + DlEqualityProof.SOffset, DlEqualityProof.SSizeBytes);


    /// <summary>Copies the proof <c>π</c> into its own typed value.</summary>
    /// <param name="pool">The pool to rent the proof buffer from.</param>
    /// <returns>The proof, owned by the caller.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public DlEqualityProof GetProof(BaseMemoryPool pool)
    {
        return DlEqualityProof.FromCanonical(AsReadOnlySpan().Slice(ProofOffset, DlEqualityProof.SizeBytes), pool);
    }


    private static Tag MergeWithAlgebraicTag(Tag tag)
    {
        return tag.With(AlgebraicRole.ZkProof)
            .With(CurveParameterSet.P256)
            .With(SecdsaStructureKind.SignatureResultRecord);
    }
}
