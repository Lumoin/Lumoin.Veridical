using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A per-verifier BBS pseudonym: a single G1 point (48 bytes canonical
/// compressed) per IETF
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 4
/// (<c>pseudonym = OP * poly</c>, serialised via <c>point_to_octets_g1</c>).
/// Pool-rented buffer, runtime-tagged with the per-verifier-pseudonym
/// Interface identifier and the G1-point algebraic role.
/// </summary>
/// <remarks>
/// Pseudonyms are Interface- and ciphersuite-specific by design (Section
/// 3.3: linking pseudonyms across Interfaces or ciphersuites is out of
/// scope), which is why the <see cref="Ciphersuite"/> tag names the
/// per-verifier-pseudonym Interface api_id rather than the core one — a
/// pseudonym computed under one Interface must never be compared against
/// or accepted as one computed under another.
/// </remarks>
public sealed class BbsPseudonym: SensitiveMemory
{
    /// <summary>The canonical byte length of a compressed G1 pseudonym point.</summary>
    public const int SizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.G1Point)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256Pseudonym);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.G1Point)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256Pseudonym);


    /// <summary>
    /// The BLS12-381 G1 base point BP1's canonical compressed encoding —
    /// the same distinguished point as the curve's G1 generator, already
    /// pinned once in <see cref="WellKnownCurves.GetG1GeneratorCompressed"/>
    /// (the "generator" and "base point" names refer to the identical
    /// point by the IETF pairing-curve convention). Delegated to rather
    /// than re-declared so the two call sites can never drift apart.
    /// </summary>
    private static ReadOnlySpan<byte> Bp1CompressedEncoding =>
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381);


    /// <summary>The per-verifier-pseudonym Interface this pseudonym was computed under (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    /// <summary>
    /// Returns the shared algebraic-identity tag every pseudonym under
    /// <paramref name="ciphersuite"/> carries: G1-point role, BLS12-381
    /// curve, the per-verifier-pseudonym Interface.
    /// </summary>
    /// <param name="ciphersuite">Either <see cref="BbsCiphersuite.Bls12Curve381Sha256Pseudonym"/> or <see cref="BbsCiphersuite.Bls12Curve381Shake256Pseudonym"/>.</param>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not one of the two per-verifier-pseudonym Interface values.</exception>
    public static Tag GetAlgebraicTag(BbsCiphersuite ciphersuite)
    {
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256Pseudonym)
        {
            return AlgebraicTagSha256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256Pseudonym)
        {
            return AlgebraicTagShake256;
        }
        throw new ArgumentException($"Unknown per-verifier-pseudonym Interface ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }


    internal BbsPseudonym(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer
    /// and returns a pseudonym wrapping it, tagged for the supplied
    /// <paramref name="ciphersuite"/>.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes (a compressed G1 point).</param>
    /// <param name="ciphersuite">The per-verifier-pseudonym Interface ciphersuite this pseudonym was computed under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>A pseudonym wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length, or encodes the G1 identity or the G1 base point BP1 (nym -03 Section 3.3 forbids both).</exception>
    public static BbsPseudonym FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ pseudonym must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        //nym -03 Section 3.3: "a point of the G1 group different from the
        //Identity (Identity_G1) or the base point (BP1) of G1". On-curve and
        //prime-order-subgroup membership are validated at the operation
        //surfaces, matching the house pattern already established for
        //BbsSignature's A and BbsProof's Abar/Bbar/D — this constructor only
        //checks the two named forbidden values.
        if(CryptographicOperations.FixedTimeEquals(canonicalBytes, WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381)))
        {
            throw new ArgumentException("BBS+ pseudonym must not be the G1 identity (nym -03 Section 3.3).", nameof(canonicalBytes));
        }
        if(CryptographicOperations.FixedTimeEquals(canonicalBytes, Bp1CompressedEncoding))
        {
            throw new ArgumentException("BBS+ pseudonym must not be the G1 base point BP1 (nym -03 Section 3.3).", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsPseudonym(owner, effectiveTag);
    }


    /// <summary>Returns the canonical compressed bytes of the pseudonym G1 point.</summary>
    public ReadOnlySpan<byte> GetPseudonymBytes() => AsReadOnlySpan();


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.G1Point)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}
