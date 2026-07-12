using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A blind BBS signature: the pair <c>(A, e)</c> where <c>A</c> is a G1
/// point (48 bytes canonical compressed) and <c>e</c> is a scalar (32
/// bytes canonical big-endian), serialised as 80 bytes total in
/// <c>A || e</c> order — byte-for-byte the core <c>signature_to_octets</c>
/// wire format per IETF <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>
/// Section 4.3.3.
/// </summary>
/// <remarks>
/// A distinct type from <see cref="BbsSignature"/> even though the wire
/// shape is identical: a blind signature is produced by
/// <c>FinalizeBlindSign</c> and verified by <c>VerifyBlindSign</c> under
/// the Blind BBS Interface api_id (<c>ciphersuite_id ||
/// "BLIND_H2G_HM2S_"</c>), which changes the domain, generator set, and
/// challenge/`e` derivation relative to core BBS+ <c>Sign</c>/<c>Verify</c>.
/// Feeding these 80 bytes to the core <see cref="BbsSignature"/> verifier
/// would silently compute the wrong domain rather than fail loudly, so
/// the type boundary — reinforced by the Interface-scoped
/// <see cref="Ciphersuite"/> tag — keeps the two from being conflated.
/// </remarks>
public sealed class BbsBlindSignature: SensitiveMemory
{
    /// <summary>The canonical byte length of the G1 component <c>A</c>.</summary>
    public const int AOffset = 0;

    /// <summary>The canonical byte length of the G1 component <c>A</c>.</summary>
    public const int ASizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>The byte offset of the scalar component <c>e</c>.</summary>
    public const int EOffset = ASizeBytes;

    /// <summary>The canonical byte length of the scalar component <c>e</c>.</summary>
    public const int ESizeBytes = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The canonical byte length of a complete blind BBS signature (<c>A</c> + <c>e</c>).</summary>
    public const int SizeBytes = ASizeBytes + ESizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.Signature)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256Blind);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.Signature)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256Blind);

    private static readonly Tag AlgebraicTagSha256Pseudonym = Tag.Create(AlgebraicRole.Signature)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256Pseudonym);

    private static readonly Tag AlgebraicTagShake256Pseudonym = Tag.Create(AlgebraicRole.Signature)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256Pseudonym);


    /// <summary>The extension Interface (Blind BBS or per-verifier-pseudonym) this signature was produced under (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    /// <summary>
    /// Returns the shared algebraic-identity tag every blind BBS signature
    /// under <paramref name="ciphersuite"/> carries: signature role,
    /// BLS12-381 curve, the extension Interface. The per-verifier-pseudonym
    /// Interface produces signatures through the same
    /// <c>FinalizeBlindSign</c> machinery (its <c>BlindSignWithNym</c>
    /// output IS a blind signature, only under the pseudonym api_id), so
    /// both extension Interface families are valid here — but never the
    /// core one, whose signatures are <see cref="BbsSignature"/>.
    /// </summary>
    /// <param name="ciphersuite">One of <see cref="BbsCiphersuite.Bls12Curve381Sha256Blind"/>, <see cref="BbsCiphersuite.Bls12Curve381Shake256Blind"/>, <see cref="BbsCiphersuite.Bls12Curve381Sha256Pseudonym"/>, or <see cref="BbsCiphersuite.Bls12Curve381Shake256Pseudonym"/>.</param>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not one of the four extension Interface values.</exception>
    public static Tag GetAlgebraicTag(BbsCiphersuite ciphersuite)
    {
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256Blind)
        {
            return AlgebraicTagSha256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256Blind)
        {
            return AlgebraicTagShake256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256Pseudonym)
        {
            return AlgebraicTagSha256Pseudonym;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256Pseudonym)
        {
            return AlgebraicTagShake256Pseudonym;
        }
        throw new ArgumentException($"Unknown blind-capable BBS Interface ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }


    internal BbsBlindSignature(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer
    /// and returns a blind signature wrapping it, tagged for the supplied
    /// <paramref name="ciphersuite"/>.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes (48 for <c>A</c>, 32 for <c>e</c>).</param>
    /// <param name="ciphersuite">The Blind BBS Interface ciphersuite this signature was produced under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>A blind signature wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length, <paramref name="ciphersuite"/> is unknown, or the scalar <c>e</c> is zero or not below the scalar field order.</exception>
    public static BbsBlindSignature FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ blind signature must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        //Mirrors BbsSignature.FromCanonical: e must be in [1, r-1]. The point A
        //is validated (on-curve, non-identity, prime-order subgroup) at the
        //operation surfaces before any pairing.
        ReadOnlySpan<byte> e = canonicalBytes.Slice(EOffset, ESizeBytes);
        if(!WellKnownCurves.IsCanonicalScalar(e, CurveParameterSet.Bls12Curve381) || e.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "BBS+ blind signature scalar e must be in [1, r-1]; received zero or a value at or above the scalar field order.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsBlindSignature(owner, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the G1 component <c>A</c>.</summary>
    public ReadOnlySpan<byte> GetABytes() => AsReadOnlySpan().Slice(AOffset, ASizeBytes);


    /// <summary>Returns the canonical bytes of the scalar component <c>e</c>.</summary>
    public ReadOnlySpan<byte> GetEBytes() => AsReadOnlySpan().Slice(EOffset, ESizeBytes);


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.Signature)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}
