using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A BBS+ signature: the pair <c>(A, e)</c> where <c>A</c> is a G1
/// point (48 bytes canonical compressed) and <c>e</c> is a scalar
/// (32 bytes canonical big-endian), serialised as 80 bytes total
/// in <c>A || e</c> order per IETF
/// <c>draft-irtf-cfrg-bbs-signatures</c> Section 4.3.1.
/// </summary>
public sealed class BbsSignature: SensitiveMemory
{
    /// <summary>The canonical byte length of the G1 component <c>A</c>.</summary>
    public const int AOffset = 0;

    /// <summary>The canonical byte length of the G1 component <c>A</c>.</summary>
    public const int ASizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>The byte offset of the scalar component <c>e</c>.</summary>
    public const int EOffset = ASizeBytes;

    /// <summary>The canonical byte length of the scalar component <c>e</c>.</summary>
    public const int ESizeBytes = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The canonical byte length of a complete BBS+ signature (<c>A</c> + <c>e</c>).</summary>
    public const int SizeBytes = ASizeBytes + ESizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.Signature)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.Signature)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256);


    /// <summary>The BBS+ ciphersuite this signature was produced under (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    internal BbsSignature(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>
    /// Returns the shared algebraic-identity tag every BBS+
    /// signature under <paramref name="ciphersuite"/> carries:
    /// signature role, BLS12-381 curve, the supplied ciphersuite.
    /// </summary>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not a known well-known ciphersuite.</exception>
    public static Tag GetAlgebraicTag(BbsCiphersuite ciphersuite)
    {
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256)
        {
            return AlgebraicTagSha256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256)
        {
            return AlgebraicTagShake256;
        }
        throw new ArgumentException($"Unknown BBS+ ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented
    /// buffer and returns a signature wrapping it, tagged for the
    /// supplied <paramref name="ciphersuite"/>.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes (48 for <c>A</c>, 32 for <c>e</c>).</param>
    /// <param name="ciphersuite">The BBS+ ciphersuite this signature was produced under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>A signature wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length, <paramref name="ciphersuite"/> is unknown, or the scalar <c>e</c> is zero or not below the scalar field order.</exception>
    public static BbsSignature FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ signature must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        //The spec's octets_to_signature: e must be in [1, r-1]. Rejecting here
        //keeps a non-canonical second encoding of the same residue from ever
        //reaching the verifier's arithmetic. The point A is validated (on-curve,
        //non-identity, prime-order subgroup) at the operation surfaces — Verify
        //and GenerateProof — before any pairing or scalar multiplication.
        ReadOnlySpan<byte> e = canonicalBytes.Slice(EOffset, ESizeBytes);
        if(!WellKnownCurves.IsCanonicalScalar(e, CurveParameterSet.Bls12Curve381) || e.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "BBS+ signature scalar e must be in [1, r-1]; received zero or a value at or above the scalar field order.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsSignature(owner, effectiveTag);
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