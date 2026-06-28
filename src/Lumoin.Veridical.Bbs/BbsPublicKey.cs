using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A BBS+ public key: the G2 point <c>W = SK · BP2</c> in canonical
/// 96-byte compressed encoding. Pool-rented buffer, runtime-tagged
/// with the BBS+ ciphersuite identifier so a verifier sees both what
/// the bytes are and which ciphersuite they belong to.
/// </summary>
/// <remarks>
/// <para>
/// The public key lives in G2 on BLS12-381 because the pairing
/// equation places the secret-key contribution on the G2 side. Verify
/// checks the equation <c>e(A, W + BP2·e) = e(B, BP2)</c>; producing
/// a forged signature would require either solving the discrete
/// logarithm in G2 (to recover SK) or computing pairings whose
/// G2-side arguments do not factor through the public key, neither
/// of which is feasible at the BLS12-381 security level.
/// </para>
/// </remarks>
public sealed class BbsPublicKey: SensitiveMemory
{
    /// <summary>The canonical byte length of a BBS+ public key (G2 compressed).</summary>
    public const int SizeBytes = WellKnownCurves.Bls12Curve381G2CompressedSizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.SignaturePublicKey)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.SignaturePublicKey)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256);


    /// <summary>The BBS+ ciphersuite this public key belongs to (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    internal BbsPublicKey(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>
    /// Returns the shared algebraic-identity tag every BBS+ public
    /// key under <paramref name="ciphersuite"/> carries:
    /// signature-public-key role, BLS12-381 curve, the supplied
    /// ciphersuite.
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
    /// buffer and returns a public key wrapping it, tagged for the
    /// supplied <paramref name="ciphersuite"/>.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes.</param>
    /// <param name="ciphersuite">The BBS+ ciphersuite this public key belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A public key wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length or <paramref name="ciphersuite"/> is unknown.</exception>
    public static BbsPublicKey FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ public key must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsPublicKey(owner, effectiveTag);
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.SignaturePublicKey)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}