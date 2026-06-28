using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A BBS+ secret key: a 32-byte canonical big-endian scalar in
/// <c>[1, r)</c> for the BLS12-381 scalar field. Pool-rented buffer,
/// runtime-tagged with the BBS+ ciphersuite identifier so a signer
/// sees both what the bytes are and which ciphersuite they belong
/// to.
/// </summary>
/// <remarks>
/// As long-lived secret key material the backing buffer is rented from the pool's hardened
/// <see cref="AllocationKind.Native"/> tier (native, locked, non-swappable). Where no native backing is wired
/// the pool degrades it to <see cref="AllocationKind.Pinned"/> (pinned-object heap — never GC-relocated, so the
/// zeroize-on-return actually wipes the bytes that held the key); a strict pool that allows neither rejects the
/// rent, so secret keys must come from a native-backed or degradation-allowing pool, not the general shared one.
/// </remarks>
public sealed class BbsSecretKey: SensitiveMemory
{
    /// <summary>The canonical byte length of a BBS+ secret key (a BLS12-381 scalar).</summary>
    public const int SizeBytes = WellKnownCurves.Bls12Curve381ScalarSizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.SignatureSecretKey)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.SignatureSecretKey)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256);


    /// <summary>The BBS+ ciphersuite this secret key belongs to (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    internal BbsSecretKey(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>
    /// Returns the shared algebraic-identity tag every BBS+ secret
    /// key under <paramref name="ciphersuite"/> carries:
    /// signature-secret-key role, BLS12-381 curve, the supplied
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
    /// buffer and returns a secret key wrapping it, tagged for the
    /// supplied <paramref name="ciphersuite"/>.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes; must encode a scalar strictly less than the BLS12-381 scalar field order <c>r</c>.</param>
    /// <param name="ciphersuite">The BBS+ ciphersuite this secret key belongs to. Determines which ciphersuite identifier is merged into the runtime tag.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>A secret key wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length or <paramref name="ciphersuite"/> is unknown.</exception>
    public static BbsSecretKey FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ secret key must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        //Secret key material → the hardened (native/locked) tier; degrades to pinned where no native backing
        //is wired (see the type remarks).
        IMemoryOwner<byte> owner = pool.Rent(SizeBytes, AllocationKind.Native);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsSecretKey(owner, effectiveTag);
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.SignatureSecretKey)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}