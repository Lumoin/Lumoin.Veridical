using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A point in the prime-order subgroup of a curve's G2 group, carried as the
/// curve's canonical compressed encoding. The curve identity travels in
/// <see cref="Curve"/> (from the <see cref="Tag"/>), not in the static type.
/// </summary>
/// <remarks>
/// <para>
/// Curve-broad and sealed, parallel to <see cref="G1Point"/>: the compressed
/// encoding is a fixed per-curve contract, the wrapper treats the bytes as
/// opaque and validates only their length, and flag interpretation /
/// decompression lives in the backend. The generator and identity are
/// curve-definition constants looked up from <see cref="WellKnownCurves"/>.
/// </para>
/// <para>
/// Arithmetic and predicates are surfaced through <c>extension(G2Point)</c>
/// blocks in <see cref="G2PointArithmeticExtensions"/> and
/// <see cref="G2PointInspectionExtensions"/>; the pairing that consumes a G2
/// point lives in <see cref="PairingExtensions"/>.
/// </para>
/// </remarks>
public sealed class G2Point: SensitiveMemory
{
    /// <summary>The curve this point lives on.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>The canonical compressed byte length of a G2 point on this point's curve.</summary>
    public int SizeBytes => WellKnownCurves.GetG2CompressedSizeBytes(Curve);


    /// <summary>
    /// Constructs a G2 point over a buffer the caller has already populated.
    /// The instance takes ownership of <paramref name="owner"/> and is
    /// responsible for clearing and returning it on disposal.
    /// </summary>
    /// <param name="owner">A pool-rented buffer holding the canonical compressed encoding.</param>
    /// <param name="curve">The curve the point lives on.</param>
    /// <param name="tag">The runtime tag.</param>
    internal G2Point(IMemoryOwner<byte> owner, CurveParameterSet curve, Tag tag)
        : base(owner, WellKnownCurves.GetG2CompressedSizeBytes(curve), tag)
    {
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and
    /// returns a G2 point wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly the curve's compressed-size bytes carrying a canonical compressed encoding.</param>
    /// <param name="curve">The curve the point lives on.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>A G2 point wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length for the curve.</exception>
    public static G2Point FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int sizeBytes = WellKnownCurves.GetG2CompressedSizeBytes(curve);
        if(canonicalBytes.Length != sizeBytes)
        {
            throw new ArgumentException(
                $"{curve} G2 compressed points must be exactly {sizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.G2PointFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new G2Point(owner, curve, effectiveTag);
    }


    /// <summary>
    /// Rents a buffer, hands it to <paramref name="hashToCurve"/> for
    /// production from <paramref name="message"/> and
    /// <paramref name="domainSeparationTag"/>, and returns a G2 point wrapping
    /// the result with provenance entries stamped by the delegate.
    /// </summary>
    /// <param name="message">The application message to map into the group.</param>
    /// <param name="domainSeparationTag">The protocol-level domain separation tag, per RFC 9380 §3.</param>
    /// <param name="hashToCurve">The backend implementation of hash-to-curve.</param>
    /// <param name="curve">The curve the point lives on.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A G2 point wrapping a freshly mapped, pool-rented buffer.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashToCurve"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static G2Point FromHashToCurve(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        G2HashToCurveDelegate hashToCurve,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(hashToCurve);
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetG2CompressedSizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        Tag stamped = hashToCurve(
            message,
            domainSeparationTag,
            owner.Memory.Span[..sizeBytes],
            curve,
            WellKnownAlgebraicTags.G2PointFor(curve));

        return new G2Point(owner, curve, stamped);
    }


    /// <summary>
    /// Returns a G2 point wrapping a fresh copy of the canonical compressed
    /// encoding of the identity (point at infinity) for <paramref name="curve"/>.
    /// </summary>
    /// <param name="curve">The curve whose identity is requested.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A G2 point representing the additive identity of the group.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static G2Point Identity(CurveParameterSet curve, SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetG2CompressedSizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        WellKnownCurves.GetG2IdentityCompressed(curve).CopyTo(owner.Memory.Span);

        return new G2Point(owner, curve, WellKnownAlgebraicTags.G2PointFor(curve));
    }


    /// <summary>
    /// Returns a G2 point wrapping a fresh copy of the canonical compressed
    /// encoding of the G2 generator for <paramref name="curve"/>.
    /// </summary>
    /// <param name="curve">The curve whose generator is requested.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A G2 point representing the canonical generator of the prime-order subgroup.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static G2Point Generator(CurveParameterSet curve, SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetG2CompressedSizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        WellKnownCurves.GetG2GeneratorCompressed(curve).CopyTo(owner.Memory.Span);

        return new G2Point(owner, curve, WellKnownAlgebraicTags.G2PointFor(curve));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(
            (typeof(AlgebraicRole), (object)AlgebraicRole.G2Point),
            (typeof(CurveParameterSet), (object)curve));
    }
}