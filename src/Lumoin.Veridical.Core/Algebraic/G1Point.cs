using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A point in the prime-order subgroup of a curve's G1 group, carried as the
/// curve's canonical compressed encoding. The curve identity travels in
/// <see cref="Curve"/> (from the <see cref="Tag"/>), not in the static type.
/// </summary>
/// <remarks>
/// <para>
/// The type is curve-broad and sealed: a single <see cref="G1Point"/> serves
/// every enumerated curve. The compressed encoding is a fixed per-curve
/// contract (RFC 9380 / the curve standard); the wrapper treats the bytes as
/// opaque and validates only their length against the curve's compressed
/// size. Flag interpretation and decompression (the y-parity / infinity /
/// compression bits) live entirely in the backend — the wrapper never reads
/// them, so a differing per-curve flag layout is the backend's concern, not
/// this type's. The distinguished constants (generator, identity) are
/// curve-definition data looked up from <see cref="WellKnownCurves"/>, the
/// same source as the size and modulus constants.
/// </para>
/// <para>
/// The type owns the buffer through the <see cref="SensitiveMemory"/> base
/// and carries the runtime algebraic identity through the tag. Arithmetic,
/// predicates, and the pairing are surfaced through <c>extension(G1Point)</c>
/// blocks in <see cref="G1PointArithmeticExtensions"/>,
/// <see cref="G1PointInspectionExtensions"/>, and
/// <see cref="PairingExtensions"/>.
/// </para>
/// <para>
/// Factories: <see cref="FromCanonical"/> copies bytes whose canonical-form
/// validity the caller has established; <see cref="FromHashToCurve"/> is the
/// RFC 9380 boundary entry; <see cref="Generator"/> and <see cref="Identity"/>
/// produce the two distinguished public constants for a curve. Each takes the
/// curve as an explicit, non-defaultable argument.
/// </para>
/// </remarks>
public sealed class G1Point: SensitiveMemory
{
    /// <summary>The curve this point lives on.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>The canonical compressed byte length of a G1 point on this point's curve.</summary>
    public int SizeBytes => WellKnownCurves.GetG1CompressedSizeBytes(Curve);


    /// <summary>
    /// Constructs a G1 point over a buffer the caller has already populated.
    /// The instance takes ownership of <paramref name="owner"/> and is
    /// responsible for clearing and returning it on disposal.
    /// </summary>
    /// <param name="owner">A pool-rented buffer holding the canonical compressed encoding.</param>
    /// <param name="curve">The curve the point lives on.</param>
    /// <param name="tag">The runtime tag; carries the algebraic identity entries plus any provenance the producer stamps.</param>
    internal G1Point(IMemoryOwner<byte> owner, CurveParameterSet curve, Tag tag)
        : base(owner, tag)
    {
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and
    /// returns a G1 point wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly the curve's compressed-size bytes carrying a canonical compressed encoding. The caller is responsible for canonical-form validity; this factory validates only the length.</param>
    /// <param name="curve">The curve the point lives on.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; the algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A G1 point wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length for the curve.</exception>
    /// <remarks>
    /// Validation against the curve equation and against prime-order subgroup
    /// membership is deliberately not performed here. An application
    /// deserialising an untrusted point composes this factory with the
    /// <c>IsOnCurve</c> / <c>IsInPrimeOrderSubgroup</c> extension members,
    /// which dispatch to backend delegates that know the curve arithmetic.
    /// </remarks>
    public static G1Point FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int sizeBytes = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        if(canonicalBytes.Length != sizeBytes)
        {
            throw new ArgumentException(
                $"{curve} G1 compressed points must be exactly {sizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.G1PointFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new G1Point(owner, curve, effectiveTag);
    }


    /// <summary>
    /// Rents a buffer, hands it to <paramref name="hashToCurve"/> for
    /// production from <paramref name="message"/> and
    /// <paramref name="domainSeparationTag"/>, and returns a G1 point wrapping
    /// the result with provenance entries stamped by the delegate.
    /// </summary>
    /// <param name="message">The application message to map into the group.</param>
    /// <param name="domainSeparationTag">The protocol-level domain separation tag binding this hash-to-curve invocation to a specific use, per RFC 9380 §3.</param>
    /// <param name="hashToCurve">The backend implementation of hash-to-curve, expected to follow RFC 9380 §3 so the output is in the prime-order subgroup by construction.</param>
    /// <param name="curve">The curve the point lives on.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A G1 point wrapping a freshly mapped, pool-rented buffer.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashToCurve"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// Boundary operation: an application message enters the system as a tagged
    /// subgroup point with provenance stamped by the producing backend. The
    /// delegate is responsible for the cryptographic correctness of the mapping
    /// including subgroup clearing.
    /// </remarks>
    public static G1Point FromHashToCurve(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        G1HashToCurveDelegate hashToCurve,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hashToCurve);
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        Tag stamped = hashToCurve(
            message,
            domainSeparationTag,
            owner.Memory.Span[..sizeBytes],
            curve,
            WellKnownAlgebraicTags.G1PointFor(curve));

        return new G1Point(owner, curve, stamped);
    }


    /// <summary>
    /// Returns a G1 point wrapping a fresh copy of the canonical compressed
    /// encoding of the identity (point at infinity) for <paramref name="curve"/>.
    /// </summary>
    /// <param name="curve">The curve whose identity is requested.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A G1 point representing the additive identity of the group.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static G1Point Identity(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        WellKnownCurves.GetG1IdentityCompressed(curve).CopyTo(owner.Memory.Span);

        return new G1Point(owner, curve, WellKnownAlgebraicTags.G1PointFor(curve));
    }


    /// <summary>
    /// Returns a G1 point wrapping a fresh copy of the canonical compressed
    /// encoding of the G1 generator for <paramref name="curve"/>.
    /// </summary>
    /// <param name="curve">The curve whose generator is requested.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A G1 point representing the canonical generator of the prime-order subgroup.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static G1Point Generator(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        WellKnownCurves.GetG1GeneratorCompressed(curve).CopyTo(owner.Memory.Span);

        return new G1Point(owner, curve, WellKnownAlgebraicTags.G1PointFor(curve));
    }


    /// <summary>
    /// Returns a tag carrying every entry from <paramref name="tag"/> plus the
    /// per-curve G1-point algebraic-identity entries, the latter taking
    /// precedence on key conflict.
    /// </summary>
    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.G1Point)
            .With(curve);
    }
}