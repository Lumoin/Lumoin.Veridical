using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// An element of a curve's quadratic extension field <c>Fp2 = Fp[u]/(u² + 1)</c>,
/// carried as the curve's canonical layout <c>[c0][c1]</c> (each component a
/// canonical big-endian Fp element). The curve identity travels in
/// <see cref="Curve"/>, not the static type.
/// </summary>
/// <remarks>
/// Curve-broad and sealed, the bottom non-trivial level of the pairing tower
/// <c>Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12</c>. Byte sizes are per-curve (two base-field
/// components) and read from <see cref="WellKnownCurves"/>; component-level
/// canonicality is the caller's responsibility at <see cref="FromCanonical"/>,
/// which validates byte length only.
/// </remarks>
public sealed class Fp2Element: SensitiveMemory
{
    /// <summary>The curve whose field tower this element belongs to.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The canonical byte length of an Fp2 element on this element's curve (two base-field components).</summary>
    public int SizeBytes => WellKnownCurves.GetFp2SizeBytes(Curve);

    /// <summary>The canonical byte length of a single Fp component (the curve's base-field width).</summary>
    public int ComponentSizeBytes => SizeBytes / 2;


    /// <summary>
    /// Constructs an Fp2 element over a buffer the caller has already
    /// populated. The instance takes ownership of <paramref name="owner"/>.
    /// </summary>
    /// <param name="owner">A pool-rented buffer whose first <c>SizeBytes</c> bytes hold the <c>[c0][c1]</c> layout.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="tag">The runtime tag.</param>
    internal Fp2Element(IMemoryOwner<byte> owner, CurveParameterSet curve, Tag tag)
        : base(owner, tag)
    {
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and
    /// returns an Fp2 element wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly the curve's Fp2 byte length.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>An Fp2 element wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length for the curve.</exception>
    public static Fp2Element FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int sizeBytes = WellKnownCurves.GetFp2SizeBytes(curve);
        if(canonicalBytes.Length != sizeBytes)
        {
            throw new ArgumentException(
                $"{curve} Fp2 elements must be exactly {sizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ExtensionFieldElementFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Fp2Element(owner, curve, effectiveTag);
    }


    /// <summary>
    /// Assembles an Fp2 element from its two Fp component byte spans.
    /// </summary>
    /// <param name="c0">The real-part bytes (a canonical Fp element).</param>
    /// <param name="c1">The <c>u</c>-coefficient bytes.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>An Fp2 element wrapping a freshly assembled pool-rented buffer.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When either component has the wrong length.</exception>
    public static Fp2Element FromComponents(
        ReadOnlySpan<byte> c0,
        ReadOnlySpan<byte> c1,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int componentSize = WellKnownCurves.GetFp2SizeBytes(curve) / 2;
        if(c0.Length != componentSize)
        {
            throw new ArgumentException(
                $"Fp2 component c0 must be exactly {componentSize} bytes; received {c0.Length}.",
                nameof(c0));
        }
        if(c1.Length != componentSize)
        {
            throw new ArgumentException(
                $"Fp2 component c1 must be exactly {componentSize} bytes; received {c1.Length}.",
                nameof(c1));
        }

        IMemoryOwner<byte> owner = pool.Rent(2 * componentSize);
        Span<byte> destination = owner.Memory.Span[..(2 * componentSize)];
        c0.CopyTo(destination[..componentSize]);
        c1.CopyTo(destination[componentSize..]);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ExtensionFieldElementFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Fp2Element(owner, curve, effectiveTag);
    }


    /// <summary>Returns the additive identity <c>(0, 0)</c> of Fp2.</summary>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static Fp2Element Zero(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetFp2SizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        owner.Memory.Span[..sizeBytes].Clear();

        return new Fp2Element(owner, curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(curve));
    }


    /// <summary>Returns the multiplicative identity <c>(1, 0)</c> of Fp2.</summary>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static Fp2Element One(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetFp2SizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        Span<byte> destination = owner.Memory.Span[..sizeBytes];
        destination.Clear();
        //c0 = 1 (big-endian: trailing byte 0x01 in the base-field slot); c1 = 0.
        destination[(sizeBytes / 2) - 1] = 0x01;

        return new Fp2Element(owner, curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(curve));
    }


    /// <summary>Returns the canonical bytes of the <c>c0</c> component (the real part).</summary>
    public ReadOnlySpan<byte> GetRealComponentBytes()
    {
        return AsReadOnlySpan()[..ComponentSizeBytes];
    }


    /// <summary>Returns the canonical bytes of the <c>c1</c> component (the <c>u</c>-coefficient).</summary>
    public ReadOnlySpan<byte> GetImaginaryComponentBytes()
    {
        return AsReadOnlySpan()[ComponentSizeBytes..];
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.ExtensionFieldElement)
            .With(curve);
    }
}