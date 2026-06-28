using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// An element of a curve's sextic extension field <c>Fp12 = Fp6[w]/(w² − v)</c>,
/// the pairing target field, carried as the curve's canonical big-endian
/// layout <c>[c0][c1]</c> (<c>c0 + c1·w</c>, each component a canonical Fp6
/// element). The curve identity travels in <see cref="Curve"/>, not the static
/// type.
/// </summary>
/// <remarks>
/// <para>
/// Curve-broad and sealed. The field tower <c>Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12</c> is
/// internal to the pairing; this is the pairing target. Byte sizes are
/// per-curve (12 base-field elements) and read from <see cref="WellKnownCurves"/>;
/// component-level canonicality is the caller's responsibility at
/// <see cref="FromCanonical"/>, which validates byte length only.
/// </para>
/// </remarks>
public sealed class Fp12Element: SensitiveMemory
{
    /// <summary>The curve whose field tower this element belongs to.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The canonical byte length of an Fp12 element on this element's curve (twelve base-field components).</summary>
    public int SizeBytes => WellKnownCurves.GetFp12SizeBytes(Curve);

    /// <summary>The canonical byte length of a single Fp6 component (half of an Fp12 element).</summary>
    public int ComponentSizeBytes => SizeBytes / 2;


    /// <summary>
    /// Constructs an Fp12 element over a buffer the caller has already
    /// populated. The instance takes ownership of <paramref name="owner"/>.
    /// </summary>
    /// <param name="owner">A pool-rented buffer whose first <c>SizeBytes</c> bytes hold the <c>[c0][c1]</c> layout.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="tag">The runtime tag.</param>
    internal Fp12Element(IMemoryOwner<byte> owner, CurveParameterSet curve, Tag tag)
        : base(owner, tag)
    {
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and
    /// returns an Fp12 element wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly the curve's Fp12 byte length.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>An Fp12 element wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length for the curve.</exception>
    public static Fp12Element FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int sizeBytes = WellKnownCurves.GetFp12SizeBytes(curve);
        if(canonicalBytes.Length != sizeBytes)
        {
            throw new ArgumentException(
                $"{curve} Fp12 elements must be exactly {sizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ExtensionFieldElementFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Fp12Element(owner, curve, effectiveTag);
    }


    /// <summary>
    /// Assembles an Fp12 element from its two Fp6 component byte spans.
    /// </summary>
    /// <param name="c0">The constant-term bytes (a canonical Fp6 element).</param>
    /// <param name="c1">The <c>w</c>-coefficient bytes.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>An Fp12 element wrapping a freshly assembled pool-rented buffer.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When either component has the wrong length.</exception>
    public static Fp12Element FromComponents(
        ReadOnlySpan<byte> c0,
        ReadOnlySpan<byte> c1,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int componentSize = WellKnownCurves.GetFp6SizeBytes(curve);
        ValidateComponent(c0, nameof(c0), componentSize);
        ValidateComponent(c1, nameof(c1), componentSize);

        IMemoryOwner<byte> owner = pool.Rent(2 * componentSize);
        Span<byte> destination = owner.Memory.Span[..(2 * componentSize)];
        c0.CopyTo(destination[..componentSize]);
        c1.CopyTo(destination.Slice(componentSize, componentSize));

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ExtensionFieldElementFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Fp12Element(owner, curve, effectiveTag);
    }


    /// <summary>Returns the additive identity <c>(0, 0)</c> of Fp12.</summary>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static Fp12Element Zero(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetFp12SizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        owner.Memory.Span[..sizeBytes].Clear();

        return new Fp12Element(owner, curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(curve));
    }


    /// <summary>Returns the multiplicative identity <c>(1, 0)</c> of Fp12.</summary>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static Fp12Element One(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetFp12SizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        Span<byte> destination = owner.Memory.Span[..sizeBytes];
        destination.Clear();
        //c0 = 1 in Fp6: the innermost Fp constant term, whose last byte sits
        //at base-field-size − 1 (one twelfth of the Fp12 element).
        destination[(sizeBytes / 12) - 1] = 0x01;

        return new Fp12Element(owner, curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(curve));
    }


    /// <summary>Returns the canonical bytes of the <c>c0</c> Fp6 component (the constant term).</summary>
    public ReadOnlySpan<byte> GetC0ComponentBytes()
    {
        return AsReadOnlySpan()[..ComponentSizeBytes];
    }


    /// <summary>Returns the canonical bytes of the <c>c1</c> Fp6 component (the <c>w</c>-coefficient).</summary>
    public ReadOnlySpan<byte> GetC1ComponentBytes()
    {
        return AsReadOnlySpan().Slice(ComponentSizeBytes, ComponentSizeBytes);
    }


    private static void ValidateComponent(ReadOnlySpan<byte> component, string parameterName, int componentSize)
    {
        if(component.Length != componentSize)
        {
            throw new ArgumentException(
                $"Fp12 Fp6-component must be exactly {componentSize} bytes; received {component.Length}.",
                parameterName);
        }
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.ExtensionFieldElement)
            .With(curve);
    }
}