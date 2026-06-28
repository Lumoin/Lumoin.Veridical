using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// An element of a curve's cubic extension field <c>Fp6 = Fp2[v]/(v³ − (1+u))</c>,
/// carried as the curve's canonical layout <c>[c0][c1][c2]</c> (each component
/// a canonical Fp2 element). The curve identity travels in <see cref="Curve"/>,
/// not the static type.
/// </summary>
/// <remarks>
/// Curve-broad and sealed, the middle level of the pairing tower
/// <c>Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12</c>. Byte sizes are per-curve (three Fp2
/// components) and read from <see cref="WellKnownCurves"/>; component-level
/// canonicality is the caller's responsibility at <see cref="FromCanonical"/>,
/// which validates byte length only.
/// </remarks>
public sealed class Fp6Element: SensitiveMemory
{
    /// <summary>The curve whose field tower this element belongs to.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The canonical byte length of an Fp6 element on this element's curve (three Fp2 components).</summary>
    public int SizeBytes => WellKnownCurves.GetFp6SizeBytes(Curve);

    /// <summary>The canonical byte length of a single Fp2 component (one third of an Fp6 element).</summary>
    public int ComponentSizeBytes => SizeBytes / 3;


    /// <summary>
    /// Constructs an Fp6 element over a buffer the caller has already
    /// populated. The instance takes ownership of <paramref name="owner"/>.
    /// </summary>
    /// <param name="owner">A pool-rented buffer whose first <c>SizeBytes</c> bytes hold the <c>[c0][c1][c2]</c> layout.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="tag">The runtime tag.</param>
    internal Fp6Element(IMemoryOwner<byte> owner, CurveParameterSet curve, Tag tag)
        : base(owner, tag)
    {
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and
    /// returns an Fp6 element wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly the curve's Fp6 byte length.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>An Fp6 element wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length for the curve.</exception>
    public static Fp6Element FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int sizeBytes = WellKnownCurves.GetFp6SizeBytes(curve);
        if(canonicalBytes.Length != sizeBytes)
        {
            throw new ArgumentException(
                $"{curve} Fp6 elements must be exactly {sizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ExtensionFieldElementFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Fp6Element(owner, curve, effectiveTag);
    }


    /// <summary>
    /// Assembles an Fp6 element from its three Fp2 component byte spans.
    /// </summary>
    /// <param name="c0">The constant-term bytes (a canonical Fp2 element).</param>
    /// <param name="c1">The <c>v</c>-coefficient bytes.</param>
    /// <param name="c2">The <c>v²</c>-coefficient bytes.</param>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>An Fp6 element wrapping a freshly assembled pool-rented buffer.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When any component has the wrong length.</exception>
    public static Fp6Element FromComponents(
        ReadOnlySpan<byte> c0,
        ReadOnlySpan<byte> c1,
        ReadOnlySpan<byte> c2,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        int componentSize = WellKnownCurves.GetFp6SizeBytes(curve) / 3;
        ValidateComponent(c0, nameof(c0), componentSize);
        ValidateComponent(c1, nameof(c1), componentSize);
        ValidateComponent(c2, nameof(c2), componentSize);

        IMemoryOwner<byte> owner = pool.Rent(3 * componentSize);
        Span<byte> destination = owner.Memory.Span[..(3 * componentSize)];
        c0.CopyTo(destination[..componentSize]);
        c1.CopyTo(destination.Slice(componentSize, componentSize));
        c2.CopyTo(destination.Slice(2 * componentSize, componentSize));

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ExtensionFieldElementFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Fp6Element(owner, curve, effectiveTag);
    }


    /// <summary>Returns the additive identity <c>(0, 0, 0)</c> of Fp6.</summary>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static Fp6Element Zero(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetFp6SizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        owner.Memory.Span[..sizeBytes].Clear();

        return new Fp6Element(owner, curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(curve));
    }


    /// <summary>Returns the multiplicative identity <c>(1, 0, 0)</c> of Fp6.</summary>
    /// <param name="curve">The curve the element belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static Fp6Element One(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int sizeBytes = WellKnownCurves.GetFp6SizeBytes(curve);
        IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
        Span<byte> destination = owner.Memory.Span[..sizeBytes];
        destination.Clear();
        //c0 = (1, 0) in Fp2: the innermost Fp constant term, whose last byte
        //sits at base-field-size − 1 (one sixth of the Fp6 element).
        destination[(sizeBytes / 6) - 1] = 0x01;

        return new Fp6Element(owner, curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(curve));
    }


    /// <summary>Returns the canonical bytes of the <c>c0</c> Fp2 component (the constant term).</summary>
    public ReadOnlySpan<byte> GetC0ComponentBytes()
    {
        return AsReadOnlySpan()[..ComponentSizeBytes];
    }


    /// <summary>Returns the canonical bytes of the <c>c1</c> Fp2 component (the <c>v</c>-coefficient).</summary>
    public ReadOnlySpan<byte> GetC1ComponentBytes()
    {
        return AsReadOnlySpan().Slice(ComponentSizeBytes, ComponentSizeBytes);
    }


    /// <summary>Returns the canonical bytes of the <c>c2</c> Fp2 component (the <c>v²</c>-coefficient).</summary>
    public ReadOnlySpan<byte> GetC2ComponentBytes()
    {
        return AsReadOnlySpan().Slice(2 * ComponentSizeBytes, ComponentSizeBytes);
    }


    private static void ValidateComponent(ReadOnlySpan<byte> component, string parameterName, int componentSize)
    {
        if(component.Length != componentSize)
        {
            throw new ArgumentException(
                $"Fp6 Fp2-component must be exactly {componentSize} bytes; received {component.Length}.",
                parameterName);
        }
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.ExtensionFieldElement)
            .With(curve);
    }
}