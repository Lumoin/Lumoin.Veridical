using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// An R1CS instance: the three coefficient matrices <c>A</c>, <c>B</c>,
/// <c>C</c> plus the vector of public inputs. The witness side lives in
/// <see cref="RawR1csWitness"/>; together they form the satisfying input
/// to the constraint system <c>(A·z) ∘ (B·z) = (C·z)</c> where
/// <c>z = (1, public_inputs, witness)</c>.
/// </summary>
/// <remarks>
/// <para>
/// The instance owns the three matrices: <see cref="Dispose"/> on the
/// instance disposes each matrix in turn. Callers can therefore pass
/// freshly-constructed matrices in without holding onto them — the
/// instance is the canonical owner once <see cref="Create"/> returns.
/// </para>
/// <para>
/// The buffer this leaf type wraps holds only the public-input bytes
/// (<c>PublicInputCount × scalarSize</c>). The matrices and witness
/// live in separate owners.
/// </para>
/// </remarks>
public sealed class RawR1csInstance: SensitiveMemory
{
    /// <summary>The <c>A</c> coefficient matrix.</summary>
    public R1csMatrix A { get; }

    /// <summary>The <c>B</c> coefficient matrix.</summary>
    public R1csMatrix B { get; }

    /// <summary>The <c>C</c> coefficient matrix.</summary>
    public R1csMatrix C { get; }

    /// <summary>The number of public inputs (<c>z[1..1+PublicInputCount]</c>).</summary>
    public int PublicInputCount { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The instance's shape bundled for inspection.</summary>
    public R1csDimensions Dimensions { get; }


    internal RawR1csInstance(
        IMemoryOwner<byte> publicInputsOwner,
        R1csMatrix a,
        R1csMatrix b,
        R1csMatrix c,
        int publicInputCount,
        CurveParameterSet curve,
        Tag tag)
        : base(publicInputsOwner, tag)
    {
        A = a;
        B = b;
        C = c;
        PublicInputCount = publicInputCount;
        Curve = curve;
        Dimensions = new R1csDimensions(a.RowCount, a.ColumnCount, publicInputCount);
    }


    /// <summary>
    /// Constructs an instance from three matrices and public-input bytes.
    /// The instance takes ownership of the matrices.
    /// </summary>
    /// <param name="a">The <c>A</c> matrix.</param>
    /// <param name="b">The <c>B</c> matrix; must share dimensions and curve with <paramref name="a"/>.</param>
    /// <param name="c">The <c>C</c> matrix; same constraints.</param>
    /// <param name="publicInputs">The canonical big-endian bytes of the public-input scalars; length must be a multiple of the scalar size.</param>
    /// <param name="pool">The pool to rent the public-input buffer from.</param>
    /// <param name="tag">An optional caller-supplied Tag.</param>
    /// <exception cref="ArgumentException">When matrix shapes, curves, or public-input length do not satisfy the constraints.</exception>
    public static RawR1csInstance Create(
        R1csMatrix a,
        R1csMatrix b,
        R1csMatrix c,
        ReadOnlySpan<byte> publicInputs,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        ArgumentNullException.ThrowIfNull(c);
        ArgumentNullException.ThrowIfNull(pool);

        if(a.Curve.Code != b.Curve.Code || b.Curve.Code != c.Curve.Code)
        {
            throw new ArgumentException(
                $"R1CS instance matrices must share a curve; received {a.Curve}, {b.Curve}, {c.Curve}.");
        }

        if(a.RowCount != b.RowCount || b.RowCount != c.RowCount
            || a.ColumnCount != b.ColumnCount || b.ColumnCount != c.ColumnCount)
        {
            throw new ArgumentException(
                $"R1CS instance matrices must share dimensions; received A {a.RowCount}×{a.ColumnCount}, B {b.RowCount}×{b.ColumnCount}, C {c.RowCount}×{c.ColumnCount}.");
        }

        int scalarSize = R1csMatrix.GetValueByteSize(a.Curve);
        if(publicInputs.Length % scalarSize != 0)
        {
            throw new ArgumentException(
                $"Public-input byte length {publicInputs.Length} must be a multiple of the scalar size {scalarSize}.",
                nameof(publicInputs));
        }

        int publicInputCount = publicInputs.Length / scalarSize;
        if(publicInputCount + 1 > a.ColumnCount)
        {
            throw new ArgumentException(
                $"Public-input count + 1 (for the constant) = {publicInputCount + 1} exceeds the variable count {a.ColumnCount}.",
                nameof(publicInputs));
        }

        //Rent at least one byte so the pool doesn't reject a zero-length buffer
        //for instances that have no public inputs. The base reports the logical
        //length as the actual byte count of inputs.
        int physicalRent = Math.Max(1, publicInputs.Length);
        IMemoryOwner<byte> owner = pool.Rent(physicalRent);
        if(publicInputs.Length > 0)
        {
            publicInputs.CopyTo(owner.Memory.Span);
        }

        var dimensions = new R1csDimensions(a.RowCount, a.ColumnCount, publicInputCount);
        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(dimensions, a.Curve)
            : MergeWithAlgebraicTag(tag, dimensions, a.Curve);

        return new RawR1csInstance(owner, a, b, c, publicInputCount, a.Curve, effectiveTag);
    }


    /// <summary>Returns the canonical big-endian bytes of the public-input scalars.</summary>
    //The backing buffer is rented with a one-byte floor so the pool never sees a zero-length request
    //(see Create); the logical content is exactly PublicInputCount scalars, so slice to that — an
    //instance with no public inputs reports an empty span, not the padding byte.
    public ReadOnlySpan<byte> GetPublicInputsBytes() => AsReadOnlySpan()[..(PublicInputCount * R1csMatrix.GetValueByteSize(Curve))];


    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        try
        {
            if(disposing)
            {
                A?.Dispose();
                B?.Dispose();
                C?.Dispose();
            }
        }
        finally
        {
            base.Dispose(disposing);
        }
    }


    private static Tag ComposeAlgebraicTag(R1csDimensions dimensions, CurveParameterSet curve)
    {
        return Tag.Create(AlgebraicRole.RawR1csInstance)
            .With(curve)
            .With(dimensions);
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, R1csDimensions dimensions, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.RawR1csInstance)
            .With(curve)
            .With(dimensions);
    }
}