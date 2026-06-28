using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// A relaxed R1CS instance. Carries the same three coefficient matrices
/// and public inputs as a standard instance plus the relaxation
/// scalar <c>u</c> and a Hyrax commitment to the error vector <c>E</c>.
/// The satisfaction condition is
/// <c>(A·z) ∘ (B·z) = u · (C·z) + E</c>.
/// </summary>
/// <remarks>
/// <para>
/// Standard R1CS is the special case <c>u = 1</c>, <c>E = 0</c>.
/// Folding schemes (Nova, ProtoStar) produce relaxed instances by
/// combining two satisfied relaxed instances into a new one whose
/// <c>u</c> and <c>E</c> reflect the combination's error term. Batch F
/// lands the data shape for those future folding-scheme batches to
/// consume; the satisfaction check here verifies the relaxed identity
/// against an explicit error vector held in
/// <see cref="RelaxedR1csWitness"/>. Verification of the error
/// commitment against that vector is a separate (commitment-scheme)
/// operation, not part of the satisfaction check itself.
/// </para>
/// <para>
/// Buffer layout: just the public-input bytes followed by the scalar
/// <c>u</c> (one canonical 32-byte scalar). The three matrices and the
/// error commitment live in separate owners and are disposed via the
/// instance's <see cref="Dispose"/>.
/// </para>
/// </remarks>
public sealed class RelaxedR1csInstance: SensitiveMemory
{
    /// <summary>The <c>A</c> coefficient matrix.</summary>
    public R1csMatrix A { get; }

    /// <summary>The <c>B</c> coefficient matrix.</summary>
    public R1csMatrix B { get; }

    /// <summary>The <c>C</c> coefficient matrix.</summary>
    public R1csMatrix C { get; }

    /// <summary>The number of public inputs.</summary>
    public int PublicInputCount { get; }

    /// <summary>The polynomial commitment to the error vector <c>E</c>.</summary>
    public PolynomialCommitment ErrorCommitment { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal RelaxedR1csInstance(
        IMemoryOwner<byte> owner,
        R1csMatrix a,
        R1csMatrix b,
        R1csMatrix c,
        int publicInputCount,
        PolynomialCommitment errorCommitment,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        A = a;
        B = b;
        C = c;
        PublicInputCount = publicInputCount;
        ErrorCommitment = errorCommitment;
        Curve = curve;
    }


    /// <summary>
    /// Constructs a relaxed instance from matrices, public inputs,
    /// the relaxation scalar <c>u</c>, and the error-vector commitment.
    /// </summary>
    public static RelaxedR1csInstance Create(
        R1csMatrix a,
        R1csMatrix b,
        R1csMatrix c,
        ReadOnlySpan<byte> publicInputs,
        ReadOnlySpan<byte> uBytes,
        PolynomialCommitment errorCommitment,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        ArgumentNullException.ThrowIfNull(c);
        ArgumentNullException.ThrowIfNull(errorCommitment);
        ArgumentNullException.ThrowIfNull(pool);

        if(a.Curve.Code != b.Curve.Code || b.Curve.Code != c.Curve.Code || c.Curve.Code != errorCommitment.Curve.Code)
        {
            throw new ArgumentException(
                $"Relaxed R1CS instance components must share a curve; received A={a.Curve}, B={b.Curve}, C={c.Curve}, E-commitment={errorCommitment.Curve}.");
        }

        if(a.RowCount != b.RowCount || b.RowCount != c.RowCount
            || a.ColumnCount != b.ColumnCount || b.ColumnCount != c.ColumnCount)
        {
            throw new ArgumentException(
                $"Relaxed R1CS matrices must share dimensions; received A {a.RowCount}×{a.ColumnCount}, B {b.RowCount}×{b.ColumnCount}, C {c.RowCount}×{c.ColumnCount}.");
        }

        int scalarSize = R1csMatrix.GetValueByteSize(a.Curve);
        if(uBytes.Length != scalarSize)
        {
            throw new ArgumentException(
                $"u must be a single canonical scalar of {scalarSize} bytes; received {uBytes.Length}.",
                nameof(uBytes));
        }

        if(publicInputs.Length % scalarSize != 0)
        {
            throw new ArgumentException(
                $"publicInputs byte length {publicInputs.Length} must be a multiple of the scalar size {scalarSize}.",
                nameof(publicInputs));
        }

        int publicInputCount = publicInputs.Length / scalarSize;
        int bufferSize = ComputeBufferSize(publicInputCount, a.Curve);
        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];

        publicInputs.CopyTo(buffer);
        uBytes.CopyTo(buffer[publicInputs.Length..]);

        var dimensions = new R1csDimensions(a.RowCount, a.ColumnCount, publicInputCount);
        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(dimensions, a.Curve)
            : MergeWithAlgebraicTag(tag, dimensions, a.Curve);

        return new RelaxedR1csInstance(owner, a, b, c, publicInputCount, errorCommitment, a.Curve, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the public-input scalars.</summary>
    public ReadOnlySpan<byte> GetPublicInputsBytes()
    {
        int scalarSize = R1csMatrix.GetValueByteSize(Curve);
        return AsReadOnlySpan()[..(PublicInputCount * scalarSize)];
    }


    /// <summary>Returns the canonical bytes of the relaxation scalar <c>u</c>.</summary>
    public ReadOnlySpan<byte> GetUBytes()
    {
        int scalarSize = R1csMatrix.GetValueByteSize(Curve);
        return AsReadOnlySpan().Slice(PublicInputCount * scalarSize, scalarSize);
    }


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
                ErrorCommitment?.Dispose();
            }
        }
        finally
        {
            base.Dispose(disposing);
        }
    }


    private static int ComputeBufferSize(int publicInputCount, CurveParameterSet curve)
    {
        int scalarSize = R1csMatrix.GetValueByteSize(curve);

        //Public inputs + the single u scalar.
        int size = (publicInputCount * scalarSize) + scalarSize;
        return Math.Max(1, size);
    }


    private static Tag ComposeAlgebraicTag(R1csDimensions dimensions, CurveParameterSet curve)
    {
        return Tag.Create(AlgebraicRole.FoldingAccumulator)
            .With(curve)
            .With(dimensions);
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, R1csDimensions dimensions, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.FoldingAccumulator)
            .With(curve)
            .With(dimensions);
    }
}