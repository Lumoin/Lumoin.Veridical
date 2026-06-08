using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The prover-side witness for a relaxed R1CS instance: the standard
/// witness scalars plus the error vector <c>E</c> the relaxed
/// satisfaction condition <c>(A·z) ∘ (B·z) = u · (C·z) + E</c> requires.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout: <c>WitnessVariableCount</c> witness scalars followed
/// by <c>ErrorLength</c> error scalars.
/// </para>
/// </remarks>
public sealed class RelaxedR1csWitness: SensitiveMemory
{
    /// <summary>The number of strictly-private witness variables.</summary>
    public int WitnessVariableCount { get; }

    /// <summary>The length of the error vector (equal to the constraint count of the parent instance).</summary>
    public int ErrorLength { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal RelaxedR1csWitness(
        IMemoryOwner<byte> owner,
        int witnessVariableCount,
        int errorLength,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, (witnessVariableCount + errorLength) * R1csMatrix.GetValueByteSize(curve), tag)
    {
        WitnessVariableCount = witnessVariableCount;
        ErrorLength = errorLength;
        Curve = curve;
    }


    /// <summary>
    /// Constructs a relaxed witness from witness and error vectors,
    /// both in canonical big-endian byte form.
    /// </summary>
    public static RelaxedR1csWitness FromCanonical(
        ReadOnlySpan<byte> witnessBytes,
        ReadOnlySpan<byte> errorBytes,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int scalarSize = R1csMatrix.GetValueByteSize(curve);
        if(witnessBytes.Length % scalarSize != 0)
        {
            throw new ArgumentException(
                $"witnessBytes length {witnessBytes.Length} must be a multiple of {scalarSize}.",
                nameof(witnessBytes));
        }

        if(errorBytes.Length % scalarSize != 0)
        {
            throw new ArgumentException(
                $"errorBytes length {errorBytes.Length} must be a multiple of {scalarSize}.",
                nameof(errorBytes));
        }

        int witnessCount = witnessBytes.Length / scalarSize;
        int errorCount = errorBytes.Length / scalarSize;
        if(witnessCount == 0 || errorCount == 0)
        {
            throw new ArgumentException(
                "Relaxed R1CS witness requires at least one witness variable and at least one error entry.");
        }

        int totalSize = witnessBytes.Length + errorBytes.Length;
        IMemoryOwner<byte> owner = pool.Rent(totalSize);
        Span<byte> buffer = owner.Memory.Span[..totalSize];
        witnessBytes.CopyTo(buffer);
        errorBytes.CopyTo(buffer[witnessBytes.Length..]);

        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new RelaxedR1csWitness(owner, witnessCount, errorCount, curve, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the witness variables.</summary>
    public ReadOnlySpan<byte> GetWitnessBytes()
    {
        int scalarSize = R1csMatrix.GetValueByteSize(Curve);
        return AsReadOnlySpan()[..(WitnessVariableCount * scalarSize)];
    }


    /// <summary>Returns the canonical bytes of the error vector <c>E</c>.</summary>
    public ReadOnlySpan<byte> GetErrorBytes()
    {
        int scalarSize = R1csMatrix.GetValueByteSize(Curve);
        return AsReadOnlySpan().Slice(WitnessVariableCount * scalarSize, ErrorLength * scalarSize);
    }


    private static Tag ComposeAlgebraicTag(CurveParameterSet curve)
    {
        return Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.FoldingAccumulator),
            (typeof(CurveParameterSet), (object)curve));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(
            (typeof(AlgebraicRole), (object)AlgebraicRole.FoldingAccumulator),
            (typeof(CurveParameterSet), (object)curve));
    }
}