using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The private witness portion of an R1CS instance: the scalar values
/// for the witness variables <c>z[1 + PublicInputCount..VariableCount]</c>.
/// Held only on the prover side and never sent to the verifier.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout: <see cref="WitnessVariableCount"/> canonical 32-byte
/// big-endian scalars concatenated.
/// </para>
/// </remarks>
public sealed class RawR1csWitness: SensitiveMemory
{
    /// <summary>The number of witness variables stored.</summary>
    public int WitnessVariableCount { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal RawR1csWitness(
        IMemoryOwner<byte> owner,
        int witnessVariableCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        WitnessVariableCount = witnessVariableCount;
        Curve = curve;
    }


    /// <summary>
    /// Constructs a witness from caller-supplied canonical bytes.
    /// </summary>
    /// <param name="witnessBytes">The witness scalar bytes; length must be a multiple of the scalar size.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional caller-supplied Tag.</param>
    public static RawR1csWitness FromCanonical(
        ReadOnlySpan<byte> witnessBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int scalarSize = R1csMatrix.GetValueByteSize(curve);
        if(witnessBytes.Length % scalarSize != 0)
        {
            throw new ArgumentException(
                $"Witness byte length {witnessBytes.Length} must be a multiple of the scalar size {scalarSize}.",
                nameof(witnessBytes));
        }

        int witnessVariableCount = witnessBytes.Length / scalarSize;
        if(witnessVariableCount == 0)
        {
            throw new ArgumentException(
                "RawR1csWitness requires at least one witness variable.",
                nameof(witnessBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(witnessBytes.Length);
        witnessBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new RawR1csWitness(owner, witnessVariableCount, curve, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the witness variables.</summary>
    public ReadOnlySpan<byte> GetWitnessBytes() => AsReadOnlySpan();


    private static Tag ComposeAlgebraicTag(CurveParameterSet curve)
    {
        return Tag.Create(AlgebraicRole.RawR1csWitness)
            .With(curve);
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.RawR1csWitness)
            .With(curve);
    }
}