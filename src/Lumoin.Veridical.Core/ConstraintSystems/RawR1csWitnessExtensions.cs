using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Preparation extension on <see cref="RawR1csWitness"/>.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class RawR1csWitnessExtensions
{
    extension(RawR1csWitness witness)
    {
        /// <summary>
        /// Prepares a raw witness for proving by attaching the
        /// all-zero error vector that the relaxed satisfaction
        /// identity requires. Pairs with
        /// <see cref="RawR1csInstanceExtensions.Prepare(RawR1csInstance, Commitments.HyraxCommitmentKey, Algebraic.ScalarRandomDelegate, Algebraic.G1MultiScalarMultiplyDelegate, SensitiveMemoryPool{byte})"/>.
        /// </summary>
        /// <remarks>
        /// The relaxed identity <c>(A·z) ∘ (B·z) = u · (C·z) + E</c>
        /// with <c>u = 1</c> and <c>E = 0</c> reduces exactly to the
        /// raw identity <c>(A·z) ∘ (B·z) = (C·z)</c>, so a raw witness
        /// satisfies the prepared relaxed instance if and only if it
        /// satisfied the raw instance. The preparation needs no
        /// algebraic delegates — it allocates the relaxed witness
        /// buffer with the original witness scalars plus an appended
        /// zero error vector.
        /// </remarks>
        /// <param name="errorLength">The error vector length, equal to the constraint count <c>m</c> of the instance being proved.</param>
        /// <param name="pool">Pool for the relaxed witness's backing buffer.</param>
        /// <returns>The prepared relaxed witness.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="errorLength"/> is non-positive.</exception>
        public RelaxedR1csWitness Prepare(int errorLength, SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(errorLength);

            int scalarSize = R1csMatrix.GetValueByteSize(witness.Curve);
            using IMemoryOwner<byte> errorOwner = pool.Rent(errorLength * scalarSize);
            Span<byte> errorBytes = errorOwner.Memory.Span[..(errorLength * scalarSize)];
            errorBytes.Clear();

            return RelaxedR1csWitness.FromCanonical(
                witness.GetWitnessBytes(),
                errorBytes,
                witness.Curve,
                pool);
        }
    }
}