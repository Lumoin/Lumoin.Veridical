using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Pedersen vector commitment helper on
/// <see cref="HyraxCommitmentKey"/>. The commitment formula is
/// <c>C = ⟨values, G⟩ + blinding · H</c>, where the vector generators
/// <c>G</c> and the blinding generator <c>H</c> come from the key.
/// </summary>
/// <remarks>
/// <para>
/// Surfaced as an extension on the key so callsites read as
/// <c>key.Commit(values, blinding, msm, pool)</c>. The implementation
/// folds the per-blinding additive term into the MSM by appending the
/// blinding generator and blinding scalar to the operand lists: one
/// <see cref="G1MultiScalarMultiplyDelegate"/> call computes the
/// whole commitment.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class PedersenVectorCommitmentExtensions
{
    extension(HyraxCommitmentKey key)
    {
        /// <summary>
        /// Computes the Pedersen vector commitment
        /// <c>⟨values, G⟩ + blinding · H</c> using the key's generators
        /// and blinding generator. The vector length may be smaller
        /// than <see cref="HyraxCommitmentKey.VectorLength"/>; only
        /// generators <c>G_0..G_{values.Length − 1}</c> are consumed.
        /// </summary>
        /// <param name="values">The scalar vector to commit to.</param>
        /// <param name="blindingFactor">The Pedersen blinding factor.</param>
        /// <param name="msm">The G1 multi-scalar-multiplication backend.</param>
        /// <param name="pool">The pool to rent scratch and the result buffer from.</param>
        /// <returns>A G1 point wrapping the Pedersen commitment.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When <paramref name="values"/> is longer than the key's vector length.</exception>
        public G1Point Commit(
            ReadOnlySpan<Scalar> values,
            Scalar blindingFactor,
            G1MultiScalarMultiplyDelegate msm,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(blindingFactor);
            ArgumentNullException.ThrowIfNull(msm);
            ArgumentNullException.ThrowIfNull(pool);

            if(values.Length > key.VectorLength)
            {
                throw new ArgumentException(
                    $"Pedersen commit requested a vector of length {values.Length}, but the key has only {key.VectorLength} generators.",
                    nameof(values));
            }

            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(key.Curve);
            int scalarSize = Scalar.SizeBytes;
            int operandCount = values.Length + 1;

            using IMemoryOwner<byte> pointsOwner = pool.Rent(operandCount * g1Size);
            using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandCount * scalarSize);
            Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
            Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * scalarSize)];

            for(int i = 0; i < values.Length; i++)
            {
                ArgumentNullException.ThrowIfNull(values[i]);
                key.GetGenerator(i).CopyTo(points.Slice(i * g1Size, g1Size));
                values[i].AsReadOnlySpan().CopyTo(scalars.Slice(i * scalarSize, scalarSize));
            }

            //Append the blinding generator and blinding scalar as the final operand pair.
            key.GetBlindingGenerator().CopyTo(points.Slice(values.Length * g1Size, g1Size));
            blindingFactor.AsReadOnlySpan().CopyTo(scalars.Slice(values.Length * scalarSize, scalarSize));

            IMemoryOwner<byte> resultOwner = pool.Rent(g1Size);
            msm(points, scalars, operandCount, resultOwner.Memory.Span[..g1Size], key.Curve);

            CryptographicOperationCounters.Increment(CryptographicOperationKind.PedersenCommit, key.Curve);

            return new G1Point(resultOwner, key.Curve, WellKnownAlgebraicTags.G1PointFor(key.Curve));
        }
    }
}