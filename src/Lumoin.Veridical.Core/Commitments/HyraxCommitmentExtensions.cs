using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Commit-side Hyrax extension methods on
/// <see cref="HyraxCommitmentKey"/>. Decomposes an MLE into the
/// <c>RowCount × ColumnCount</c> matrix and produces one Pedersen
/// vector commitment per row.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class HyraxCommitmentExtensions
{
    extension(HyraxCommitmentKey key)
    {
        /// <summary>
        /// Commits to <paramref name="mle"/>, returning the commitment
        /// (the public list of row commitments) and the witness (the
        /// per-row blinding factors, kept by the prover for the future
        /// open call).
        /// </summary>
        /// <param name="mle">The MLE to commit to. Must be over BLS12-381.</param>
        /// <param name="random">The scalar-random backend for sampling blinding factors.</param>
        /// <param name="msm">The G1 MSM backend.</param>
        /// <param name="pool">The pool to rent the buffers from.</param>
        /// <returns>A tuple of (commitment, witness). The witness is consumed by the future <c>Open</c> call.</returns>
        /// <exception cref="ArgumentException">When dimensions or curve don't match.</exception>
        public (HyraxCommitment Commitment, HyraxOpeningWitness Witness) CommitMultilinearExtension(
            MultilinearExtension mle,
            ScalarRandomDelegate random,
            G1MultiScalarMultiplyDelegate msm,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(mle);
            ArgumentNullException.ThrowIfNull(random);
            ArgumentNullException.ThrowIfNull(msm);
            ArgumentNullException.ThrowIfNull(pool);

            if(mle.Curve.Code != key.Curve.Code)
            {
                throw new ArgumentException(
                    $"Hyrax commit requires the MLE and the commitment key to share a curve; MLE was {mle.Curve}, key was {key.Curve}.");
            }

            HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(mle.VariableCount);
            int rowCount = dimensions.RowCount;
            int columnCount = dimensions.ColumnCount;

            if(key.VectorLength < columnCount)
            {
                throw new ArgumentException(
                    $"Hyrax commitment key has VectorLength = {key.VectorLength}, but committing this MLE requires at least {columnCount} generators (one per column).");
            }

            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(key.Curve);
            int scalarSize = Scalar.SizeBytes;
            int operandsPerRow = columnCount + 1;

            IMemoryOwner<byte> commitmentOwner = pool.Rent(HyraxCommitment.GetBufferSizeBytes(rowCount, key.Curve));
            IMemoryOwner<byte> witnessOwner = pool.Rent(HyraxOpeningWitness.GetBufferSizeBytes(rowCount));
            Span<byte> commitmentBuffer = commitmentOwner.Memory.Span[..HyraxCommitment.GetBufferSizeBytes(rowCount, key.Curve)];
            Span<byte> witnessBuffer = witnessOwner.Memory.Span[..HyraxOpeningWitness.GetBufferSizeBytes(rowCount)];

            //Reusable MSM input buffers. Generators are the same for every row.
            using IMemoryOwner<byte> pointsOwner = pool.Rent(operandsPerRow * g1Size);
            using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandsPerRow * scalarSize);
            Span<byte> points = pointsOwner.Memory.Span[..(operandsPerRow * g1Size)];
            Span<byte> scalars = scalarsOwner.Memory.Span[..(operandsPerRow * scalarSize)];

            for(int j = 0; j < columnCount; j++)
            {
                key.GetGenerator(j).CopyTo(points.Slice(j * g1Size, g1Size));
            }

            key.GetBlindingGenerator().CopyTo(points.Slice(columnCount * g1Size, g1Size));

            ReadOnlySpan<byte> mleBytes = mle.AsReadOnlySpan();

            for(int i = 0; i < rowCount; i++)
            {
                ReadOnlySpan<byte> rowBytes = mleBytes.Slice(i * columnCount * scalarSize, columnCount * scalarSize);
                rowBytes.CopyTo(scalars[..(columnCount * scalarSize)]);

                Span<byte> blindingSlot = witnessBuffer.Slice(i * scalarSize, scalarSize);
                _ = random(blindingSlot, key.Curve, Tag.Empty);
                blindingSlot.CopyTo(scalars.Slice(columnCount * scalarSize, scalarSize));

                Span<byte> commitmentSlot = commitmentBuffer.Slice(i * g1Size, g1Size);
                msm(points, scalars, operandsPerRow, commitmentSlot, key.Curve);
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.HyraxCommit, key.Curve);

            Tag commitmentTag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.Commitment),
                (typeof(CurveParameterSet), (object)key.Curve),
                (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax),
                (typeof(HyraxCommitmentDimensions), (object)dimensions));

            Tag witnessTag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.CommitmentWitness),
                (typeof(CurveParameterSet), (object)key.Curve),
                (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));

            var commitment = new HyraxCommitment(commitmentOwner, rowCount, columnCount, mle.VariableCount, key.Curve, commitmentTag);
            var witness = new HyraxOpeningWitness(witnessOwner, rowCount, key.Curve, witnessTag);

            return (commitment, witness);
        }


        /// <summary>
        /// Commits to <paramref name="vector"/> as a <em>single-row</em>
        /// Pedersen vector commitment: <c>C = ⟨vector, G⟩ + b·H</c> with one
        /// blinding factor — the shape
        /// <c>HyraxWeightedOpeningExtensions.OpenWeightedSum</c> consumes. The
        /// matrix-split <see cref="CommitMultilinearExtension"/> remains the
        /// evaluation-opening commitment; an arbitrary public weight vector
        /// does not factor through the matrix split, so the weighted opening
        /// commits the whole vector as one row.
        /// </summary>
        /// <param name="vector">The vector to commit, carried as an MLE; its <c>2^n</c> evaluations are the vector coordinates.</param>
        /// <param name="random">The scalar-random backend for the blinding factor.</param>
        /// <param name="msm">The G1 MSM backend.</param>
        /// <param name="pool">The pool to rent the buffers from.</param>
        /// <returns>A tuple of (commitment, witness); the witness carries the single row blind.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the curves differ or the key has fewer generators than the vector has coordinates.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The rented commitment and witness buffers transfer ownership to the returned leaf types.")]
        public (HyraxCommitment Commitment, HyraxOpeningWitness Witness) CommitVector(
            MultilinearExtension vector,
            ScalarRandomDelegate random,
            G1MultiScalarMultiplyDelegate msm,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(vector);
            ArgumentNullException.ThrowIfNull(random);
            ArgumentNullException.ThrowIfNull(msm);
            ArgumentNullException.ThrowIfNull(pool);

            if(vector.Curve.Code != key.Curve.Code)
            {
                throw new ArgumentException(
                    $"Hyrax vector commit requires the vector and the commitment key to share a curve; vector was {vector.Curve}, key was {key.Curve}.");
            }

            //One Pedersen row carrying the whole vector.
            const int SingleRowCount = 1;

            int columnCount = vector.EvaluationCount;
            if(key.VectorLength < columnCount)
            {
                throw new ArgumentException(
                    $"Hyrax commitment key has VectorLength = {key.VectorLength}, but committing this vector requires at least {columnCount} generators (one per coordinate).");
            }

            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(key.Curve);
            int scalarSize = Scalar.SizeBytes;

            IMemoryOwner<byte> commitmentOwner = pool.Rent(HyraxCommitment.GetBufferSizeBytes(SingleRowCount, key.Curve));
            IMemoryOwner<byte> witnessOwner = pool.Rent(HyraxOpeningWitness.GetBufferSizeBytes(SingleRowCount));
            Span<byte> commitmentBuffer = commitmentOwner.Memory.Span[..g1Size];
            Span<byte> witnessBuffer = witnessOwner.Memory.Span[..scalarSize];

            _ = random(witnessBuffer, key.Curve, Tag.Empty);
            HyraxOpeningProofExtensions.ComputePedersenCommitment(
                vector.AsReadOnlySpan(), witnessBuffer, key, columnCount, commitmentBuffer, msm, pool);

            CryptographicOperationCounters.Increment(CryptographicOperationKind.HyraxCommit, key.Curve);

            Tag commitmentTag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.Commitment),
                (typeof(CurveParameterSet), (object)key.Curve),
                (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));

            Tag witnessTag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.CommitmentWitness),
                (typeof(CurveParameterSet), (object)key.Curve),
                (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));

            var commitment = new HyraxCommitment(commitmentOwner, SingleRowCount, columnCount, vector.VariableCount, key.Curve, commitmentTag);
            var witness = new HyraxOpeningWitness(witnessOwner, SingleRowCount, key.Curve, witnessTag);

            return (commitment, witness);
        }
    }
}