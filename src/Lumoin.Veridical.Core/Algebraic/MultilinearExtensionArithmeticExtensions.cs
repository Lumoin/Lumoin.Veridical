using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="MultilinearExtension"/> that produce
/// folded MLEs or scalar evaluations against BLS12-381 challenge points.
/// </summary>
/// <remarks>
/// <para>
/// These verbs are the bridge between the broad
/// <see cref="MultilinearExtension"/> type and the narrow
/// <see cref="Scalar"/> type. The block is curve-broad: the receiver
/// MLE's <see cref="MultilinearExtension.Curve"/> is threaded through the
/// backend delegate and into the result's tag, and the buffers are sized
/// by the receiver's <see cref="MultilinearExtension.FieldElementSizeBytes"/>.
/// A guard rejects curves that are not yet wired (Bls12Curve381, Bn254).
/// </para>
/// <para>
/// This replaced the original per-curve design (a planned parallel
/// <c>MultilinearExtensionBn254ArithmeticExtensions</c>): when BN254 was
/// wired (Batch U) the block was curve-broadened in place rather than
/// duplicated, matching the delegate-per-backend composability model
/// where the curve rides on the operand and delegate, not the call site.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MultilinearExtensionArithmeticExtensions
{
    extension(MultilinearExtension mle)
    {
        /// <summary>
        /// Folds one variable of the MLE against
        /// <paramref name="challenge"/>, returning the MLE in one fewer
        /// variable. Identity:
        /// <c>folded(x_2, ..., x_n) = (1 - c)·mle(0, x_2, ..., x_n) + c·mle(1, x_2, ..., x_n)</c>.
        /// </summary>
        /// <param name="challenge">The fold challenge <c>c</c>.</param>
        /// <param name="fold">The backend implementation of MLE folding.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A new MLE with <see cref="MultilinearExtension.VariableCount"/> equal to <c>this.VariableCount - 1</c>.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the receiver's <see cref="MultilinearExtension.Curve"/> is not BLS12-381 or has zero variables.</exception>
        public MultilinearExtension Fold(
            Scalar challenge,
            MleFoldDelegate fold,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(mle);
            ArgumentNullException.ThrowIfNull(challenge);
            ArgumentNullException.ThrowIfNull(fold);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(mle.Curve);
            if(mle.VariableCount < 1)
            {
                //ArgumentException without a paramName: the extension receiver
                //is not a named parameter from the analyzer's point of view.
                throw new ArgumentException(
                    "Cannot fold a zero-variable MLE; folding requires at least one variable to consume.");
            }

            int foldedVariableCount = mle.VariableCount - 1;
            int foldedEvaluationCount = 1 << foldedVariableCount;
            int foldedBufferSize = foldedEvaluationCount * mle.FieldElementSizeBytes;

            IMemoryOwner<byte> destination = pool.Rent(foldedBufferSize);
            fold(
                mle.AsReadOnlySpan(),
                challenge.AsReadOnlySpan(),
                destination.Memory.Span[..foldedBufferSize],
                mle.VariableCount,
                mle.Curve);

            //Tag composition for the folded result mirrors the source MLE's
            //algebraic-identity entries with the dimension entry updated for
            //the reduced variable count.
            Tag tag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.MultilinearExtension),
                (typeof(CurveParameterSet), (object)mle.Curve),
                (typeof(MultilinearExtensionDimensions), (object)new MultilinearExtensionDimensions(foldedVariableCount, foldedEvaluationCount)));

            return new MultilinearExtension(destination, foldedVariableCount, mle.FieldElementSizeBytes, mle.Curve, tag);
        }


        /// <summary>
        /// Evaluates the MLE at <paramref name="point"/>.
        /// </summary>
        /// <param name="point">The evaluation point; one scalar per MLE variable.</param>
        /// <param name="evaluate">The backend implementation of MLE evaluation.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A scalar wrapping the evaluation result.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the receiver's <see cref="MultilinearExtension.Curve"/> is not BLS12-381, or when <paramref name="point"/>'s length does not match <see cref="MultilinearExtension.VariableCount"/>.</exception>
        public Scalar Evaluate(
            ReadOnlySpan<Scalar> point,
            MleEvaluateDelegate evaluate,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(mle);
            ArgumentNullException.ThrowIfNull(evaluate);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(mle.Curve);
            if(point.Length != mle.VariableCount)
            {
                throw new ArgumentException(
                    $"Evaluation point must carry exactly {mle.VariableCount} scalar(s) (one per MLE variable); received {point.Length}.",
                    nameof(point));
            }

            int elementSize = mle.FieldElementSizeBytes;
            int pointBufferSize = mle.VariableCount * elementSize;

            //Zero-variable MLE: a constant, the single stored evaluation is
            //already the answer. The delegate honours the variableCount=0
            //contract by copying that one element to result, with no point
            //bytes to pack — skipping the rent avoids the pool's
            //"bufferSize must be greater than zero" guard.
            if(pointBufferSize == 0)
            {
                IMemoryOwner<byte> zeroVarResultOwner = pool.Rent(elementSize);
                evaluate(
                    mle.AsReadOnlySpan(),
                    ReadOnlySpan<byte>.Empty,
                    zeroVarResultOwner.Memory.Span[..elementSize],
                    0,
                    mle.Curve);

                return new Scalar(zeroVarResultOwner, mle.Curve, WellKnownAlgebraicTags.ScalarFor(mle.Curve));
            }

            //Pack the point's per-variable scalars into a contiguous buffer for
            //the delegate's flat ReadOnlySpan<byte> contract.
            using IMemoryOwner<byte> pointOwner = pool.Rent(pointBufferSize);
            Span<byte> pointBytes = pointOwner.Memory.Span[..pointBufferSize];
            for(int i = 0; i < point.Length; i++)
            {
                ArgumentNullException.ThrowIfNull(point[i]);
                point[i].AsReadOnlySpan().CopyTo(pointBytes.Slice(i * elementSize, elementSize));
            }

            IMemoryOwner<byte> resultOwner = pool.Rent(elementSize);
            evaluate(
                mle.AsReadOnlySpan(),
                pointBytes,
                resultOwner.Memory.Span[..elementSize],
                mle.VariableCount,
                mle.Curve);

            return new Scalar(resultOwner, mle.Curve, WellKnownAlgebraicTags.ScalarFor(mle.Curve));
        }
    }


}