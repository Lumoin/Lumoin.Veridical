using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Batched multilinear-extension operations composed from the scalar
/// backend bundle: the fold — the inner loop of every sumcheck-based proof
/// system in the library — runs its per-pair products through a
/// <see cref="ScalarBatchMultiplyDelegate"/> (lane-interleaved SIMD where the
/// host supports it) instead of one multiply call per pair.
/// </summary>
/// <remarks>
/// <para>
/// The fold identity is computed as
/// <c>folded[i] = e[2i] + c·(e[2i+1] − e[2i])</c>, which equals the
/// reference's <c>(1 − c)·e[2i] + c·e[2i+1]</c> exactly in the field —
/// byte-identical canonical output. The interleaved pairs are gathered into
/// a contiguous difference column per block, the challenge is broadcast,
/// and the products run batched; the surrounding subtract/add stay on the
/// per-element delegates. Like the reference, writes run forward
/// (<c>folded[i]</c> lands at index <c>i ≤ 2i</c>), so in-place folding over
/// the source buffer's prefix is safe.
/// </para>
/// <para>
/// Evaluation tables are witness data, so the column scratch is pooled
/// sensitive memory from the factory-captured pool.
/// </para>
/// </remarks>
public static class ManagedMultilinearExtensionBackend
{
    private const int ScalarSize = Scalar.SizeBytes;

    //Pairs per batched block, matching the prover-side convention: bounds the
    //pooled column scratch while keeping each BatchMultiply call long enough
    //to amortise its lane setup.
    private const int BatchBlockPairCount = 1024;


    /// <summary>
    /// Returns a batched <see cref="MleFoldDelegate"/> composed from the
    /// given scalar backends.
    /// </summary>
    /// <param name="add">Scalar-addition backend.</param>
    /// <param name="subtract">Scalar-subtraction backend.</param>
    /// <param name="batchMultiply">Batch-multiply backend (the facade-routed SIMD bundle's, or any other).</param>
    /// <param name="pool">The pool the returned delegate rents its column scratch from.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static MleFoldDelegate CreateFold(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarBatchMultiplyDelegate batchMultiply,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(batchMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        return (originalEvaluations, challenge, foldedEvaluations, variableCount, curve) =>
            Fold(originalEvaluations, challenge, foldedEvaluations, variableCount, curve, add, subtract, batchMultiply, pool);
    }


    /// <summary>
    /// Returns a batched <see cref="MleFoldDelegate"/> composed from the
    /// given backend bundle — the convenience form of
    /// <see cref="CreateFold(ScalarAddDelegate, ScalarSubtractDelegate, ScalarBatchMultiplyDelegate, SensitiveMemoryPool{byte})"/>.
    /// </summary>
    /// <param name="backend">The scalar backend bundle (borrowed, not owned).</param>
    /// <param name="pool">The pool the returned delegate rents its column scratch from.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static MleFoldDelegate CreateFold(ScalarArithmeticBackend backend, SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(backend);

        return CreateFold(backend.Add, backend.Subtract, backend.BatchMultiply, pool);
    }


    /// <summary>
    /// Returns a batched <see cref="MleEvaluateDelegate"/> composed from the
    /// given backend bundle — the convenience form of
    /// <see cref="CreateEvaluate(ScalarAddDelegate, ScalarSubtractDelegate, ScalarBatchMultiplyDelegate, SensitiveMemoryPool{byte})"/>.
    /// </summary>
    /// <param name="backend">The scalar backend bundle (borrowed, not owned).</param>
    /// <param name="pool">The pool the returned delegate rents its fold scratch from.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static MleEvaluateDelegate CreateEvaluate(ScalarArithmeticBackend backend, SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(backend);

        return CreateEvaluate(backend.Add, backend.Subtract, backend.BatchMultiply, pool);
    }


    /// <summary>
    /// Returns a batched <see cref="MleEvaluateDelegate"/> composed from the
    /// given scalar backends: <c>n</c> successive batched folds against the
    /// point's coordinates in pooled ping-pong scratch, the final element
    /// copied out — the production counterpart of the test-only BigInteger
    /// reference, so library consumers have a shipped evaluate.
    /// </summary>
    /// <param name="add">Scalar-addition backend.</param>
    /// <param name="subtract">Scalar-subtraction backend.</param>
    /// <param name="batchMultiply">Batch-multiply backend.</param>
    /// <param name="pool">The pool the returned delegate rents its fold scratch from.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static MleEvaluateDelegate CreateEvaluate(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarBatchMultiplyDelegate batchMultiply,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(batchMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        return (evaluations, point, result, variableCount, curve) =>
            Evaluate(evaluations, point, result, variableCount, curve, add, subtract, batchMultiply, pool);
    }


    private static void Evaluate(
        ReadOnlySpan<byte> evaluations,
        ReadOnlySpan<byte> point,
        Span<byte> result,
        int variableCount,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarBatchMultiplyDelegate batchMultiply,
        SensitiveMemoryPool<byte> pool)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.MleEvaluate, curve);

        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        int evaluationCount = 1 << variableCount;
        if(evaluations.Length != evaluationCount * ScalarSize)
        {
            throw new ArgumentException(
                $"Evaluations span must be {evaluationCount * ScalarSize} bytes for variableCount = {variableCount}; received {evaluations.Length}.",
                nameof(evaluations));
        }

        if(point.Length != variableCount * ScalarSize)
        {
            throw new ArgumentException(
                $"Point span must be {variableCount * ScalarSize} bytes for variableCount = {variableCount}; received {point.Length}.",
                nameof(point));
        }

        if(result.Length != ScalarSize)
        {
            throw new ArgumentException($"Result span must be {ScalarSize} bytes; received {result.Length}.", nameof(result));
        }

        if(variableCount == 0)
        {
            //An MLE in zero variables has a single evaluation; that is the answer.
            evaluations.CopyTo(result);

            return;
        }

        //One working buffer folded into its own prefix per round — the fold's
        //forward writes make this safe, exactly as the sumcheck drivers use it.
        int bufferBytes = evaluationCount * ScalarSize;
        using IMemoryOwner<byte> bufferOwner = pool.Rent(bufferBytes);
        Span<byte> buffer = bufferOwner.Memory.Span[..bufferBytes];
        evaluations.CopyTo(buffer);

        for(int round = 0; round < variableCount; round++)
        {
            int currentVariableCount = variableCount - round;
            int sourceBytes = (1 << currentVariableCount) * ScalarSize;
            FoldCore(
                buffer[..sourceBytes],
                point.Slice(round * ScalarSize, ScalarSize),
                buffer[..(sourceBytes / 2)],
                currentVariableCount,
                curve,
                add,
                subtract,
                batchMultiply,
                pool);
        }

        buffer[..ScalarSize].CopyTo(result);
    }


    private static void Fold(
        ReadOnlySpan<byte> originalEvaluations,
        ReadOnlySpan<byte> challenge,
        Span<byte> foldedEvaluations,
        int variableCount,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarBatchMultiplyDelegate batchMultiply,
        SensitiveMemoryPool<byte> pool)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.MleFold, curve);
        FoldCore(originalEvaluations, challenge, foldedEvaluations, variableCount, curve, add, subtract, batchMultiply, pool);
    }


    //The fold body without the telemetry bump, shared by the delegate-facing
    //fold (one bump per call) and the evaluate (one MleEvaluate bump total,
    //matching the reference's accounting).
    private static void FoldCore(
        ReadOnlySpan<byte> originalEvaluations,
        ReadOnlySpan<byte> challenge,
        Span<byte> foldedEvaluations,
        int variableCount,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarBatchMultiplyDelegate batchMultiply,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(variableCount, 1);
        int pairCount = 1 << (variableCount - 1);
        if(originalEvaluations.Length != 2 * pairCount * ScalarSize)
        {
            throw new ArgumentException(
                $"Evaluations span must be {2 * pairCount * ScalarSize} bytes for variableCount = {variableCount}; received {originalEvaluations.Length}.",
                nameof(originalEvaluations));
        }

        if(challenge.Length != ScalarSize)
        {
            throw new ArgumentException($"Challenge must be one scalar of {ScalarSize} bytes; received {challenge.Length}.", nameof(challenge));
        }

        if(foldedEvaluations.Length < pairCount * ScalarSize)
        {
            throw new ArgumentException(
                $"Folded span must hold at least {pairCount * ScalarSize} bytes; received {foldedEvaluations.Length}.",
                nameof(foldedEvaluations));
        }

        int blockSize = Math.Min(pairCount, BatchBlockPairCount);
        int columnBytes = blockSize * ScalarSize;
        using IMemoryOwner<byte> columnsOwner = pool.Rent(2 * columnBytes);
        Span<byte> columns = columnsOwner.Memory.Span[..(2 * columnBytes)];
        Span<byte> differences = columns[..columnBytes];
        Span<byte> broadcast = columns.Slice(columnBytes, columnBytes);
        for(int j = 0; j < blockSize; j++)
        {
            challenge.CopyTo(broadcast.Slice(j * ScalarSize, ScalarSize));
        }

        for(int blockStart = 0; blockStart < pairCount; blockStart += blockSize)
        {
            int n = Math.Min(blockSize, pairCount - blockStart);
            int usedBytes = n * ScalarSize;

            for(int j = 0; j < n; j++)
            {
                int low = 2 * (blockStart + j) * ScalarSize;
                subtract(
                    originalEvaluations.Slice(low + ScalarSize, ScalarSize),
                    originalEvaluations.Slice(low, ScalarSize),
                    differences.Slice(j * ScalarSize, ScalarSize),
                    curve);
            }

            batchMultiply(broadcast[..usedBytes], differences[..usedBytes], differences[..usedBytes], n, curve);

            for(int j = 0; j < n; j++)
            {
                int i = blockStart + j;
                add(
                    originalEvaluations.Slice(2 * i * ScalarSize, ScalarSize),
                    differences.Slice(j * ScalarSize, ScalarSize),
                    foldedEvaluations.Slice(i * ScalarSize, ScalarSize),
                    curve);
            }
        }
    }
}
