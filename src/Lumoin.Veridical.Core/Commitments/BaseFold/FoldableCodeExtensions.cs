using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Encoding and folding operations on a <see cref="FoldableCode"/>. Encoding
/// maps a message to its codeword via the recursive BaseFold algorithm;
/// folding collapses a codeword one layer under a challenge, the operation the
/// IOPP repeats round by round.
/// </summary>
/// <remarks>
/// Implements Protocol 1 and the fold of Zeilberger, Chen, Fisch (CRYPTO 2024,
/// IACR ePrint 2023/1705). Structural inspiration only, no code dependency.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FoldableCodeExtensions
{
    private const int ScalarSize = Scalar.SizeBytes;


    extension(FoldableCode code)
    {
        /// <summary>
        /// Encodes <paramref name="message"/> (the code's <c>k_d</c> message
        /// elements) into <paramref name="codeword"/> (its <c>n_d</c> codeword
        /// elements) by the recursive rule
        /// <c>Enc_d(m_l, m_r) = (l + t∘r, l − t∘r)</c>, with the base case the
        /// repetition encoding of the single element.
        /// </summary>
        /// <param name="message">The message; exactly <c>MessageLength · 32</c> bytes.</param>
        /// <param name="codeword">The destination codeword; exactly <c>CodewordLength · 32</c> bytes.</param>
        /// <param name="scalarAdd">Scalar-add backend.</param>
        /// <param name="scalarSubtract">Scalar-subtract backend.</param>
        /// <param name="scalarMultiply">Scalar-multiply backend.</param>
        /// <param name="pool">The pool to rent recursion scratch from.</param>
        /// <param name="batch">Optional batch-multiply backend: each layer's <c>t∘r</c> products run as one batched call over the already-contiguous diagonal and right half — byte-identical results; <see langword="null"/> runs the per-element path.</param>
        /// <exception cref="ArgumentNullException">When <paramref name="code"/> or a backend or the pool is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the message or codeword length does not match the code's parameters.</exception>
        public void Encode(
            ReadOnlySpan<byte> message,
            Span<byte> codeword,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            ArgumentNullException.ThrowIfNull(code);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(pool);

            int expectedMessage = code.Parameters.MessageLength * ScalarSize;
            int expectedCodeword = code.Parameters.CodewordLength * ScalarSize;
            if(message.Length != expectedMessage)
            {
                throw new ArgumentException($"Message must be {expectedMessage} bytes; received {message.Length}.", nameof(message));
            }

            if(codeword.Length != expectedCodeword)
            {
                throw new ArgumentException($"Codeword must be {expectedCodeword} bytes; received {codeword.Length}.", nameof(codeword));
            }

            EncodeLayer(code, message, code.Parameters.LayerCount, codeword, scalarAdd, scalarSubtract, scalarMultiply, code.Parameters.Curve, pool, batch);
        }


        /// <summary>
        /// Folds <paramref name="codeword"/> — a codeword of the layer-
        /// <paramref name="level"/> code — into <paramref name="folded"/>, a
        /// codeword of the layer-<c>(level − 1)</c> code, under
        /// <paramref name="challenge"/>. The result is
        /// <c>Enc_{level-1}(m_l + α·m_r)</c> when the input encodes
        /// <c>(m_l, m_r)</c>: recovering <c>l = (w₁+w₂)/2</c> and
        /// <c>r = (w₁−w₂)/(2t)</c>, the fold returns <c>l + α·r</c>.
        /// </summary>
        /// <param name="codeword">The codeword to fold; <c>n_level · 32</c> bytes.</param>
        /// <param name="level">The current layer (in <c>[1, LayerCount]</c>).</param>
        /// <param name="challenge">The fold challenge α; one scalar (32 bytes).</param>
        /// <param name="folded">The destination half-length codeword; <c>n_{level-1} · 32</c> bytes.</param>
        /// <param name="scalarAdd">Scalar-add backend.</param>
        /// <param name="scalarSubtract">Scalar-subtract backend.</param>
        /// <param name="scalarMultiply">Scalar-multiply backend.</param>
        /// <param name="scalarInvert">Scalar-invert backend (for the factor 2 and the diagonal entries).</param>
        /// <param name="batch">Optional batch-multiply backend; requires <paramref name="batchPool"/>. The per-position products run over the already-contiguous halves and inverse diagonal, with the challenge folded into one broadcast factor <c>α·2⁻¹</c> — byte-identical results by field associativity.</param>
        /// <param name="batchPool">The pool for the batched path's column scratch; required when <paramref name="batch"/> is present.</param>
        /// <exception cref="ArgumentNullException">When <paramref name="code"/> or a backend is <see langword="null"/>, or <paramref name="batch"/> is present without <paramref name="batchPool"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="level"/> is outside <c>[1, LayerCount]</c>.</exception>
        /// <exception cref="ArgumentException">When a length does not match the code's parameters.</exception>
        public void Fold(
            ReadOnlySpan<byte> codeword,
            int level,
            ReadOnlySpan<byte> challenge,
            Span<byte> folded,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarArithmeticBackend? batch = null,
            BaseMemoryPool? batchPool = null)
        {
            if(batch is not null)
            {
                ArgumentNullException.ThrowIfNull(batchPool);
            }

            ArgumentNullException.ThrowIfNull(code);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentOutOfRangeException.ThrowIfLessThan(level, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(level, code.Parameters.LayerCount);

            CurveParameterSet curve = code.Parameters.Curve;
            int baseUnit = code.Parameters.InverseRate * code.Parameters.BaseDimension;
            int halfCount = baseUnit << (level - 1);

            if(challenge.Length != ScalarSize)
            {
                throw new ArgumentException($"Challenge must be one scalar of {ScalarSize} bytes; received {challenge.Length}.", nameof(challenge));
            }

            if(codeword.Length != 2 * halfCount * ScalarSize)
            {
                throw new ArgumentException($"Codeword must be {2 * halfCount * ScalarSize} bytes at level {level}; received {codeword.Length}.", nameof(codeword));
            }

            if(folded.Length != halfCount * ScalarSize)
            {
                throw new ArgumentException($"Folded codeword must be {halfCount * ScalarSize} bytes; received {folded.Length}.", nameof(folded));
            }

            //The diagonal inverses and 2^{-1} come from the code's lazily-built
            //fold tables — one Montgomery batch inversion on the first fold
            //instead of one field inversion per position per opening.
            code.EnsureFoldTablesBuilt(scalarMultiply, scalarInvert);
            ReadOnlySpan<byte> diagonalInverse = code.GetDiagonalInverse(level - 1);
            ReadOnlySpan<byte> half = code.GetHalfScalar();

            ReadOnlySpan<byte> firstHalf = codeword[..(halfCount * ScalarSize)];
            ReadOnlySpan<byte> secondHalf = codeword[(halfCount * ScalarSize)..];

            if(batch is not null)
            {
                BaseMemoryPool columnPool = batchPool ?? throw new ArgumentNullException(nameof(batchPool));
                FoldBatched(firstHalf, secondHalf, diagonalInverse, challenge, half, halfCount, folded, scalarAdd, scalarSubtract, scalarMultiply, batch, curve, columnPool);

                return;
            }

            for(int j = 0; j < halfCount; j++)
            {
                ReadOnlySpan<byte> w1 = firstHalf.Slice(j * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> w2 = secondHalf.Slice(j * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> tInverse = diagonalInverse.Slice(j * ScalarSize, ScalarSize);
                Span<byte> output = folded.Slice(j * ScalarSize, ScalarSize);

                FoldOnePosition(w1, w2, tInverse, challenge, half, curve, scalarAdd, scalarSubtract, scalarMultiply, output);
            }
        }
    }


    //Pairs per batched block, matching the sumcheck convention: bounds the
    //pooled column scratch while keeping each BatchMultiply call long enough
    //to amortise its lane setup.
    private const int BatchBlockPairCount = 1024;


    //The batched fold: sums and differences form contiguous columns (the input
    //halves and the inverse diagonal already are contiguous), l = sums·2⁻¹ and
    //the r-term reassociates as (diffs∘t⁻¹)·(α·2⁻¹) — three batched products
    //per block instead of four per position, the same field values either way.
    private static void FoldBatched(
        ReadOnlySpan<byte> firstHalf,
        ReadOnlySpan<byte> secondHalf,
        ReadOnlySpan<byte> diagonalInverse,
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> half,
        int halfCount,
        Span<byte> folded,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarArithmeticBackend batch,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        //α·2⁻¹ once; broadcast per block.
        Span<byte> alphaHalf = stackalloc byte[ScalarSize];
        scalarMultiply(challenge, half, alphaHalf, curve);

        int blockSize = Math.Min(halfCount, BatchBlockPairCount);
        int columnBytes = blockSize * ScalarSize;
        using IMemoryOwner<byte> columnsOwner = pool.Rent(3 * columnBytes);
        Span<byte> columns = columnsOwner.Memory.Span[..(3 * columnBytes)];
        Span<byte> sums = columns[..columnBytes];
        Span<byte> diffs = columns.Slice(1 * columnBytes, columnBytes);
        Span<byte> broadcast = columns.Slice(2 * columnBytes, columnBytes);

        for(int blockStart = 0; blockStart < halfCount; blockStart += blockSize)
        {
            int n = Math.Min(blockSize, halfCount - blockStart);
            int usedBytes = n * ScalarSize;
            int sourceOffset = blockStart * ScalarSize;

            //The input halves are contiguous: sums and differences are
            //whole-block batch calls, no gather.
            batch.BatchAdd(firstHalf.Slice(sourceOffset, usedBytes), secondHalf.Slice(sourceOffset, usedBytes), sums[..usedBytes], n, curve);
            batch.BatchSubtract(firstHalf.Slice(sourceOffset, usedBytes), secondHalf.Slice(sourceOffset, usedBytes), diffs[..usedBytes], n, curve);

            //l = sums·2⁻¹.
            for(int j = 0; j < n; j++)
            {
                half.CopyTo(broadcast.Slice(j * ScalarSize, ScalarSize));
            }

            batch.BatchMultiply(sums[..usedBytes], broadcast[..usedBytes], sums[..usedBytes], n, curve);

            //r-term = (diffs∘t⁻¹)·(α·2⁻¹).
            batch.BatchMultiply(diffs[..usedBytes], diagonalInverse.Slice(sourceOffset, usedBytes), diffs[..usedBytes], n, curve);
            for(int j = 0; j < n; j++)
            {
                alphaHalf.CopyTo(broadcast.Slice(j * ScalarSize, ScalarSize));
            }

            batch.BatchMultiply(diffs[..usedBytes], broadcast[..usedBytes], diffs[..usedBytes], n, curve);

            batch.BatchAdd(sums[..usedBytes], diffs[..usedBytes], folded.Slice(sourceOffset, usedBytes), n, curve);
        }
    }


    /// <summary>
    /// Folds a single codeword position the same way <c>Fold</c> folds every
    /// position: given the two layer-<paramref name="level"/> entries that
    /// share a fold pair (<paramref name="first"/> at index
    /// <paramref name="positionInLowerLayer"/>, <paramref name="second"/> at
    /// that index plus the lower-layer length), returns the layer-
    /// <c>(level-1)</c> entry <c>l + α·r</c> at
    /// <paramref name="positionInLowerLayer"/>. The IOPP verifier uses this to
    /// recompute one folded value per queried position without folding the
    /// whole codeword.
    /// </summary>
    /// <param name="code">The code whose diagonal supplies the fold weight.</param>
    /// <param name="level">The current layer (in <c>[1, LayerCount]</c>); the result belongs to layer <c>level - 1</c>.</param>
    /// <param name="positionInLowerLayer">The position in the layer-<c>(level-1)</c> codeword (in <c>[0, n_{level-1})</c>).</param>
    /// <param name="first">The layer-<paramref name="level"/> entry at <paramref name="positionInLowerLayer"/>; one scalar.</param>
    /// <param name="second">The layer-<paramref name="level"/> entry at <paramref name="positionInLowerLayer"/> plus the lower-layer length; one scalar.</param>
    /// <param name="challenge">The fold challenge α; one scalar.</param>
    /// <param name="folded">The destination for the single folded scalar.</param>
    /// <param name="scalarAdd">Scalar-add backend.</param>
    /// <param name="scalarSubtract">Scalar-subtract backend.</param>
    /// <param name="scalarMultiply">Scalar-multiply backend.</param>
    /// <param name="scalarInvert">Scalar-invert backend.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="code"/> or a backend is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="level"/> or <paramref name="positionInLowerLayer"/> is out of range.</exception>
    internal static void FoldPosition(
        FoldableCode code,
        int level,
        int positionInLowerLayer,
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        ReadOnlySpan<byte> challenge,
        Span<byte> folded,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarSubtract);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentOutOfRangeException.ThrowIfLessThan(level, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(level, code.Parameters.LayerCount);

        CurveParameterSet curve = code.Parameters.Curve;
        int lowerLength = (code.Parameters.InverseRate * code.Parameters.BaseDimension) << (level - 1);
        ArgumentOutOfRangeException.ThrowIfNegative(positionInLowerLayer);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(positionInLowerLayer, lowerLength);

        code.EnsureFoldTablesBuilt(scalarMultiply, scalarInvert);
        ReadOnlySpan<byte> tInverse = code.GetDiagonalInverse(level - 1).Slice(positionInLowerLayer * ScalarSize, ScalarSize);

        FoldOnePosition(first, second, tInverse, challenge, code.GetHalfScalar(), curve, scalarAdd, scalarSubtract, scalarMultiply, folded);
    }


    //The per-position fold shared by Fold (every position) and FoldPosition (one
    //position): l = (w1+w2)·half, r = (w1-w2)·half·t^{-1}, output = l + α·r.
    //The diagonal inverse comes precomputed from the code's fold tables.
    private static void FoldOnePosition(
        ReadOnlySpan<byte> w1,
        ReadOnlySpan<byte> w2,
        ReadOnlySpan<byte> tInverse,
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> half,
        CurveParameterSet curve,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        Span<byte> output)
    {
        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];

        //l = (w1 + w2) · half.
        scalarAdd(w1, w2, sum, curve);
        scalarMultiply(sum, half, sum, curve);

        //r = (w1 − w2) · half · t^{-1}.
        scalarSubtract(w1, w2, difference, curve);
        scalarMultiply(difference, half, difference, curve);
        scalarMultiply(difference, tInverse, difference, curve);

        //folded = l + α · r.
        scalarMultiply(challenge, difference, difference, curve);
        scalarAdd(sum, difference, output, curve);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Recursion scratch buffers are released by their using declarations before the call returns.")]
    private static void EncodeLayer(
        FoldableCode code,
        ReadOnlySpan<byte> message,
        int level,
        Span<byte> output,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch)
    {
        if(level == 0)
        {
            //Base case: the [c, 1, c] repetition code. The single message
            //element is repeated across all c codeword positions.
            for(int position = 0; position < output.Length; position += ScalarSize)
            {
                message.CopyTo(output.Slice(position, ScalarSize));
            }

            return;
        }

        int halfMessage = message.Length / 2;
        int halfOutput = output.Length / 2;
        ReadOnlySpan<byte> messageLeft = message[..halfMessage];
        ReadOnlySpan<byte> messageRight = message[halfMessage..];

        using IMemoryOwner<byte> leftOwner = pool.Rent(halfOutput);
        using IMemoryOwner<byte> rightOwner = pool.Rent(halfOutput);
        Span<byte> left = leftOwner.Memory.Span[..halfOutput];
        Span<byte> right = rightOwner.Memory.Span[..halfOutput];

        EncodeLayer(code, messageLeft, level - 1, left, scalarAdd, scalarSubtract, scalarMultiply, curve, pool, batch);
        EncodeLayer(code, messageRight, level - 1, right, scalarAdd, scalarSubtract, scalarMultiply, curve, pool, batch);

        //This layer combines the two level-(level-1) encodings with T_{level-1}.
        ReadOnlySpan<byte> diagonal = code.GetDiagonal(level - 1);
        int halfCount = halfOutput / ScalarSize;

        if(batch is not null)
        {
            //The diagonal and the right half are both contiguous, so the whole
            //layer's t∘r products run as one batched call with no gather.
            using IMemoryOwner<byte> scaledOwner = pool.Rent(halfOutput);
            Span<byte> scaled = scaledOwner.Memory.Span[..halfOutput];
            batch.BatchMultiply(diagonal, right, scaled, halfCount, curve);
            for(int j = 0; j < halfCount; j++)
            {
                ReadOnlySpan<byte> leftElement = left.Slice(j * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> scaledElement = scaled.Slice(j * ScalarSize, ScalarSize);
                scalarAdd(leftElement, scaledElement, output.Slice(j * ScalarSize, ScalarSize), curve);
                scalarSubtract(leftElement, scaledElement, output.Slice(halfOutput + (j * ScalarSize), ScalarSize), curve);
            }

            return;
        }

        Span<byte> scaledRight = stackalloc byte[ScalarSize];
        for(int j = 0; j < halfCount; j++)
        {
            ReadOnlySpan<byte> leftElement = left.Slice(j * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> rightElement = right.Slice(j * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> t = diagonal.Slice(j * ScalarSize, ScalarSize);

            //t∘r for this position.
            scalarMultiply(t, rightElement, scaledRight, curve);

            //First half: l + t∘r. Second half: l − t∘r.
            scalarAdd(leftElement, scaledRight, output.Slice(j * ScalarSize, ScalarSize), curve);
            scalarSubtract(leftElement, scaledRight, output.Slice(halfOutput + (j * ScalarSize), ScalarSize), curve);
        }
    }
}
