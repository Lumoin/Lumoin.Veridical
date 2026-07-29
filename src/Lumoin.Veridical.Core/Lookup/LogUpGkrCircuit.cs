using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The LogUp-GKR fraction circuit (Papini–Haböck, ePrint 2023/1284): the
/// input-layer fractions of the log-derivative identity and the binary tree
/// of projective fraction additions
/// <c>(a₀,b₀) + (a₁,b₁) = (a₀·b₁ + a₁·b₀, b₀·b₁)</c> that sums them without
/// a single field inversion.
/// </summary>
/// <remarks>
/// <para>
/// Leaf layout over <c>{0,1}^(n+k)</c> with the selector bits above the row
/// bits (leaf index = selector·2^n + row): selector 0 is the table slot
/// (numerator <c>m(row)</c>, denominator <c>α − t(row)</c>), selectors
/// <c>1..M</c> are the witness columns (numerator <c>−1</c>, denominator
/// <c>α − w_s(row)</c>), and selectors above <c>M</c> carry the neutral
/// fraction <c>0/1</c> — it adds nothing and its denominator never vanishes,
/// which is how a witness-column count that is not one below a power of two
/// pads soundly.
/// </para>
/// <para>
/// Tree levels combine the pair <c>(j, j + half)</c> — splitting the top
/// remaining index bit — so the protocol's terminal evaluation point arrives
/// with its first <c>n</c> coordinates being the row point in the codebase's
/// standard variable order, directly usable as the commitment opening point.
/// </para>
/// </remarks>
internal static class LogUpGkrCircuit
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Builds the input-layer numerator and denominator tables over the
    /// extended hypercube.
    /// </summary>
    /// <param name="tableEvaluations">The table column, <c>2^rowVariableCount × 32</c> bytes.</param>
    /// <param name="witnessEvaluations">The witness columns concatenated.</param>
    /// <param name="multiplicityEvaluations">The multiplicity column.</param>
    /// <param name="denominatorChallenge">The challenge <c>α</c>.</param>
    /// <param name="rowVariableCount">The row hypercube variable count <c>n</c>.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>.</param>
    /// <param name="selectorVariableCount">The selector variable count <c>k = ⌈log2(M+1)⌉</c>.</param>
    /// <param name="numerators">Receives the <c>2^(n+k)</c> numerator leaves.</param>
    /// <param name="denominators">Receives the <c>2^(n+k)</c> denominator leaves.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="curve">The curve whose scalar field the columns live in.</param>
    public static void BuildLeaves(
        ReadOnlySpan<byte> tableEvaluations,
        ReadOnlySpan<byte> witnessEvaluations,
        ReadOnlySpan<byte> multiplicityEvaluations,
        ReadOnlySpan<byte> denominatorChallenge,
        int rowVariableCount,
        int witnessColumnCount,
        int selectorVariableCount,
        Span<byte> numerators,
        Span<byte> denominators,
        ScalarSubtractDelegate subtract,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(subtract);

        int rowCount = 1 << rowVariableCount;
        int selectorCount = 1 << selectorVariableCount;
        int leafCount = rowCount * selectorCount;
        if(numerators.Length != leafCount * ScalarSize || denominators.Length != leafCount * ScalarSize)
        {
            throw new ArgumentException($"Leaf tables over {leafCount} entries need {leafCount * ScalarSize} bytes each; received {numerators.Length} and {denominators.Length}.");
        }

        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(one);
        Span<byte> minusOne = stackalloc byte[ScalarSize];
        subtract(zero, one, minusOne, curve);

        for(int selector = 0; selector < selectorCount; selector++)
        {
            Span<byte> numeratorBlock = numerators.Slice(selector * rowCount * ScalarSize, rowCount * ScalarSize);
            Span<byte> denominatorBlock = denominators.Slice(selector * rowCount * ScalarSize, rowCount * ScalarSize);
            if(selector == 0)
            {
                multiplicityEvaluations.CopyTo(numeratorBlock);
                for(int row = 0; row < rowCount; row++)
                {
                    subtract(denominatorChallenge, tableEvaluations.Slice(row * ScalarSize, ScalarSize), denominatorBlock.Slice(row * ScalarSize, ScalarSize), curve);
                }
            }
            else if(selector <= witnessColumnCount)
            {
                ReadOnlySpan<byte> witnessColumn = witnessEvaluations.Slice((selector - 1) * rowCount * ScalarSize, rowCount * ScalarSize);
                for(int row = 0; row < rowCount; row++)
                {
                    minusOne.CopyTo(numeratorBlock.Slice(row * ScalarSize, ScalarSize));
                    subtract(denominatorChallenge, witnessColumn.Slice(row * ScalarSize, ScalarSize), denominatorBlock.Slice(row * ScalarSize, ScalarSize), curve);
                }
            }
            else
            {
                //Neutral padding fraction 0/1 for selector slots past the
                //witness columns.
                for(int row = 0; row < rowCount; row++)
                {
                    zero.CopyTo(numeratorBlock.Slice(row * ScalarSize, ScalarSize));
                    one.CopyTo(denominatorBlock.Slice(row * ScalarSize, ScalarSize));
                }
            }
        }
    }


    /// <summary>
    /// Builds every tree layer from the leaves down to layer 1, storing the
    /// layers back to back: layer ℓ holds <c>2^ℓ</c> numerator and
    /// <c>2^ℓ</c> denominator entries.
    /// </summary>
    /// <param name="leafNumerators">The input-layer numerators, <c>2^totalVariableCount</c> entries.</param>
    /// <param name="leafDenominators">The input-layer denominators.</param>
    /// <param name="totalVariableCount">The extended hypercube variable count <c>ν = n + k</c>.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the tree lives in.</param>
    /// <param name="pool">The pool the layer buffers are rented from.</param>
    /// <returns>Layer buffers indexed 1..ν−1 (index 0 unused); each buffer holds [numerators | denominators] of its layer. Ownership transfers to the caller.</returns>
    public static IMemoryOwner<byte>[] BuildLayers(
        ReadOnlySpan<byte> leafNumerators,
        ReadOnlySpan<byte> leafDenominators,
        int totalVariableCount,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(totalVariableCount, 2);

        IMemoryOwner<byte>[] layers = new IMemoryOwner<byte>[totalVariableCount];
        try
        {
            ReadOnlySpan<byte> upperNumerators = leafNumerators;
            ReadOnlySpan<byte> upperDenominators = leafDenominators;
            for(int layer = totalVariableCount - 1; layer >= 1; layer--)
            {
                int size = 1 << layer;
                layers[layer] = pool.Rent(2 * size * ScalarSize);
                Span<byte> numerators = layers[layer].Memory.Span[..(size * ScalarSize)];
                Span<byte> denominators = layers[layer].Memory.Span.Slice(size * ScalarSize, size * ScalarSize);

                CombineLayer(upperNumerators, upperDenominators, size, numerators, denominators, add, multiply, curve);

                upperNumerators = numerators;
                upperDenominators = denominators;
            }

            return layers;
        }
        catch
        {
            foreach(IMemoryOwner<byte>? layer in layers)
            {
                layer?.Dispose();
            }
            throw;
        }
    }


    //One projective addition level: child pair (j, j + half) of the upper
    //layer combines into node j — the top remaining index bit is split.
    private static void CombineLayer(
        ReadOnlySpan<byte> upperNumerators,
        ReadOnlySpan<byte> upperDenominators,
        int size,
        Span<byte> numerators,
        Span<byte> denominators,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> crossLow = stackalloc byte[ScalarSize];
        Span<byte> crossHigh = stackalloc byte[ScalarSize];
        for(int j = 0; j < size; j++)
        {
            ReadOnlySpan<byte> lowNumerator = upperNumerators.Slice(j * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> highNumerator = upperNumerators.Slice((j + size) * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> lowDenominator = upperDenominators.Slice(j * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> highDenominator = upperDenominators.Slice((j + size) * ScalarSize, ScalarSize);

            multiply(lowNumerator, highDenominator, crossLow, curve);
            multiply(highNumerator, lowDenominator, crossHigh, curve);
            add(crossLow, crossHigh, numerators.Slice(j * ScalarSize, ScalarSize), curve);
            multiply(lowDenominator, highDenominator, denominators.Slice(j * ScalarSize, ScalarSize), curve);
        }
    }
}
