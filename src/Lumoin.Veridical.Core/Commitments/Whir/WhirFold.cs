using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The WHIR folding operator (WHIR Definition 4.14):
/// <c>Fold(f, α)(x²) = (f(x) + f(−x))/2 + α·(f(x) − f(−x))/(2x)</c>, iterated
/// per challenge coordinate. Both sides of the protocol fold with it in their
/// own representation: the prover on coefficient vectors, where folding the
/// first variable is the even/odd interleave <c>c'[j] = c[2j] + α·c[2j+1]</c>
/// and costs no inversions, and the verifier on a queried
/// <c>2^k</c>-coset value block, where the iterated two-point butterfly
/// reconstructs one evaluation of <c>Fold(f, α)</c> from the block.
/// </summary>
/// <remarks>
/// The two paths compute the same function (WHIR Claim 4.15:
/// <c>Fold(f, α)</c> of a codeword with multilinear extension <c>f̂</c> is
/// the codeword of <c>f̂(α, ·)</c> on the squared domain), which is the
/// agreement gate the fold tests pin: encoding a folded coefficient vector
/// must equal butterfly-folding the encoded blocks, point for point.
/// </remarks>
public static class WhirFold
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// Caps the coset exponent so <c>1 &lt;&lt; foldingParameter</c> and
    /// every derived byte length stay well inside the positive int range;
    /// every wired schedule keeps <c>k</c> in single digits.
    /// </summary>
    private const int MaximumFoldingParameter = 30;


    /// <summary>
    /// Folds the first variable out of a multilinear coefficient vector:
    /// <c>destination[j] = coefficients[2j] + challenge·coefficients[2j+1]</c>,
    /// producing the coefficient vector of <c>f̂(challenge, ·)</c>. The
    /// destination may alias the source's first half for in-place folding.
    /// </summary>
    /// <param name="coefficients">The coefficient vector; an even element count.</param>
    /// <param name="challenge">The folding challenge <c>α</c>, one element.</param>
    /// <param name="destination">Receives half as many elements as the source carries.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public static void FoldCoefficients(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> challenge,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ThrowIfNotOneElement(challenge, nameof(challenge));
        int pairCount = coefficients.Length / (2 * ScalarSize);
        if(coefficients.Length == 0 || coefficients.Length % (2 * ScalarSize) != 0)
        {
            throw new ArgumentException(
                $"The coefficient vector must be a positive even count of {ScalarSize}-byte elements; received {coefficients.Length} bytes.",
                nameof(coefficients));
        }

        if(destination.Length != pairCount * ScalarSize)
        {
            throw new ArgumentException(
                $"The destination must carry {pairCount} elements; received {destination.Length} bytes.",
                nameof(destination));
        }

        Span<byte> term = stackalloc byte[ScalarSize];
        for(int j = 0; j < pairCount; j++)
        {
            //Ascending order keeps the write at j behind the reads at 2j and
            //2j + 1, so folding into the source's own first half is safe.
            multiply(coefficients.Slice(((2 * j) + 1) * ScalarSize, ScalarSize), challenge, term, curve);
            add(coefficients.Slice(2 * j * ScalarSize, ScalarSize), term, destination.Slice(j * ScalarSize, ScalarSize), curve);
        }
    }


    /// <summary>
    /// Evaluates <c>Fold(f, challenges)</c> at the block's query point from
    /// the queried coset values: position <c>j</c> of
    /// <paramref name="blockValues"/> must hold <c>f(basePoint·strideRoot^j)</c>,
    /// the layout <see cref="WhirCosetEncoder.EncodeToCosetLeaves"/> commits.
    /// Runs the definition's butterfly once per challenge, consuming the block
    /// in place; the single surviving element is the result.
    /// </summary>
    /// <param name="blockValues">The <c>2^k</c> queried values; overwritten as folding scratch.</param>
    /// <param name="foldingParameter">The coset exponent <c>k</c>, at least 1.</param>
    /// <param name="challenges">The <c>k</c> folding challenges, first variable first.</param>
    /// <param name="basePoint">The block's base point <c>ω^s</c>, one element.</param>
    /// <param name="strideRoot">The order-<c>2^k</c> root of unity <c>ω^(2^(n-k))</c> stepping through the block, one element.</param>
    /// <param name="result">Receives the folded evaluation, one element.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="invert">Scalar inversion (for the per-pair <c>1/(2x)</c> factors).</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <param name="pool">The pool the point column rents from.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="foldingParameter"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public static void FoldCosetBlock(
        Span<byte> blockValues,
        int foldingParameter,
        ReadOnlySpan<byte> challenges,
        ReadOnlySpan<byte> basePoint,
        ReadOnlySpan<byte> strideRoot,
        Span<byte> result,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(foldingParameter, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(foldingParameter, MaximumFoldingParameter);
        ThrowIfNotOneElement(basePoint, nameof(basePoint));
        ThrowIfNotOneElement(strideRoot, nameof(strideRoot));
        ThrowIfNotOneElement(result, nameof(result));

        int blockSize = 1 << foldingParameter;
        if(blockValues.Length != blockSize * ScalarSize)
        {
            throw new ArgumentException(
                $"The block must carry {blockSize} elements; received {blockValues.Length} bytes.",
                nameof(blockValues));
        }

        if(challenges.Length != foldingParameter * ScalarSize)
        {
            throw new ArgumentException(
                $"The challenge vector must carry {foldingParameter} elements; received {challenges.Length} bytes.",
                nameof(challenges));
        }

        //The block's points p[j] = basePoint·strideRoot^j; only the first half
        //is materialised because the pair partner of p[j] is p[j + half] = −p[j]
        //(strideRoot^half is the unique order-2 element of the 2-group, −1).
        int halfSize = blockSize / 2;
        using IMemoryOwner<byte> pointsOwner = pool.Rent(halfSize * ScalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(halfSize * ScalarSize)];
        basePoint.CopyTo(points[..ScalarSize]);
        for(int j = 1; j < halfSize; j++)
        {
            multiply(points.Slice((j - 1) * ScalarSize, ScalarSize), strideRoot, points.Slice(j * ScalarSize, ScalarSize), curve);
        }

        Span<byte> twoInverse = stackalloc byte[ScalarSize];
        WriteCanonicalUInt(2, twoInverse);
        invert(twoInverse, twoInverse, curve);

        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> pointInverse = stackalloc byte[ScalarSize];
        for(int level = 0; level < foldingParameter; level++)
        {
            int half = blockSize >> (level + 1);
            ReadOnlySpan<byte> challenge = challenges.Slice(level * ScalarSize, ScalarSize);
            for(int j = 0; j < half; j++)
            {
                Span<byte> low = blockValues.Slice(j * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> high = blockValues.Slice((j + half) * ScalarSize, ScalarSize);
                Span<byte> point = points.Slice(j * ScalarSize, ScalarSize);

                //(f(x) + f(−x))/2 + α·(f(x) − f(−x))/(2x), folded as
                //((sum) + α·(difference)/x)·(1/2) to spend one inversion.
                add(low, high, sum, curve);
                subtract(low, high, difference, curve);
                invert(point, pointInverse, curve);
                multiply(difference, pointInverse, difference, curve);
                multiply(difference, challenge, difference, curve);
                add(sum, difference, sum, curve);
                multiply(sum, twoInverse, low, curve);

                //The next level's point over this pair is x².
                multiply(point, point, point, curve);
            }
        }

        blockValues[..ScalarSize].CopyTo(result);
    }


    /// <summary>
    /// Raises a domain root to a non-negative exponent by square-and-multiply:
    /// resolves a queried block index <c>s</c> to its base point <c>ω^s</c>.
    /// </summary>
    /// <param name="root">The domain root <c>ω</c>, one element.</param>
    /// <param name="exponent">The exponent, non-negative.</param>
    /// <param name="destination">Receives <c>ω^exponent</c>, one element.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The wired curve the delegate routes over.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="multiply"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="exponent"/> is negative.</exception>
    /// <exception cref="ArgumentException">When a span is not one element.</exception>
    public static void ComputeDomainPoint(
        ReadOnlySpan<byte> root,
        int exponent,
        Span<byte> destination,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfNegative(exponent);
        ThrowIfNotOneElement(root, nameof(root));
        ThrowIfNotOneElement(destination, nameof(destination));

        WriteCanonicalUInt(1, destination);
        if(exponent == 0)
        {
            return;
        }

        Span<byte> baseValue = stackalloc byte[ScalarSize];
        root.CopyTo(baseValue);
        for(int remaining = exponent; remaining != 0; remaining >>= 1)
        {
            if((remaining & 1) == 1)
            {
                multiply(destination, baseValue, destination, curve);
            }

            multiply(baseValue, baseValue, baseValue, curve);
        }
    }


    /// <summary>
    /// Rejects a span that is not exactly one field element wide.
    /// </summary>
    private static void ThrowIfNotOneElement(ReadOnlySpan<byte> span, string parameterName)
    {
        if(span.Length != ScalarSize)
        {
            throw new ArgumentException($"The value must be one {ScalarSize}-byte element; received {span.Length} bytes.", parameterName);
        }
    }


    /// <summary>
    /// Writes a small integer as a canonical big-endian field element.
    /// </summary>
    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
