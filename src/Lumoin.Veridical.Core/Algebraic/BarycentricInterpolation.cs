using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Univariate Lagrange interpolation over a prime field in the second
/// (true) barycentric form, on the consecutive integer node set
/// <c>{0, 1, …, nodeCount − 1}</c>. Given a polynomial of degree
/// <c>&lt; nodeCount</c> by its evaluations at those nodes, it evaluates the
/// polynomial at further integer points — exactly the "extend the evaluations"
/// map a systematic Reed–Solomon encoder needs.
/// </summary>
/// <remarks>
/// <para>
/// This is the field-agnostic, no-NTT realization: it needs only add, subtract,
/// multiply and invert over the field (supplied as delegates with their
/// <see cref="CurveParameterSet"/>), so it works over fields with no
/// smooth-order roots of unity — P-256's scalar/base field included — where an
/// FFT is unavailable.
/// </para>
/// <para>
/// Modular inversion dominates the cost over fields with no fast inverse (the
/// P-256 BigInteger reference's Fermat inversion is ~100× a multiply), so both
/// the weights and the per-point evaluation use <em>batched</em> inversion
/// (Montgomery's trick): a batch of <c>n</c> inverses costs one field inversion
/// plus O(n) multiplications. The consecutive-node weights additionally use the
/// closed form <c>w_i = (−1)^{nodeCount−1−i} / (i! · (nodeCount−1−i)!)</c>
/// — equal to <c>1 / ∏_{j≠i}(i − j)</c> — computed from factorials in O(nodeCount)
/// multiplications and a single batch inversion, rather than the O(nodeCount²)
/// product form. The codeword produced is identical to the naive form; this is a
/// pure speedup, not a protocol change. Weights depend only on <c>nodeCount</c>,
/// so <see cref="ComputeConsecutiveNodeWeights"/> is called once and reused
/// across every evaluation point. Evaluation points must be distinct from every
/// node — for the encoder they are, since the extension points start at
/// <c>nodeCount</c>. Node and point integers must be below the field order
/// (always true for the small domains used here).
/// </para>
/// </remarks>
public static class BarycentricInterpolation
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Computes the barycentric weights
    /// <c>w_i = 1 / ∏_{j≠i} (i − j)</c> for the consecutive nodes
    /// <c>{0, …, nodeCount − 1}</c>, via the factorial closed form and a single
    /// batched inversion.
    /// </summary>
    /// <param name="nodeCount">The number of nodes (the message length); at least 1.</param>
    /// <param name="weights">Receives <c>nodeCount</c> scalars (<c>nodeCount · 32</c> bytes).</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the factorial scratch from.</param>
    public static void ComputeConsecutiveNodeWeights(
        int nodeCount,
        Span<byte> weights,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(nodeCount, 1);
        if(weights.Length != nodeCount * ScalarSize)
        {
            throw new ArgumentException($"Weights must be {nodeCount * ScalarSize} bytes; received {weights.Length}.", nameof(weights));
        }

        //factorials[k] = k!, then batch-inverted in place to 1/k!.
        using IMemoryOwner<byte> factorialOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> factorials = factorialOwner.Memory.Span[..(nodeCount * ScalarSize)];
        WriteSmallInteger(1, factorials[..ScalarSize]);
        Span<byte> index = stackalloc byte[ScalarSize];
        for(int k = 1; k < nodeCount; k++)
        {
            WriteSmallInteger(k, index);
            multiply(factorials.Slice((k - 1) * ScalarSize, ScalarSize), index, factorials.Slice(k * ScalarSize, ScalarSize), curve);
        }

        using IMemoryOwner<byte> prefixOwner = pool.Rent(nodeCount * ScalarSize);
        BatchInvert(factorials, prefixOwner.Memory.Span[..(nodeCount * ScalarSize)], nodeCount, multiply, invert, curve);

        //w_i = (−1)^{nodeCount−1−i} · (1/i!) · (1/(nodeCount−1−i)!).
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        for(int i = 0; i < nodeCount; i++)
        {
            int complement = nodeCount - 1 - i;
            multiply(factorials.Slice(i * ScalarSize, ScalarSize), factorials.Slice(complement * ScalarSize, ScalarSize), product, curve);
            if((complement & 1) == 1)
            {
                subtract(zero, product, weights.Slice(i * ScalarSize, ScalarSize), curve);
            }
            else
            {
                product.CopyTo(weights.Slice(i * ScalarSize, ScalarSize));
            }
        }
    }


    /// <summary>
    /// Computes the barycentric weights <c>w_i = 1 / ∏_{j≠i} (x_i − x_j)</c> for the bit-pattern
    /// nodes <c>{0, …, nodeCount − 1}</c> over a binary field, where the node difference is
    /// <c>element(i ⊕ j)</c> — the factorial closed form of the integer domain does not apply in
    /// characteristic two, so the products are taken directly (O(nodeCount²) multiplications and
    /// one batched inversion). The evaluation routines are domain-agnostic: only the weights
    /// differ between the integer and binary domains.
    /// </summary>
    /// <param name="nodeCount">The number of nodes (the message length); at least 1.</param>
    /// <param name="weights">Receives <c>nodeCount</c> scalars (<c>nodeCount · 32</c> bytes).</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the inversion scratch from.</param>
    public static void ComputeBinaryNodeWeights(
        int nodeCount,
        Span<byte> weights,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(nodeCount, 1);
        if(weights.Length != nodeCount * ScalarSize)
        {
            throw new ArgumentException($"Weights must be {nodeCount * ScalarSize} bytes; received {weights.Length}.", nameof(weights));
        }

        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int i = 0; i < nodeCount; i++)
        {
            Span<byte> slot = weights.Slice(i * ScalarSize, ScalarSize);
            WriteSmallInteger(1, slot);
            for(int j = 0; j < nodeCount; j++)
            {
                if(j == i)
                {
                    continue;
                }

                WriteSmallInteger(i ^ j, difference);
                multiply(slot, difference, scratch, curve);
                scratch.CopyTo(slot);
            }
        }

        using IMemoryOwner<byte> prefixOwner = pool.Rent(nodeCount * ScalarSize);
        BatchInvert(weights, prefixOwner.Memory.Span[..(nodeCount * ScalarSize)], nodeCount, multiply, invert, curve);
    }


    /// <summary>
    /// Evaluates the interpolant at the consecutive integer points
    /// <c>{firstPoint, …, firstPoint + pointCount − 1}</c>.
    /// </summary>
    /// <param name="values">The <c>nodeCount</c> evaluations at the nodes (<c>nodeCount · 32</c> bytes).</param>
    /// <param name="weights">The weights from <see cref="ComputeConsecutiveNodeWeights"/>.</param>
    /// <param name="nodeCount">The number of nodes.</param>
    /// <param name="firstPoint">The first evaluation point; must be ≥ <paramref name="nodeCount"/> so no point coincides with a node.</param>
    /// <param name="pointCount">The number of consecutive points.</param>
    /// <param name="results">Receives <paramref name="pointCount"/> scalars.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the node-element and inversion scratch from.</param>
    public static void EvaluateAtConsecutivePoints(
        ReadOnlySpan<byte> values,
        ReadOnlySpan<byte> weights,
        int nodeCount,
        int firstPoint,
        int pointCount,
        Span<byte> results,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(firstPoint, nodeCount);
        ValidateEvaluateArguments(values, weights, nodeCount, pointCount, results, add, subtract, multiply, invert, pool);

        using IMemoryOwner<byte> nodeOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> nodes = nodeOwner.Memory.Span[..(nodeCount * ScalarSize)];
        for(int i = 0; i < nodeCount; i++)
        {
            WriteSmallInteger(i, nodes.Slice(i * ScalarSize, ScalarSize));
        }

        using IMemoryOwner<byte> reciprocalOwner = pool.Rent(nodeCount * ScalarSize);
        using IMemoryOwner<byte> prefixOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> reciprocals = reciprocalOwner.Memory.Span[..(nodeCount * ScalarSize)];
        Span<byte> prefix = prefixOwner.Memory.Span[..(nodeCount * ScalarSize)];
        for(int p = 0; p < pointCount; p++)
        {
            EvaluateSingle(values, weights, nodes, nodeCount, firstPoint + p, results.Slice(p * ScalarSize, ScalarSize), reciprocals, prefix, add, subtract, multiply, invert, curve);
        }
    }


    /// <summary>
    /// Evaluates the interpolant at an arbitrary set of integer points (e.g.
    /// the columns a verifier samples). Every point must differ from every node.
    /// </summary>
    /// <param name="values">The <c>nodeCount</c> evaluations at the nodes.</param>
    /// <param name="weights">The weights from <see cref="ComputeConsecutiveNodeWeights"/>.</param>
    /// <param name="nodeCount">The number of nodes.</param>
    /// <param name="points">The evaluation points; each must be ≥ <paramref name="nodeCount"/>.</param>
    /// <param name="results">Receives <c>points.Length</c> scalars.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the node-element and inversion scratch from.</param>
    public static void EvaluateAtPoints(
        ReadOnlySpan<byte> values,
        ReadOnlySpan<byte> weights,
        int nodeCount,
        ReadOnlySpan<int> points,
        Span<byte> results,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ValidateEvaluateArguments(values, weights, nodeCount, points.Length, results, add, subtract, multiply, invert, pool);

        using IMemoryOwner<byte> nodeOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> nodes = nodeOwner.Memory.Span[..(nodeCount * ScalarSize)];
        for(int i = 0; i < nodeCount; i++)
        {
            WriteSmallInteger(i, nodes.Slice(i * ScalarSize, ScalarSize));
        }

        using IMemoryOwner<byte> reciprocalOwner = pool.Rent(nodeCount * ScalarSize);
        using IMemoryOwner<byte> prefixOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> reciprocals = reciprocalOwner.Memory.Span[..(nodeCount * ScalarSize)];
        Span<byte> prefix = prefixOwner.Memory.Span[..(nodeCount * ScalarSize)];
        for(int p = 0; p < points.Length; p++)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(points[p], nodeCount);
            EvaluateSingle(values, weights, nodes, nodeCount, points[p], results.Slice(p * ScalarSize, ScalarSize), reciprocals, prefix, add, subtract, multiply, invert, curve);
        }
    }


    //p(x) = (Σ_i (w_i / (x − x_i)) · y_i) / (Σ_i w_i / (x − x_i)) — the second
    //barycentric form. x is never a node, so every (x − x_i) is invertible; the
    //whole set of reciprocals is taken in one batched inversion. The accumulation
    //order matches the naive form, so the result is byte-identical.
    private static void EvaluateSingle(
        ReadOnlySpan<byte> values,
        ReadOnlySpan<byte> weights,
        ReadOnlySpan<byte> nodes,
        int nodeCount,
        int point,
        Span<byte> result,
        Span<byte> reciprocals,
        Span<byte> prefix,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve)
    {
        Span<byte> pointElement = stackalloc byte[ScalarSize];
        WriteSmallInteger(point, pointElement);

        //reciprocals[i] = x − x_i, then batch-inverted in place to 1/(x − x_i).
        for(int i = 0; i < nodeCount; i++)
        {
            subtract(pointElement, nodes.Slice(i * ScalarSize, ScalarSize), reciprocals.Slice(i * ScalarSize, ScalarSize), curve);
        }

        BatchInvert(reciprocals, prefix, nodeCount, multiply, invert, curve);

        Span<byte> numerator = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];
        numerator.Clear();
        denominator.Clear();

        Span<byte> weighted = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        for(int i = 0; i < nodeCount; i++)
        {
            //weighted = w_i / (x − x_i).
            multiply(weights.Slice(i * ScalarSize, ScalarSize), reciprocals.Slice(i * ScalarSize, ScalarSize), weighted, curve);

            //numerator += weighted · y_i; denominator += weighted. The backends
            //do not promise alias-safe in-place accumulation, so route through a
            //scratch and copy back.
            multiply(weighted, values.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(numerator, term, accumulator, curve);
            accumulator.CopyTo(numerator);
            add(denominator, weighted, accumulator, curve);
            accumulator.CopyTo(denominator);
        }

        Span<byte> reciprocal = stackalloc byte[ScalarSize];
        invert(denominator, reciprocal, curve);
        multiply(numerator, reciprocal, result, curve);
    }


    //In-place batch inversion (Montgomery's trick): replaces each of the first
    //`count` elements with its field inverse using a single inversion plus
    //O(count) multiplications. `prefix` is count·32 bytes of scratch. Every
    //element must be non-zero in the field.
    private static void BatchInvert(
        Span<byte> elements,
        Span<byte> prefix,
        int count,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve)
    {
        //prefix[i] = elements[0]·…·elements[i].
        elements[..ScalarSize].CopyTo(prefix[..ScalarSize]);
        for(int i = 1; i < count; i++)
        {
            multiply(prefix.Slice((i - 1) * ScalarSize, ScalarSize), elements.Slice(i * ScalarSize, ScalarSize), prefix.Slice(i * ScalarSize, ScalarSize), curve);
        }

        //running = 1 / (elements[0]·…·elements[count−1]).
        Span<byte> running = stackalloc byte[ScalarSize];
        invert(prefix.Slice((count - 1) * ScalarSize, ScalarSize), running, curve);

        Span<byte> original = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int i = count - 1; i >= 1; i--)
        {
            elements.Slice(i * ScalarSize, ScalarSize).CopyTo(original);

            //1/elements[i] = running · prefix[i−1]; then peel elements[i] off running.
            multiply(running, prefix.Slice((i - 1) * ScalarSize, ScalarSize), elements.Slice(i * ScalarSize, ScalarSize), curve);
            multiply(running, original, scratch, curve);
            scratch.CopyTo(running);
        }

        running.CopyTo(elements[..ScalarSize]);
    }


    private static void ValidateEvaluateArguments(
        ReadOnlySpan<byte> values,
        ReadOnlySpan<byte> weights,
        int nodeCount,
        int pointCount,
        ReadOnlySpan<byte> results,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(nodeCount, 1);
        if(values.Length != nodeCount * ScalarSize)
        {
            throw new ArgumentException($"Values must be {nodeCount * ScalarSize} bytes; received {values.Length}.", nameof(values));
        }

        if(weights.Length != nodeCount * ScalarSize)
        {
            throw new ArgumentException($"Weights must be {nodeCount * ScalarSize} bytes; received {weights.Length}.", nameof(weights));
        }

        if(results.Length != pointCount * ScalarSize)
        {
            throw new ArgumentException($"Results must be {pointCount * ScalarSize} bytes; received {results.Length}.", nameof(results));
        }
    }


    //Writes a non-negative integer below the field order as a canonical
    //32-byte big-endian field element.
    private static void WriteSmallInteger(int value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[^sizeof(uint)..], (uint)value);
    }
}
