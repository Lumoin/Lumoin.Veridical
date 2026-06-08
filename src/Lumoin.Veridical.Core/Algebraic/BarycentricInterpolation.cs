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
/// FFT is unavailable. It is the correctness-first counterpart to the
/// CRT-convolution encoder used for speed in the Longfellow reference; an
/// FFT/CRT-backed encoder is a later performance seam, not a protocol change.
/// </para>
/// <para>
/// Weights depend only on <c>nodeCount</c>, so
/// <see cref="ComputeConsecutiveNodeWeights"/> is called once and the result
/// reused across every evaluation point. Complexity is O(nodeCount²) for the
/// weights and O(nodeCount) field operations (including one inversion) per
/// evaluation point. Evaluation points must be distinct from every node — for
/// the encoder they are, since the extension points start at
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
    /// <c>{0, …, nodeCount − 1}</c>.
    /// </summary>
    /// <param name="nodeCount">The number of nodes (the message length); at least 1.</param>
    /// <param name="weights">Receives <c>nodeCount</c> scalars (<c>nodeCount · 32</c> bytes).</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the node-element scratch from.</param>
    public static void ComputeConsecutiveNodeWeights(
        int nodeCount,
        Span<byte> weights,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
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

        using IMemoryOwner<byte> nodeOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> nodes = nodeOwner.Memory.Span[..(nodeCount * ScalarSize)];
        for(int i = 0; i < nodeCount; i++)
        {
            WriteSmallInteger(i, nodes.Slice(i * ScalarSize, ScalarSize));
        }

        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int i = 0; i < nodeCount; i++)
        {
            //product = ∏_{j≠i} (node_i − node_j); start at the field's one.
            WriteSmallInteger(1, product);
            ReadOnlySpan<byte> nodeI = nodes.Slice(i * ScalarSize, ScalarSize);
            for(int j = 0; j < nodeCount; j++)
            {
                if(j == i)
                {
                    continue;
                }

                subtract(nodeI, nodes.Slice(j * ScalarSize, ScalarSize), difference, curve);
                multiply(product, difference, scratch, curve);
                scratch.CopyTo(product);
            }

            invert(product, weights.Slice(i * ScalarSize, ScalarSize), curve);
        }
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
    /// <param name="pool">Pool to rent the node-element scratch from.</param>
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
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(firstPoint, nodeCount);
        ValidateEvaluateArguments(values, weights, nodeCount, pointCount, results, add, subtract, multiply, invert, pool);

        using IMemoryOwner<byte> nodeOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> nodes = nodeOwner.Memory.Span[..(nodeCount * ScalarSize)];
        for(int i = 0; i < nodeCount; i++)
        {
            WriteSmallInteger(i, nodes.Slice(i * ScalarSize, ScalarSize));
        }

        for(int p = 0; p < pointCount; p++)
        {
            EvaluateSingle(values, weights, nodes, nodeCount, firstPoint + p, results.Slice(p * ScalarSize, ScalarSize), add, subtract, multiply, invert, curve);
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
    /// <param name="pool">Pool to rent the node-element scratch from.</param>
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
        SensitiveMemoryPool<byte> pool)
    {
        ValidateEvaluateArguments(values, weights, nodeCount, points.Length, results, add, subtract, multiply, invert, pool);

        using IMemoryOwner<byte> nodeOwner = pool.Rent(nodeCount * ScalarSize);
        Span<byte> nodes = nodeOwner.Memory.Span[..(nodeCount * ScalarSize)];
        for(int i = 0; i < nodeCount; i++)
        {
            WriteSmallInteger(i, nodes.Slice(i * ScalarSize, ScalarSize));
        }

        for(int p = 0; p < points.Length; p++)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(points[p], nodeCount);
            EvaluateSingle(values, weights, nodes, nodeCount, points[p], results.Slice(p * ScalarSize, ScalarSize), add, subtract, multiply, invert, curve);
        }
    }


    //p(x) = (Σ_i (w_i / (x − x_i)) · y_i) / (Σ_i w_i / (x − x_i)) — the second
    //barycentric form. x is never a node, so (x − x_i) is invertible.
    private static void EvaluateSingle(
        ReadOnlySpan<byte> values,
        ReadOnlySpan<byte> weights,
        ReadOnlySpan<byte> nodes,
        int nodeCount,
        int point,
        Span<byte> result,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve)
    {
        Span<byte> pointElement = stackalloc byte[ScalarSize];
        WriteSmallInteger(point, pointElement);

        Span<byte> numerator = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];
        numerator.Clear();
        denominator.Clear();

        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> reciprocal = stackalloc byte[ScalarSize];
        Span<byte> weighted = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        for(int i = 0; i < nodeCount; i++)
        {
            //weighted = w_i / (x − x_i).
            subtract(pointElement, nodes.Slice(i * ScalarSize, ScalarSize), difference, curve);
            invert(difference, reciprocal, curve);
            multiply(weights.Slice(i * ScalarSize, ScalarSize), reciprocal, weighted, curve);

            //numerator += weighted · y_i; denominator += weighted. The backends
            //do not promise alias-safe in-place accumulation, so route through a
            //scratch and copy back.
            multiply(weighted, values.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(numerator, term, accumulator, curve);
            accumulator.CopyTo(numerator);
            add(denominator, weighted, accumulator, curve);
            accumulator.CopyTo(denominator);
        }

        invert(denominator, reciprocal, curve);
        multiply(numerator, reciprocal, result, curve);
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
        SensitiveMemoryPool<byte> pool)
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
