using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The systematic Reed–Solomon encoder for Ligero rows. A row's message is its
/// first <c>messageLength</c> entries — the evaluations of a degree-<c>&lt;
/// messageLength</c> polynomial at the nodes <c>{0, …, messageLength − 1}</c> —
/// and the codeword extends those same evaluations to
/// <c>{messageLength, …, codewordLength − 1}</c>. Systematic: the message
/// entries appear unchanged as the codeword's prefix, and the encoder only
/// computes the extension.
/// </summary>
/// <remarks>
/// <para>
/// The encoding is the univariate "extend the evaluations" map realized by
/// <see cref="BarycentricInterpolation"/>, which needs no NTT and therefore
/// runs over P-256's field (no smooth-order roots of unity) as readily as over
/// an FFT-friendly one. This is the correctness-first encoder; a
/// CRT-convolution / FFT backend is a later performance seam that produces the
/// identical codeword.
/// </para>
/// <para>
/// All buffers are the shared canonical layout: <c>length · 32</c> bytes, one
/// big-endian field element per <see cref="Scalar.SizeBytes"/> slot.
/// </para>
/// </remarks>
public static class LigeroReedSolomonEncoder
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Encodes <paramref name="message"/> (its <c>messageLength</c> evaluations)
    /// into <paramref name="codeword"/> (its <c>codewordLength</c> evaluations),
    /// systematically: the prefix is copied and the suffix interpolated.
    /// </summary>
    /// <param name="message">The message; exactly <c>messageLength · 32</c> bytes.</param>
    /// <param name="messageLength">The message length (the RS dimension); at least 1.</param>
    /// <param name="codeword">The destination codeword; exactly <c>codewordLength · 32</c> bytes.</param>
    /// <param name="codewordLength">The codeword length (the RS block length); at least <paramref name="messageLength"/>.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent encoding scratch from.</param>
    /// <exception cref="ArgumentNullException">When a backend or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a length does not match.</exception>
    public static void Encode(
        ReadOnlySpan<byte> message,
        int messageLength,
        Span<byte> codeword,
        int codewordLength,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool) =>
        Encode(message, messageLength, codeword, codewordLength, LigeroNodeDomain.ConsecutiveIntegers, add, subtract, multiply, invert, curve, pool);


    /// <summary>
    /// Encodes over an explicit Reed–Solomon node domain — the binary-field domain computes the
    /// barycentric weights over XOR node differences instead of the integer factorial form.
    /// </summary>
    public static void Encode(
        ReadOnlySpan<byte> message,
        int messageLength,
        Span<byte> codeword,
        int codewordLength,
        LigeroNodeDomain nodeDomain,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool) =>
        Encode(message, messageLength, codeword, codewordLength, nodeDomain, [], add, subtract, multiply, invert, curve, pool);


    /// <summary>
    /// Encodes with optionally precomputed barycentric weights (from
    /// <see cref="ComputeWeights"/>): the weights depend only on the domain and the message
    /// length, so a caller encoding many rows of the same shape — a tableau build — computes
    /// them once. An empty span computes them per call.
    /// </summary>
    public static void Encode(
        ReadOnlySpan<byte> message,
        int messageLength,
        Span<byte> codeword,
        int codewordLength,
        LigeroNodeDomain nodeDomain,
        ReadOnlySpan<byte> precomputedWeights,
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
        ArgumentOutOfRangeException.ThrowIfLessThan(messageLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(codewordLength, messageLength);
        if(message.Length != messageLength * ScalarSize)
        {
            throw new ArgumentException($"Message must be {messageLength * ScalarSize} bytes; received {message.Length}.", nameof(message));
        }

        if(codeword.Length != codewordLength * ScalarSize)
        {
            throw new ArgumentException($"Codeword must be {codewordLength * ScalarSize} bytes; received {codeword.Length}.", nameof(codeword));
        }

        //Systematic prefix: the message evaluations are the codeword's first
        //messageLength entries verbatim.
        message.CopyTo(codeword[..(messageLength * ScalarSize)]);

        int extensionCount = codewordLength - messageLength;
        if(extensionCount == 0)
        {
            return;
        }

        using IMemoryOwner<byte> weightsOwner = pool.Rent(messageLength * ScalarSize);
        Span<byte> weights = weightsOwner.Memory.Span[..(messageLength * ScalarSize)];
        if(precomputedWeights.IsEmpty)
        {
            ComputeWeights(messageLength, nodeDomain, weights, subtract, multiply, invert, curve, pool);
        }
        else
        {
            if(precomputedWeights.Length != messageLength * ScalarSize)
            {
                throw new ArgumentException($"Precomputed weights must be {messageLength * ScalarSize} bytes; received {precomputedWeights.Length}.", nameof(precomputedWeights));
            }

            precomputedWeights.CopyTo(weights);
        }

        BarycentricInterpolation.EvaluateAtConsecutivePoints(
            message,
            weights,
            messageLength,
            messageLength,
            extensionCount,
            codeword[(messageLength * ScalarSize)..],
            add,
            subtract,
            multiply,
            invert,
            curve,
            pool);
    }


    /// <summary>
    /// Computes the barycentric weights for the given domain and message length — the
    /// per-domain dispatch shared by the encoder, the tableau build and the verifier.
    /// </summary>
    public static void ComputeWeights(
        int messageLength,
        LigeroNodeDomain nodeDomain,
        Span<byte> weights,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        if(nodeDomain == LigeroNodeDomain.BinaryField)
        {
            BarycentricInterpolation.ComputeBinaryNodeWeights(messageLength, weights, multiply, invert, curve, pool);
        }
        else
        {
            BarycentricInterpolation.ComputeConsecutiveNodeWeights(messageLength, weights, subtract, multiply, invert, curve, pool);
        }
    }
}
