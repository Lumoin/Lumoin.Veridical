using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The deterministic batching algebra of one HVZK code-switch round
/// (eprint 2026/391 Construction 9.7, Section 9.4): the zero-evader
/// evaluation answering an out-of-domain sample privately over
/// <c>(message ‖ randomness ‖ pad)</c>, and the dense covector the fresh
/// code-switch mask contributes to the carried mask relation. The round loop,
/// proof payload and transcript order live in the hiding pipeline; this class
/// owns only the algebra both endpoints recompute.
/// </summary>
/// <remarks>
/// <para>
/// The private reply to an out-of-domain point <c>ρ</c> is the univariate
/// evaluation of the concatenated coefficient vector,
/// <c>y = ze*_l(ρ)·message + ρ^l·ze*_r(ρ)·maskMessage</c> with
/// <c>ze*_n(ρ) = (1, ρ, …, ρ^(n-1))</c> (Definition 6.1). For <c>ρ ≠ 0</c>
/// the pad contribution is a nonzero linear functional of the fresh pad, so a
/// uniform pad makes <c>y</c> uniform and independent of the committed data —
/// the deterministic zero-evader of Lemma 9.3 with no extra sampling.
/// </para>
/// <para>
/// Privacy preconditions, enforced loudly by
/// <see cref="ThrowIfOutOfDomainPointsInadmissible"/> per the wired ruling
/// rather than left as debug assumptions: the pad carries at least one fresh
/// coordinate per out-of-domain sample and the points are pairwise distinct
/// and nonzero. Over the wired ≈2^254 scalar fields the offending events have
/// probability about <c>1/|F|</c>; failing loudly costs nothing and never
/// leaks silently.
/// </para>
/// </remarks>
public static class ZkWhirCodeSwitch
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Evaluates a coefficient vector at a point by Horner's rule:
    /// <c>Σ_i c_i·ρ^i</c>. An empty vector evaluates to zero.
    /// </summary>
    /// <param name="point">The evaluation point <c>ρ</c>, one element.</param>
    /// <param name="coefficients">The coefficients in ascending degree order; any whole-element length.</param>
    /// <param name="destination">Receives the evaluation, one element.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The curve whose scalar field the evaluation runs in.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public static void EvaluateCoefficients(
        ReadOnlySpan<byte> point,
        ReadOnlySpan<byte> coefficients,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ThrowIfNotOneElement(point, nameof(point));
        ThrowIfNotOneElement(destination, nameof(destination));
        if(coefficients.Length % ScalarSize != 0)
        {
            throw new ArgumentException(
                $"The coefficients must be whole {ScalarSize}-byte elements; received {coefficients.Length} bytes.",
                nameof(coefficients));
        }

        destination.Clear();
        for(int offset = coefficients.Length - ScalarSize; offset >= 0; offset -= ScalarSize)
        {
            multiply(destination, point, destination, curve);
            add(destination, coefficients.Slice(offset, ScalarSize), destination, curve);
        }
    }


    /// <summary>
    /// Writes the private out-of-domain reply
    /// <c>y = Σ_j m_j·ρ^j + ρ^l·Σ_s u_s·ρ^s</c> over the concatenated
    /// coefficient vector <c>(message ‖ maskMessage)</c>, where the mask
    /// message is the source oracle's folded randomness followed by the fresh
    /// pad — the coefficient layout the code-switch mask commits.
    /// </summary>
    /// <param name="point">The out-of-domain point <c>ρ</c>, one element.</param>
    /// <param name="message">The folded message coefficients, <c>l</c> elements.</param>
    /// <param name="maskMessage">The mask message <c>(randomness ‖ pad)</c> coefficients.</param>
    /// <param name="destination">Receives the reply, one element.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The curve whose scalar field the evaluation runs in.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public static void EvaluatePaddedOutOfDomain(
        ReadOnlySpan<byte> point,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> maskMessage,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ThrowIfNotOneElement(point, nameof(point));
        ThrowIfNotOneElement(destination, nameof(destination));

        Span<byte> maskEvaluation = stackalloc byte[ScalarSize];
        EvaluateCoefficients(point, maskMessage, maskEvaluation, add, multiply, curve);

        //The shift ρ^l relocates the mask message to global degrees l, l+1, …
        //— the contiguous slots after the message.
        Span<byte> shift = stackalloc byte[ScalarSize];
        WhirFold.ComputeDomainPoint(point, message.Length / ScalarSize, shift, multiply, curve);
        multiply(maskEvaluation, shift, maskEvaluation, curve);

        EvaluateCoefficients(point, message, destination, add, multiply, curve);
        add(destination, maskEvaluation, destination, curve);
    }


    /// <summary>
    /// Accumulates the dense covector the batched claim lays on a fresh
    /// code-switch mask <c>(randomness ‖ pad)</c>: an out-of-domain point
    /// <c>ρ</c> with coefficient <c>c</c> adds <c>c·ρ^(l+s)</c> to every mask
    /// slot <c>s</c>, an in-domain query point <c>x</c> with coefficient
    /// <c>c</c> adds <c>c·x^(l+s)</c> to the randomness slots only — the pad
    /// never appears in openings, so the query layers stop at the randomness
    /// boundary.
    /// </summary>
    /// <param name="messageLength">The folded message element count <c>l</c> the mask slots continue from.</param>
    /// <param name="sourceRandomnessLength">The folded randomness element count of the mask message.</param>
    /// <param name="padLength">The fresh pad element count of the mask message.</param>
    /// <param name="outOfDomainPoints">The out-of-domain points, concatenated elements.</param>
    /// <param name="outOfDomainCoefficients">The matching batching coefficients, one per point.</param>
    /// <param name="queryPoints">The in-domain query points, concatenated elements.</param>
    /// <param name="queryCoefficients">The matching batching coefficients, one per point.</param>
    /// <param name="destination">Receives the covector, <c>sourceRandomnessLength + padLength</c> elements; cleared first.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The curve whose scalar field the covector lives in.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public static void WriteSwitchMaskCovector(
        int messageLength,
        int sourceRandomnessLength,
        int padLength,
        ReadOnlySpan<byte> outOfDomainPoints,
        ReadOnlySpan<byte> outOfDomainCoefficients,
        ReadOnlySpan<byte> queryPoints,
        ReadOnlySpan<byte> queryCoefficients,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfNegative(messageLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sourceRandomnessLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(padLength);
        if(outOfDomainPoints.Length != outOfDomainCoefficients.Length || queryPoints.Length != queryCoefficients.Length)
        {
            throw new ArgumentException("Every point span must carry exactly one coefficient per point.");
        }

        int slotCount = sourceRandomnessLength + padLength;
        if(destination.Length != slotCount * ScalarSize)
        {
            throw new ArgumentException(
                $"The covector destination must carry {slotCount} elements ({slotCount * ScalarSize} bytes); received {destination.Length}.",
                nameof(destination));
        }

        destination.Clear();
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int point = 0; point < outOfDomainPoints.Length / ScalarSize; point++)
        {
            AccumulatePowerLayer(
                outOfDomainPoints.Slice(point * ScalarSize, ScalarSize),
                outOfDomainCoefficients.Slice(point * ScalarSize, ScalarSize),
                messageLength,
                slotCount,
                destination,
                term,
                add,
                multiply,
                curve);
        }

        for(int point = 0; point < queryPoints.Length / ScalarSize; point++)
        {
            AccumulatePowerLayer(
                queryPoints.Slice(point * ScalarSize, ScalarSize),
                queryCoefficients.Slice(point * ScalarSize, ScalarSize),
                messageLength,
                sourceRandomnessLength,
                destination,
                term,
                add,
                multiply,
                curve);
        }
    }


    /// <summary>
    /// Rejects an inadmissible private out-of-domain point set before any
    /// reply is computed: a zero point or a repeated point collapses the
    /// pad-coefficient matrix and the replies would leak a linear functional
    /// of the committed data (eprint 2026/391 Section 9.4). Both endpoints
    /// derive the same points from the shared transcript, so the gate fires
    /// identically on both sides.
    /// </summary>
    /// <param name="points">The squeezed out-of-domain points, concatenated elements.</param>
    /// <param name="padLength">The fresh pad element count of the round's code-switch mask.</param>
    /// <exception cref="ArgumentException">When <paramref name="points"/> is not whole elements.</exception>
    /// <exception cref="InvalidOperationException">When the pad is shorter than the point count, a point is zero or two points coincide.</exception>
    public static void ThrowIfOutOfDomainPointsInadmissible(ReadOnlySpan<byte> points, int padLength)
    {
        if(points.Length % ScalarSize != 0)
        {
            throw new ArgumentException(
                $"The points must be whole {ScalarSize}-byte elements; received {points.Length} bytes.",
                nameof(points));
        }

        int pointCount = points.Length / ScalarSize;
        if(padLength < pointCount)
        {
            throw new InvalidOperationException(
                $"The code-switch pad carries {padLength} fresh coordinates for {pointCount} out-of-domain samples; joint privacy requires one per sample.");
        }

        for(int i = 0; i < pointCount; i++)
        {
            ReadOnlySpan<byte> point = points.Slice(i * ScalarSize, ScalarSize);
            if(!point.ContainsAnyExcept((byte)0))
            {
                throw new InvalidOperationException(
                    "A private out-of-domain point of zero would leak the committed data; the transcript produced a probability-1/|F| event.");
            }

            for(int j = 0; j < i; j++)
            {
                if(point.SequenceEqual(points.Slice(j * ScalarSize, ScalarSize)))
                {
                    throw new InvalidOperationException(
                        "Two private out-of-domain points coincide; the pad-coefficient matrix is singular and the replies would leak.");
                }
            }
        }
    }


    /// <summary>
    /// Adds <c>coefficient·point^(messageLength + s)</c> to the first
    /// <paramref name="reachedSlots"/> covector slots.
    /// </summary>
    private static void AccumulatePowerLayer(
        ReadOnlySpan<byte> point,
        ReadOnlySpan<byte> coefficient,
        int messageLength,
        int reachedSlots,
        Span<byte> destination,
        Span<byte> term,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        WhirFold.ComputeDomainPoint(point, messageLength, term, multiply, curve);
        multiply(term, coefficient, term, curve);
        for(int slot = 0; slot < reachedSlots; slot++)
        {
            Span<byte> slotBytes = destination.Slice(slot * ScalarSize, ScalarSize);
            add(slotBytes, term, slotBytes, curve);
            multiply(term, point, term, curve);
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
}
