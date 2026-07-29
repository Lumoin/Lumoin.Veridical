using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// A LogUp-GKR lookup proof: the multiplicity column is the only committed
/// column beyond the witness columns — the helper column of the plain
/// <see cref="LogUpProof"/> variant is replaced by the fraction-tree layer
/// messages. Carries the commitments, the four root values, every layer's
/// sumcheck rounds and terminating quad, the claimed column evaluations at
/// the terminal row point, and the openings proving them.
/// </summary>
/// <remarks>
/// Sound but not hiding, like the plain variant: openings disclose the opened
/// evaluations. <see cref="FromParts"/> is the deserialization funnel that
/// enforces the shape caps and canonical scalar encodings on every
/// transcript-bound byte.
/// </remarks>
public sealed class LogUpGkrProof: IDisposable
{
    private readonly PolynomialCommitment[] witnessCommitments;
    private readonly PolynomialOpening[] witnessOpenings;
    private readonly IMemoryOwner<byte> rootValues;
    private readonly IMemoryOwner<byte> layerMessages;
    private readonly IMemoryOwner<byte> claimedEvaluations;
    private bool disposed;

    private const int ScalarSize = Scalar.SizeBytes;

    //The four root values and each layer's terminating message are quads:
    //numerator and denominator at the two children of the split point.
    internal const int QuadScalarCount = 4;


    /// <summary>The row hypercube variable count <c>n</c>.</summary>
    public int VariableCount { get; }

    /// <summary>The witness-column count <c>M</c>.</summary>
    public int WitnessColumnCount { get; }

    /// <summary>The selector variable count <c>⌈log2(M + 1)⌉</c>; the fraction tree spans <c>VariableCount + SelectorVariableCount</c> variables.</summary>
    public int SelectorVariableCount { get; }

    /// <summary>The curve whose scalar field the argument runs over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The witness-column commitments, in column order.</summary>
    public IReadOnlyList<PolynomialCommitment> WitnessCommitments => witnessCommitments;

    /// <summary>The multiplicity-column commitment — the argument's only additional committed column.</summary>
    public PolynomialCommitment MultiplicityCommitment { get; }

    /// <summary>The witness-column openings at the terminal row point, in column order.</summary>
    public IReadOnlyList<PolynomialOpening> WitnessOpenings => witnessOpenings;

    /// <summary>The multiplicity-column opening at the terminal row point.</summary>
    public PolynomialOpening MultiplicityOpening { get; }


    internal LogUpGkrProof(
        int variableCount,
        int witnessColumnCount,
        CurveParameterSet curve,
        PolynomialCommitment[] witnessCommitments,
        PolynomialCommitment multiplicityCommitment,
        IMemoryOwner<byte> rootValues,
        IMemoryOwner<byte> layerMessages,
        IMemoryOwner<byte> claimedEvaluations,
        PolynomialOpening[] witnessOpenings,
        PolynomialOpening multiplicityOpening)
    {
        VariableCount = variableCount;
        WitnessColumnCount = witnessColumnCount;
        SelectorVariableCount = SelectorVariableCountFor(witnessColumnCount);
        Curve = curve;
        this.witnessCommitments = witnessCommitments;
        MultiplicityCommitment = multiplicityCommitment;
        this.rootValues = rootValues;
        this.layerMessages = layerMessages;
        this.claimedEvaluations = claimedEvaluations;
        this.witnessOpenings = witnessOpenings;
        MultiplicityOpening = multiplicityOpening;
    }


    /// <summary>The selector variable count for a witness-column count: <c>⌈log2(M + 1)⌉</c>.</summary>
    public static int SelectorVariableCountFor(int witnessColumnCount)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(witnessColumnCount, 1);

        return BitOperations.Log2((uint)witnessColumnCount) + 1;
    }


    /// <summary>
    /// The layer-message byte length for a tree over
    /// <paramref name="totalVariableCount"/> variables: layers 1..ν−1, each
    /// carrying its round evaluations (four per round) and a terminating quad.
    /// </summary>
    public static int GetLayerMessagesLength(int totalVariableCount)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(totalVariableCount, 2);

        int totalScalars = 0;
        for(int layer = 1; layer < totalVariableCount; layer++)
        {
            totalScalars += (LogUpGkrSumcheck.RoundEvaluationCount * layer) + QuadScalarCount;
        }

        return totalScalars * ScalarSize;
    }


    /// <summary>The four root values <c>p₁(0), p₁(1), q₁(0), q₁(1)</c>.</summary>
    public ReadOnlySpan<byte> GetRootValueBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return rootValues.Memory.Span[..(QuadScalarCount * ScalarSize)];
    }


    /// <summary>Every layer's sumcheck rounds and terminating quad, layers 1..ν−1 back to back.</summary>
    public ReadOnlySpan<byte> GetLayerMessageBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return layerMessages.Memory.Span[..GetLayerMessagesLength(VariableCount + SelectorVariableCount)];
    }


    /// <summary>The claimed evaluations at the terminal row point, in the order <c>w_1(r), …, w_M(r), m(r)</c>.</summary>
    public ReadOnlySpan<byte> GetClaimedEvaluationBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return claimedEvaluations.Memory.Span[..((WitnessColumnCount + 1) * ScalarSize)];
    }


    /// <summary>
    /// Reconstructs a proof from its parts, enforcing the shape caps and
    /// canonical scalar encodings — the funnel every untrusted proof passes
    /// through. Ownership of the commitment and opening instances transfers
    /// only on success.
    /// </summary>
    /// <param name="variableCount">The row variable count; the tree total <c>n + ⌈log2(M+1)⌉</c> must stay within <see cref="LogUpProver.MaximumVariableCount"/>.</param>
    /// <param name="witnessColumnCount">The witness-column count; in <c>[1, LogUpProver.MaximumWitnessColumnCount]</c>.</param>
    /// <param name="curve">The curve whose scalar field the argument runs over.</param>
    /// <param name="witnessCommitments">The witness-column commitments, in column order.</param>
    /// <param name="multiplicityCommitment">The multiplicity-column commitment.</param>
    /// <param name="rootValueBytes">The four root values, <c>4 × 32</c> bytes.</param>
    /// <param name="layerMessageBytes">The layer messages, <see cref="GetLayerMessagesLength"/> bytes.</param>
    /// <param name="claimedEvaluationBytes">The claimed evaluations, <c>(M + 1) × 32</c> bytes.</param>
    /// <param name="witnessOpenings">The witness-column openings, in column order.</param>
    /// <param name="multiplicityOpening">The multiplicity-column opening.</param>
    /// <param name="pool">The pool to rent the byte buffers from.</param>
    /// <returns>The reconstructed proof.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a shape cap is violated.</exception>
    /// <exception cref="ArgumentException">When a length mismatches or a scalar encoding is non-canonical.</exception>
    public static LogUpGkrProof FromParts(
        int variableCount,
        int witnessColumnCount,
        CurveParameterSet curve,
        IReadOnlyList<PolynomialCommitment> witnessCommitments,
        PolynomialCommitment multiplicityCommitment,
        ReadOnlySpan<byte> rootValueBytes,
        ReadOnlySpan<byte> layerMessageBytes,
        ReadOnlySpan<byte> claimedEvaluationBytes,
        IReadOnlyList<PolynomialOpening> witnessOpenings,
        PolynomialOpening multiplicityOpening,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(witnessCommitments);
        ArgumentNullException.ThrowIfNull(multiplicityCommitment);
        ArgumentNullException.ThrowIfNull(witnessOpenings);
        ArgumentNullException.ThrowIfNull(multiplicityOpening);
        ArgumentNullException.ThrowIfNull(pool);
        if(witnessColumnCount < 1 || witnessColumnCount > LogUpProver.MaximumWitnessColumnCount)
        {
            throw new ArgumentOutOfRangeException(nameof(witnessColumnCount), witnessColumnCount, $"The witness-column count must lie in [1, {LogUpProver.MaximumWitnessColumnCount}].");
        }

        //The row count is bounded BEFORE the selector addition so an extreme
        //value can never wrap the total past the cap comparison; the tree
        //spans row and selector variables together, and its leaf tables are
        //the largest spans, so the plain variant's cap applies to the TOTAL.
        if(variableCount < 1 || variableCount > LogUpProver.MaximumVariableCount)
        {
            throw new ArgumentOutOfRangeException(nameof(variableCount), variableCount, $"The row variable count must lie in [1, {LogUpProver.MaximumVariableCount}].");
        }

        int totalVariableCount = variableCount + SelectorVariableCountFor(witnessColumnCount);
        if(totalVariableCount > LogUpProver.MaximumVariableCount)
        {
            throw new ArgumentOutOfRangeException(nameof(variableCount), variableCount, $"The row variable count plus ⌈log2(M+1)⌉ selector variables must lie in [2, {LogUpProver.MaximumVariableCount}].");
        }

        if(witnessCommitments.Count != witnessColumnCount || witnessOpenings.Count != witnessColumnCount)
        {
            throw new ArgumentException($"Expected {witnessColumnCount} witness commitments and openings; received {witnessCommitments.Count} and {witnessOpenings.Count}.", nameof(witnessCommitments));
        }

        if(rootValueBytes.Length != QuadScalarCount * ScalarSize)
        {
            throw new ArgumentException($"Root values must be {QuadScalarCount * ScalarSize} bytes; received {rootValueBytes.Length}.", nameof(rootValueBytes));
        }

        int layersLength = GetLayerMessagesLength(totalVariableCount);
        if(layerMessageBytes.Length != layersLength)
        {
            throw new ArgumentException($"Layer messages must be {layersLength} bytes; received {layerMessageBytes.Length}.", nameof(layerMessageBytes));
        }

        int claimedLength = (witnessColumnCount + 1) * ScalarSize;
        if(claimedEvaluationBytes.Length != claimedLength)
        {
            throw new ArgumentException($"Claimed evaluations must be {claimedLength} bytes; received {claimedEvaluationBytes.Length}.", nameof(claimedEvaluationBytes));
        }

        LogUpProver.ThrowIfNonCanonical(rootValueBytes, curve, nameof(rootValueBytes));
        LogUpProver.ThrowIfNonCanonical(layerMessageBytes, curve, nameof(layerMessageBytes));
        LogUpProver.ThrowIfNonCanonical(claimedEvaluationBytes, curve, nameof(claimedEvaluationBytes));

        IMemoryOwner<byte> rootOwner = pool.Rent(rootValueBytes.Length);
        IMemoryOwner<byte>? layersOwner = null;
        IMemoryOwner<byte>? claimedOwner = null;
        try
        {
            rootValueBytes.CopyTo(rootOwner.Memory.Span);
            layersOwner = pool.Rent(layersLength);
            layerMessageBytes.CopyTo(layersOwner.Memory.Span);
            claimedOwner = pool.Rent(claimedLength);
            claimedEvaluationBytes.CopyTo(claimedOwner.Memory.Span);

            PolynomialCommitment[] commitments = new PolynomialCommitment[witnessColumnCount];
            PolynomialOpening[] openings = new PolynomialOpening[witnessColumnCount];
            for(int i = 0; i < witnessColumnCount; i++)
            {
                commitments[i] = witnessCommitments[i];
                openings[i] = witnessOpenings[i];
            }

            return new LogUpGkrProof(
                variableCount,
                witnessColumnCount,
                curve,
                commitments,
                multiplicityCommitment,
                rootOwner,
                layersOwner,
                claimedOwner,
                openings,
                multiplicityOpening);
        }
        catch
        {
            rootOwner.Dispose();
            layersOwner?.Dispose();
            claimedOwner?.Dispose();
            throw;
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        foreach(PolynomialCommitment commitment in witnessCommitments)
        {
            commitment.Dispose();
        }
        foreach(PolynomialOpening opening in witnessOpenings)
        {
            opening.Dispose();
        }
        MultiplicityCommitment.Dispose();
        MultiplicityOpening.Dispose();
        rootValues.Dispose();
        layerMessages.Dispose();
        claimedEvaluations.Dispose();
    }
}
