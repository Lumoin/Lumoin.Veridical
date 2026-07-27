using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// A LogUp lookup proof: the argument that every value of the committed
/// witness columns appears in the public table. Carries the column
/// commitments, the sumcheck round messages in evaluation form, the claimed
/// column evaluations at the sumcheck point, and the polynomial-commitment
/// openings proving them.
/// </summary>
/// <remarks>
/// <para>
/// The proof is sound but NOT hiding under a transparent commitment scheme:
/// the openings disclose the opened evaluations, and the committed columns are
/// binding commitments to the witness data, not encryptions of it. The
/// argument provides integrity, never confidentiality.
/// </para>
/// <para>
/// This is a typed-parts carrier: each part round-trips through its own
/// <c>AsReadOnlySpan</c>/<c>FromBytes</c> surface, and
/// <see cref="FromParts"/> is the deserialization funnel that enforces
/// canonical scalar encodings on the sumcheck and evaluation bytes. A
/// fixed-layout single-buffer carrier per commitment scheme (the
/// <c>LigeroSpartanProof</c> precedent) is deliberately deferred until a
/// consumer surface needs wire bytes.
/// </para>
/// </remarks>
public sealed class LogUpProof: IDisposable
{
    private readonly PolynomialCommitment[] witnessCommitments;
    private readonly PolynomialOpening[] witnessOpenings;
    private readonly IMemoryOwner<byte> roundEvaluations;
    private readonly IMemoryOwner<byte> claimedEvaluations;
    private bool disposed;

    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>The hypercube variable count (the sumcheck round count).</summary>
    public int VariableCount { get; }

    /// <summary>The witness-column count.</summary>
    public int WitnessColumnCount { get; }

    /// <summary>The curve whose scalar field the argument runs over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The witness-column commitments, in column order.</summary>
    public IReadOnlyList<PolynomialCommitment> WitnessCommitments => witnessCommitments;

    /// <summary>The multiplicity-column commitment.</summary>
    public PolynomialCommitment MultiplicityCommitment { get; }

    /// <summary>The helper-column commitment.</summary>
    public PolynomialCommitment HelperCommitment { get; }

    /// <summary>The witness-column openings at the sumcheck point, in column order.</summary>
    public IReadOnlyList<PolynomialOpening> WitnessOpenings => witnessOpenings;

    /// <summary>The multiplicity-column opening at the sumcheck point.</summary>
    public PolynomialOpening MultiplicityOpening { get; }

    /// <summary>The helper-column opening at the sumcheck point.</summary>
    public PolynomialOpening HelperOpening { get; }


    internal LogUpProof(
        int variableCount,
        int witnessColumnCount,
        CurveParameterSet curve,
        PolynomialCommitment[] witnessCommitments,
        PolynomialCommitment multiplicityCommitment,
        PolynomialCommitment helperCommitment,
        IMemoryOwner<byte> roundEvaluations,
        IMemoryOwner<byte> claimedEvaluations,
        PolynomialOpening[] witnessOpenings,
        PolynomialOpening multiplicityOpening,
        PolynomialOpening helperOpening)
    {
        VariableCount = variableCount;
        WitnessColumnCount = witnessColumnCount;
        Curve = curve;
        this.witnessCommitments = witnessCommitments;
        MultiplicityCommitment = multiplicityCommitment;
        HelperCommitment = helperCommitment;
        this.roundEvaluations = roundEvaluations;
        this.claimedEvaluations = claimedEvaluations;
        this.witnessOpenings = witnessOpenings;
        MultiplicityOpening = multiplicityOpening;
        HelperOpening = helperOpening;
    }


    /// <summary>
    /// The sumcheck round messages: <c>VariableCount</c> rounds of
    /// <c>WitnessColumnCount + 4</c> evaluations each, 32 bytes per scalar.
    /// </summary>
    public ReadOnlySpan<byte> GetRoundEvaluationBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return roundEvaluations.Memory.Span[..(VariableCount * LogUpSumcheck.RoundEvaluationCount(WitnessColumnCount) * ScalarSize)];
    }


    /// <summary>
    /// The claimed column evaluations at the sumcheck point, in the order
    /// <c>w_1(r), …, w_M(r), m(r), h(r)</c>, 32 bytes per scalar.
    /// </summary>
    public ReadOnlySpan<byte> GetClaimedEvaluationBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return claimedEvaluations.Memory.Span[..((WitnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount) * ScalarSize)];
    }


    /// <summary>The claimed evaluation of witness column <paramref name="columnIndex"/> at the sumcheck point.</summary>
    public ReadOnlySpan<byte> GetClaimedWitnessEvaluationBytes(int columnIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(columnIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(columnIndex, WitnessColumnCount);

        return GetClaimedEvaluationBytes().Slice(columnIndex * ScalarSize, ScalarSize);
    }


    /// <summary>The claimed multiplicity-column evaluation at the sumcheck point.</summary>
    public ReadOnlySpan<byte> GetClaimedMultiplicityEvaluationBytes() =>
        GetClaimedEvaluationBytes().Slice(WitnessColumnCount * ScalarSize, ScalarSize);


    /// <summary>The claimed helper-column evaluation at the sumcheck point.</summary>
    public ReadOnlySpan<byte> GetClaimedHelperEvaluationBytes() =>
        GetClaimedEvaluationBytes().Slice((WitnessColumnCount + 1) * ScalarSize, ScalarSize);


    /// <summary>
    /// Reconstructs a proof from its parts, copying the sumcheck and
    /// evaluation bytes into pool-rented buffers and rejecting non-canonical
    /// scalar encodings — the deserialization funnel every untrusted proof
    /// passes through. Ownership of the commitment and opening instances
    /// transfers to the returned proof.
    /// </summary>
    /// <param name="variableCount">The hypercube variable count; at least 1.</param>
    /// <param name="witnessColumnCount">The witness-column count; at least 1.</param>
    /// <param name="curve">The curve whose scalar field the argument runs over.</param>
    /// <param name="witnessCommitments">The witness-column commitments, in column order.</param>
    /// <param name="multiplicityCommitment">The multiplicity-column commitment.</param>
    /// <param name="helperCommitment">The helper-column commitment.</param>
    /// <param name="roundEvaluationBytes">The sumcheck round messages, <c>variableCount × (witnessColumnCount + 4) × 32</c> bytes.</param>
    /// <param name="claimedEvaluationBytes">The claimed evaluations, <c>(witnessColumnCount + 2) × 32</c> bytes.</param>
    /// <param name="witnessOpenings">The witness-column openings, in column order.</param>
    /// <param name="multiplicityOpening">The multiplicity-column opening.</param>
    /// <param name="helperOpening">The helper-column opening.</param>
    /// <param name="pool">The pool to rent the byte buffers from.</param>
    /// <returns>The reconstructed proof.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a length mismatches or a scalar encoding is non-canonical.</exception>
    public static LogUpProof FromParts(
        int variableCount,
        int witnessColumnCount,
        CurveParameterSet curve,
        IReadOnlyList<PolynomialCommitment> witnessCommitments,
        PolynomialCommitment multiplicityCommitment,
        PolynomialCommitment helperCommitment,
        ReadOnlySpan<byte> roundEvaluationBytes,
        ReadOnlySpan<byte> claimedEvaluationBytes,
        IReadOnlyList<PolynomialOpening> witnessOpenings,
        PolynomialOpening multiplicityOpening,
        PolynomialOpening helperOpening,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(witnessCommitments);
        ArgumentNullException.ThrowIfNull(multiplicityCommitment);
        ArgumentNullException.ThrowIfNull(helperCommitment);
        ArgumentNullException.ThrowIfNull(witnessOpenings);
        ArgumentNullException.ThrowIfNull(multiplicityOpening);
        ArgumentNullException.ThrowIfNull(helperOpening);
        ArgumentNullException.ThrowIfNull(pool);

        //The caps close the hostile-shape hole: a shape past them would reach
        //masked shifts and wrapped length arithmetic downstream, letting a
        //crafted proof make the verifier throw instead of return false.
        if(variableCount < 1 || variableCount > LogUpProver.MaximumVariableCount)
        {
            throw new ArgumentOutOfRangeException(nameof(variableCount), variableCount, $"The variable count must lie in [1, {LogUpProver.MaximumVariableCount}].");
        }

        if(witnessColumnCount < 1 || witnessColumnCount > LogUpProver.MaximumWitnessColumnCount)
        {
            throw new ArgumentOutOfRangeException(nameof(witnessColumnCount), witnessColumnCount, $"The witness-column count must lie in [1, {LogUpProver.MaximumWitnessColumnCount}].");
        }

        if(witnessCommitments.Count != witnessColumnCount)
        {
            throw new ArgumentException($"Expected {witnessColumnCount} witness commitments; received {witnessCommitments.Count}.", nameof(witnessCommitments));
        }

        if(witnessOpenings.Count != witnessColumnCount)
        {
            throw new ArgumentException($"Expected {witnessColumnCount} witness openings; received {witnessOpenings.Count}.", nameof(witnessOpenings));
        }

        int roundLength = variableCount * LogUpSumcheck.RoundEvaluationCount(witnessColumnCount) * ScalarSize;
        if(roundEvaluationBytes.Length != roundLength)
        {
            throw new ArgumentException($"Round evaluations must be {roundLength} bytes; received {roundEvaluationBytes.Length}.", nameof(roundEvaluationBytes));
        }

        int claimedLength = (witnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount) * ScalarSize;
        if(claimedEvaluationBytes.Length != claimedLength)
        {
            throw new ArgumentException($"Claimed evaluations must be {claimedLength} bytes; received {claimedEvaluationBytes.Length}.", nameof(claimedEvaluationBytes));
        }

        //Round messages and claimed evaluations are absorbed into the
        //transcript verbatim; a non-canonical encoding would let one accepted
        //proof exist as two byte-distinct transcripts.
        ThrowIfNonCanonical(roundEvaluationBytes, curve, nameof(roundEvaluationBytes));
        ThrowIfNonCanonical(claimedEvaluationBytes, curve, nameof(claimedEvaluationBytes));

        IMemoryOwner<byte> roundOwner = pool.Rent(roundLength);
        IMemoryOwner<byte>? claimedOwner = null;
        try
        {
            roundEvaluationBytes.CopyTo(roundOwner.Memory.Span);
            claimedOwner = pool.Rent(claimedLength);
            claimedEvaluationBytes.CopyTo(claimedOwner.Memory.Span);

            PolynomialCommitment[] commitments = new PolynomialCommitment[witnessColumnCount];
            PolynomialOpening[] openings = new PolynomialOpening[witnessColumnCount];
            for(int i = 0; i < witnessColumnCount; i++)
            {
                commitments[i] = witnessCommitments[i];
                openings[i] = witnessOpenings[i];
            }

            return new LogUpProof(
                variableCount,
                witnessColumnCount,
                curve,
                commitments,
                multiplicityCommitment,
                helperCommitment,
                roundOwner,
                claimedOwner,
                openings,
                multiplicityOpening,
                helperOpening);
        }
        catch
        {
            //Ownership of the commitments and openings transfers only on
            //success; the rentals made here are released before rethrowing.
            roundOwner.Dispose();
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
        HelperCommitment.Dispose();
        MultiplicityOpening.Dispose();
        HelperOpening.Dispose();
        roundEvaluations.Dispose();
        claimedEvaluations.Dispose();
    }


    private static void ThrowIfNonCanonical(ReadOnlySpan<byte> scalars, CurveParameterSet curve, string parameterName)
    {
        for(int offset = 0; offset < scalars.Length; offset += ScalarSize)
        {
            if(!WellKnownCurves.IsCanonicalScalar(scalars.Slice(offset, ScalarSize), curve))
            {
                throw new ArgumentException($"Scalar at byte offset {offset} encodes an integer at or above the scalar field order of {curve}.", parameterName);
            }
        }
    }
}
