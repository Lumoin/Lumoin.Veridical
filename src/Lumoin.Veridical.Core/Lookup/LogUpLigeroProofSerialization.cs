using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The wire format of a <see cref="LogUpProof"/> whose polynomial-commitment
/// scheme is Ligero: the LogUp sibling of <see cref="Spartan.LigeroSpartanProof"/>'s
/// layout doctrine. Every section size is a pure function of the argument
/// dimensions — the variable count, the witness-column count, the opened-column
/// query count, the inverse code rate and the Merkle digest size — all known to
/// both endpoints, so the layout carries no length prefixes and a hostile
/// length cannot steer the parse.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Witness-column commitments, in column order (<c>witnessColumnCount</c> column-commitment roots of <c>digestSizeBytes</c> each).</description></item>
///   <item><description>Multiplicity-column commitment (<c>digestSizeBytes</c> bytes).</description></item>
///   <item><description>Helper-column commitment (<c>digestSizeBytes</c> bytes).</description></item>
///   <item><description>Sumcheck round messages (<c>variableCount × (witnessColumnCount + 4) × 32</c> bytes).</description></item>
///   <item><description>Claimed evaluations <c>w_1(r), …, w_M(r), m(r), h(r)</c> (<c>(witnessColumnCount + 2) × 32</c> bytes).</description></item>
///   <item><description>Witness-column openings, in column order (serialized Ligero evaluation openings over <c>variableCount</c> variables).</description></item>
///   <item><description>Multiplicity-column opening.</description></item>
///   <item><description>Helper-column opening.</description></item>
/// </list>
/// <para>
/// Canonicity is enforced in two layers. Reconstruction funnels through
/// <see cref="LogUpProof.FromParts"/>, which rejects non-canonical scalar
/// encodings in the sumcheck round messages and the claimed evaluations; the
/// scalars inside the commitment openings (the proximity and evaluation
/// responses and the opened columns) are rejected by the Ligero opening
/// verifier when the proof is checked. A proof that verifies therefore has
/// exactly one byte representation.
/// </para>
/// </remarks>
public static class LogUpLigeroProofSerialization
{
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The largest opened-column query count the wire format accepts. The most
    /// column-hungry supported configuration — the unique-decoding regime at
    /// the minimum inverse rate targeting 256 bits — needs about 617 columns,
    /// so the cap leaves ample headroom while keeping a single opening's
    /// serialized size within <see cref="int"/> range.
    /// </summary>
    public const int MaximumQueryCount = 1024;

    /// <summary>
    /// The largest inverse code rate <c>c</c> the wire format accepts. The rate
    /// is a proof-size lever — a larger <c>c</c> buys more soundness bits per
    /// opened column at the cost of a codeword <c>c</c> times its message — and
    /// the trade is exhausted long before this bound (256 already gives eight
    /// bits per column under conjectured capacity), so the cap only excludes
    /// shapes no deployment produces.
    /// </summary>
    public const int MaximumInverseRate = 256;

    /// <summary>
    /// The largest Merkle digest size in bytes the wire format accepts:
    /// <see cref="WellKnownMerkleHashParameters.MaximumDigestSizeBytes"/>, the
    /// bound the Merkle authentication-path reader enforces, so a digest size
    /// the codec admits is never one the path walk later rejects.
    /// </summary>
    public const int MaximumDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;


    /// <summary>
    /// The total wire-format byte size of a LogUp-over-Ligero proof with the
    /// supplied dimensions.
    /// </summary>
    /// <param name="variableCount">The hypercube variable count; in <c>[1, LogUpProver.MaximumVariableCount]</c>.</param>
    /// <param name="witnessColumnCount">The witness-column count; in <c>[1, LogUpProver.MaximumWitnessColumnCount]</c>.</param>
    /// <param name="queryCount">The Ligero opened-column query count; in <c>[1, MaximumQueryCount]</c>.</param>
    /// <param name="inverseRate">The Ligero inverse code rate; in <c>[2, MaximumInverseRate]</c>.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes; in <c>[1, MaximumDigestSizeBytes]</c>.</param>
    /// <param name="curve">The curve whose scalar field the argument runs over.</param>
    /// <returns>The exact serialized length in bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a dimension is out of range.</exception>
    /// <exception cref="ArgumentException">When the dimensions are individually in range but jointly describe a proof longer than <see cref="int.MaxValue"/> bytes.</exception>
    public static int GetBufferSizeBytes(int variableCount, int witnessColumnCount, int queryCount, int inverseRate, int digestSizeBytes, CurveParameterSet curve)
    {
        ValidateDimensions(variableCount, witnessColumnCount, queryCount, inverseRate, digestSizeBytes);

        long commitmentSection = (long)(witnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount) * digestSizeBytes;
        long roundSection = (long)variableCount * LogUpSumcheck.RoundEvaluationCount(witnessColumnCount) * ScalarSize;
        long claimedSection = (long)(witnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount) * ScalarSize;
        long openingSection = (long)(witnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount) * OpeningSizeBytes(variableCount, curve, queryCount, inverseRate, digestSizeBytes);
        long totalSize = commitmentSection + roundSection + claimedSection + openingSection;
        if(totalSize > int.MaxValue)
        {
            throw new ArgumentException($"The dimensions describe a proof of {totalSize} bytes, above the supported maximum of {int.MaxValue}.");
        }

        return (int)totalSize;
    }


    /// <summary>
    /// Serializes <paramref name="proof"/> into <paramref name="destination"/>,
    /// which must be exactly <see cref="GetBufferSizeBytes"/> long. The proof
    /// retains ownership of its parts; all bytes are copied.
    /// </summary>
    /// <param name="proof">The proof to serialize.</param>
    /// <param name="queryCount">The opened-column query count the openings were produced under.</param>
    /// <param name="inverseRate">The inverse code rate the openings were produced under.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes of the commitment scheme.</param>
    /// <param name="destination">Receives the wire bytes; exactly the expected length.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="proof"/> is null.</exception>
    /// <exception cref="ArgumentException">When a section of <paramref name="proof"/> or <paramref name="destination"/> does not match the expected layout.</exception>
    public static void Write(LogUpProof proof, int queryCount, int inverseRate, int digestSizeBytes, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(proof);

        int expected = GetBufferSizeBytes(proof.VariableCount, proof.WitnessColumnCount, queryCount, inverseRate, digestSizeBytes, proof.Curve);
        if(destination.Length != expected)
        {
            throw new ArgumentException($"The destination must be {expected} bytes for the proof's dimensions; received {destination.Length}.", nameof(destination));
        }

        int openingSize = OpeningSizeBytes(proof.VariableCount, proof.Curve, queryCount, inverseRate, digestSizeBytes);
        int offset = 0;
        for(int column = 0; column < proof.WitnessColumnCount; column++)
        {
            offset += CopySection(proof.WitnessCommitments[column].AsReadOnlySpan(), digestSizeBytes, destination, offset, $"witness commitment {column}");
        }

        offset += CopySection(proof.MultiplicityCommitment.AsReadOnlySpan(), digestSizeBytes, destination, offset, "multiplicity commitment");
        offset += CopySection(proof.HelperCommitment.AsReadOnlySpan(), digestSizeBytes, destination, offset, "helper commitment");

        ReadOnlySpan<byte> rounds = proof.GetRoundEvaluationBytes();
        rounds.CopyTo(destination.Slice(offset, rounds.Length));
        offset += rounds.Length;

        ReadOnlySpan<byte> claimed = proof.GetClaimedEvaluationBytes();
        claimed.CopyTo(destination.Slice(offset, claimed.Length));
        offset += claimed.Length;

        for(int column = 0; column < proof.WitnessColumnCount; column++)
        {
            offset += CopySection(proof.WitnessOpenings[column].AsReadOnlySpan(), openingSize, destination, offset, $"witness opening {column}");
        }

        offset += CopySection(proof.MultiplicityOpening.AsReadOnlySpan(), openingSize, destination, offset, "multiplicity opening");
        CopySection(proof.HelperOpening.AsReadOnlySpan(), openingSize, destination, offset, "helper opening");
    }


    /// <summary>
    /// Reconstructs a proof from its canonical wire bytes given the dimensions
    /// (recovered by the verifier from the claim it checks and the provider's
    /// parameters). Funnels through <see cref="LogUpProof.FromParts"/>, so
    /// non-canonical scalar encodings are rejected.
    /// </summary>
    /// <param name="bytes">The wire bytes; exactly <see cref="GetBufferSizeBytes"/> long.</param>
    /// <param name="variableCount">The hypercube variable count.</param>
    /// <param name="witnessColumnCount">The witness-column count.</param>
    /// <param name="queryCount">The opened-column query count.</param>
    /// <param name="inverseRate">The inverse code rate.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <param name="curve">The curve whose scalar field the argument runs over.</param>
    /// <param name="pool">The pool the reconstructed parts are rented from.</param>
    /// <returns>The reconstructed proof; ownership transfers to the caller.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is null.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> has the wrong length or a scalar encoding is non-canonical.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a dimension is out of range.</exception>
    public static LogUpProof FromBytes(
        ReadOnlySpan<byte> bytes,
        int variableCount,
        int witnessColumnCount,
        int queryCount,
        int inverseRate,
        int digestSizeBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int expected = GetBufferSizeBytes(variableCount, witnessColumnCount, queryCount, inverseRate, digestSizeBytes, curve);
        if(bytes.Length != expected)
        {
            throw new ArgumentException($"A LogUp-over-Ligero proof must be {expected} bytes for the supplied dimensions; received {bytes.Length}.", nameof(bytes));
        }

        int openingSize = OpeningSizeBytes(variableCount, curve, queryCount, inverseRate, digestSizeBytes);
        int roundLength = variableCount * LogUpSumcheck.RoundEvaluationCount(witnessColumnCount) * ScalarSize;
        int claimedLength = (witnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount) * ScalarSize;

        var witnessCommitments = new List<PolynomialCommitment>(witnessColumnCount);
        var witnessOpenings = new List<PolynomialOpening>(witnessColumnCount);
        PolynomialCommitment? multiplicityCommitment = null;
        PolynomialCommitment? helperCommitment = null;
        PolynomialOpening? multiplicityOpening = null;
        PolynomialOpening? helperOpening = null;
        try
        {
            int offset = 0;
            for(int column = 0; column < witnessColumnCount; column++)
            {
                witnessCommitments.Add(PolynomialCommitment.FromBytes(bytes.Slice(offset, digestSizeBytes), curve, CommitmentScheme.Ligero, pool));
                offset += digestSizeBytes;
            }

            multiplicityCommitment = PolynomialCommitment.FromBytes(bytes.Slice(offset, digestSizeBytes), curve, CommitmentScheme.Ligero, pool);
            offset += digestSizeBytes;
            helperCommitment = PolynomialCommitment.FromBytes(bytes.Slice(offset, digestSizeBytes), curve, CommitmentScheme.Ligero, pool);
            offset += digestSizeBytes;

            ReadOnlySpan<byte> roundEvaluationBytes = bytes.Slice(offset, roundLength);
            offset += roundLength;
            ReadOnlySpan<byte> claimedEvaluationBytes = bytes.Slice(offset, claimedLength);
            offset += claimedLength;

            for(int column = 0; column < witnessColumnCount; column++)
            {
                witnessOpenings.Add(PolynomialOpening.FromBytes(bytes.Slice(offset, openingSize), curve, CommitmentScheme.Ligero, pool));
                offset += openingSize;
            }

            multiplicityOpening = PolynomialOpening.FromBytes(bytes.Slice(offset, openingSize), curve, CommitmentScheme.Ligero, pool);
            offset += openingSize;
            helperOpening = PolynomialOpening.FromBytes(bytes.Slice(offset, openingSize), curve, CommitmentScheme.Ligero, pool);

            return LogUpProof.FromParts(
                variableCount,
                witnessColumnCount,
                curve,
                witnessCommitments,
                multiplicityCommitment,
                helperCommitment,
                roundEvaluationBytes,
                claimedEvaluationBytes,
                witnessOpenings,
                multiplicityOpening,
                helperOpening,
                pool);
        }
        catch
        {
            //Ownership transfers to the proof only when FromParts succeeds;
            //everything materialized before the throw is released here.
            foreach(PolynomialCommitment commitment in witnessCommitments)
            {
                commitment.Dispose();
            }
            foreach(PolynomialOpening opening in witnessOpenings)
            {
                opening.Dispose();
            }
            multiplicityCommitment?.Dispose();
            helperCommitment?.Dispose();
            multiplicityOpening?.Dispose();
            helperOpening?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Copies one proof section into the wire buffer after checking its exact
    /// expected length, returning the length so callers advance their offset.
    /// </summary>
    /// <param name="section">The section bytes to copy.</param>
    /// <param name="expectedLength">The exact length the layout requires.</param>
    /// <param name="destination">The wire buffer.</param>
    /// <param name="offset">The write offset inside <paramref name="destination"/>.</param>
    /// <param name="sectionName">The section name for the failure message.</param>
    /// <returns>The copied length.</returns>
    /// <exception cref="ArgumentException">When the section length mismatches the layout.</exception>
    private static int CopySection(ReadOnlySpan<byte> section, int expectedLength, Span<byte> destination, int offset, string sectionName)
    {
        if(section.Length != expectedLength)
        {
            throw new ArgumentException($"The {sectionName} must be {expectedLength} bytes; received {section.Length}.", nameof(section));
        }

        section.CopyTo(destination.Slice(offset, expectedLength));

        return expectedLength;
    }


    /// <summary>
    /// The serialized Ligero evaluation opening size for one committed column;
    /// every LogUp column spans the same hypercube, so all openings share one
    /// size.
    /// </summary>
    private static int OpeningSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int inverseRate, int digestSizeBytes)
    {
        return LigeroPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(variableCount, curve, queryCount, digestSizeBytes, inverseRate);
    }


    /// <summary>
    /// Rejects out-of-range argument dimensions before any size arithmetic.
    /// The upper caps bound every intermediate product of the capped
    /// dimensions — in particular the per-opening size, whose worst capped
    /// shape stays near 270 MB — so only the final section sum needs the
    /// widened total check in <see cref="GetBufferSizeBytes"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When a dimension is out of range.</exception>
    private static void ValidateDimensions(int variableCount, int witnessColumnCount, int queryCount, int inverseRate, int digestSizeBytes)
    {
        if(variableCount < 1 || variableCount > LogUpProver.MaximumVariableCount)
        {
            throw new ArgumentOutOfRangeException(nameof(variableCount), variableCount, $"The variable count must lie in [1, {LogUpProver.MaximumVariableCount}].");
        }

        if(witnessColumnCount < 1 || witnessColumnCount > LogUpProver.MaximumWitnessColumnCount)
        {
            throw new ArgumentOutOfRangeException(nameof(witnessColumnCount), witnessColumnCount, $"The witness-column count must lie in [1, {LogUpProver.MaximumWitnessColumnCount}].");
        }

        if(queryCount < 1 || queryCount > MaximumQueryCount)
        {
            throw new ArgumentOutOfRangeException(nameof(queryCount), queryCount, $"The query count must lie in [1, {MaximumQueryCount}].");
        }

        if(inverseRate < 2 || inverseRate > MaximumInverseRate)
        {
            throw new ArgumentOutOfRangeException(nameof(inverseRate), inverseRate, $"The inverse rate must lie in [2, {MaximumInverseRate}].");
        }

        if(digestSizeBytes < 1 || digestSizeBytes > MaximumDigestSizeBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(digestSizeBytes), digestSizeBytes, $"The digest size must lie in [1, {MaximumDigestSizeBytes}] bytes.");
        }
    }
}
