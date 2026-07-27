using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The LogUp lookup-argument prover (Haböck, ePrint 2022/1530, Protocol 2 at
/// chunk size <c>ℓ = M + 1</c>): proves that every value of the witness
/// columns appears in the public table, by committing the counted multiplicity
/// column and one helper column of fractional terms and running a single
/// degree-<c>M + 3</c> sumcheck over the combined zero-sum and
/// well-formedness identity.
/// </summary>
/// <remarks>
/// <para>
/// Transcript schedule (soundness-critical, mirrored exactly by
/// <see cref="LogUpVerifier"/>): instance shape and full table bytes, witness
/// commitments, multiplicity commitment — then the denominator challenge —
/// then the helper commitment — then the kernel point and folding challenge —
/// then the sumcheck rounds — then the claimed evaluations and the openings.
/// The multiplicity column is counted here from the witness and table, never
/// accepted from the caller, so it cannot depend on any challenge.
/// </para>
/// <para>
/// The argument is sound but not hiding: openings disclose the opened
/// evaluations. Completeness aborts (with an <see cref="ArgumentException"/>
/// from the batched inversion) in the negligible event the denominator
/// challenge collides with a committed value.
/// </para>
/// </remarks>
public static class LogUpProver
{
    private const int ScalarSize = Scalar.SizeBytes;

    //Wide-squeeze width for challenge derivation: 64 bytes keeps the
    //modular-reduction bias below 2^-256 (RFC 9380 L = 64), matching every
    //other challenge squeeze in the library.
    private const int SqueezeWideBytes = 64;

    /// <summary>
    /// The largest supported hypercube: 2^25 rows. A 26-variable column's
    /// byte length, <c>2^26 · 32 = 2^31</c>, already exceeds what an
    /// <see cref="int"/>-length span can address, so 25 is the operational
    /// ceiling of the span-based column layout. Together with
    /// <see cref="MaximumWitnessColumnCount"/> this caps the total looked-up
    /// count at <c>65 · 2^25 &lt; 2^32</c>, far below the ~2^252 scalar-field
    /// characteristic — the bound under which multiplicity counts cannot wrap
    /// (Eagen–Haböck, ePrint 2024/2067).
    /// </summary>
    public const int MaximumVariableCount = 25;

    /// <summary>
    /// The largest supported witness-column count. Sixty-four columns cover a
    /// byte-decomposition of 512-bit values against one table while keeping
    /// the per-round message at 68 scalars and the round degree at 67.
    /// </summary>
    public const int MaximumWitnessColumnCount = 64;


    /// <summary>
    /// Proves that every value of the <paramref name="witnessEvaluations"/>
    /// columns appears in <paramref name="tableEvaluations"/>.
    /// </summary>
    /// <param name="tableEvaluations">The public table column, <c>2^variableCount × 32</c> canonical big-endian bytes; duplicate entries are allowed.</param>
    /// <param name="witnessEvaluations">The witness columns concatenated, <c>witnessColumnCount × 2^variableCount × 32</c> canonical bytes.</param>
    /// <param name="variableCount">The hypercube variable count; in <c>[1, MaximumVariableCount]</c>.</param>
    /// <param name="witnessColumnCount">The witness-column count; in <c>[1, MaximumWitnessColumnCount]</c>.</param>
    /// <param name="pcs">The polynomial-commitment provider the columns are committed and opened through.</param>
    /// <param name="transcript">The Fiat-Shamir transcript; the caller separates domains.</param>
    /// <param name="hash">The transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="reduce">The wide-bytes-to-scalar reduction backend.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="invert">Scalar-invert delegate.</param>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <returns>The proof; ownership transfers to the caller.</returns>
    /// <exception cref="ArgumentException">When an input is malformed, a witness value is absent from the table, or a challenge collided with a committed value.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of commitments and openings transfers to the returned LogUpProof; exceptional paths dispose the accumulated parts in the catch block.")]
    public static LogUpProof Prove(
        ReadOnlySpan<byte> tableEvaluations,
        ReadOnlySpan<byte> witnessEvaluations,
        int variableCount,
        int witnessColumnCount,
        PolynomialCommitmentProvider pcs,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pcs);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ValidateShape(tableEvaluations, witnessEvaluations, variableCount, witnessColumnCount);

        CurveParameterSet curve = pcs.Curve;
        ThrowIfNonCanonical(tableEvaluations, curve, nameof(tableEvaluations));
        ThrowIfNonCanonical(witnessEvaluations, curve, nameof(witnessEvaluations));

        int size = 1 << variableCount;
        int evaluationCount = LogUpSumcheck.RoundEvaluationCount(witnessColumnCount);

        AbsorbInstanceShape(transcript, variableCount, witnessColumnCount, curve, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.TableEvaluations), tableEvaluations, hash);

        int committedColumnCount = witnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount;
        var commitments = new List<PolynomialCommitment>(committedColumnCount);
        var blinds = new List<PolynomialCommitmentBlind>(committedColumnCount);
        var columnMles = new List<MultilinearExtension>(committedColumnCount);
        var openings = new List<PolynomialOpening>(committedColumnCount);
        IMemoryOwner<byte>? roundOwner = null;
        IMemoryOwner<byte>? claimedOwner = null;
        try
        {
            //Witness and multiplicity commitments precede the denominator
            //challenge; the helper commitment precedes the kernel point and
            //folding challenge. A column committed after a challenge it can
            //depend on is the Frozen-Heart forgery shape.
            for(int column = 0; column < witnessColumnCount; column++)
            {
                MultilinearExtension witnessMle = MultilinearExtension.FromEvaluations(
                    witnessEvaluations.Slice(column * size * ScalarSize, size * ScalarSize), variableCount, curve, pool);
                columnMles.Add(witnessMle);
                (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = pcs.Commit(witnessMle, pool);
                commitments.Add(commitment);
                blinds.Add(blind);
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.WitnessCommitment), commitment.AsReadOnlySpan(), hash);
            }

            using IMemoryOwner<byte> multiplicityColumnOwner = LogUpColumns.BuildMultiplicities(
                tableEvaluations, witnessEvaluations, variableCount, witnessColumnCount, pool);
            ReadOnlySpan<byte> multiplicityColumn = multiplicityColumnOwner.Memory.Span[..(size * ScalarSize)];

            MultilinearExtension multiplicityMle = MultilinearExtension.FromEvaluations(multiplicityColumn, variableCount, curve, pool);
            columnMles.Add(multiplicityMle);
            (PolynomialCommitment multiplicityCommitment, PolynomialCommitmentBlind multiplicityBlind) = pcs.Commit(multiplicityMle, pool);
            commitments.Add(multiplicityCommitment);
            blinds.Add(multiplicityBlind);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.MultiplicityCommitment), multiplicityCommitment.AsReadOnlySpan(), hash);

            Span<byte> denominatorChallenge = stackalloc byte[ScalarSize];
            SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.DenominatorChallenge, denominatorChallenge, squeeze, hash, reduce, curve);

            using IMemoryOwner<byte> helperColumnOwner = LogUpColumns.BuildHelperColumn(
                tableEvaluations, witnessEvaluations, multiplicityColumn, denominatorChallenge,
                variableCount, witnessColumnCount, add, subtract, multiply, invert, curve, pool);
            ReadOnlySpan<byte> helperColumn = helperColumnOwner.Memory.Span[..(size * ScalarSize)];

            MultilinearExtension helperMle = MultilinearExtension.FromEvaluations(helperColumn, variableCount, curve, pool);
            columnMles.Add(helperMle);
            (PolynomialCommitment helperCommitment, PolynomialCommitmentBlind helperBlind) = pcs.Commit(helperMle, pool);
            commitments.Add(helperCommitment);
            blinds.Add(helperBlind);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.HelperCommitment), helperCommitment.AsReadOnlySpan(), hash);

            Scalar[] kernelPoint = SqueezeKernelPoint(transcript, variableCount, squeeze, hash, reduce, curve, pool);
            try
            {
                Span<byte> foldingChallenge = stackalloc byte[ScalarSize];
                SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.FoldingChallenge, foldingChallenge, squeeze, hash, reduce, curve);

                using MultilinearExtension kernelMle = SumcheckRoundComputation.BuildEqEvaluations(kernelPoint, subtract, multiply, curve, pool);

                //Working copies of every column, folded in place round by
                //round; witness columns keep their original stride.
                using IMemoryOwner<byte> helperTableOwner = pool.Rent(size * ScalarSize);
                Span<byte> helperTable = helperTableOwner.Memory.Span[..(size * ScalarSize)];
                helperColumn.CopyTo(helperTable);
                using IMemoryOwner<byte> multiplicityTableOwner = pool.Rent(size * ScalarSize);
                Span<byte> multiplicityTable = multiplicityTableOwner.Memory.Span[..(size * ScalarSize)];
                multiplicityColumn.CopyTo(multiplicityTable);
                using IMemoryOwner<byte> kernelTableOwner = pool.Rent(size * ScalarSize);
                Span<byte> kernelTable = kernelTableOwner.Memory.Span[..(size * ScalarSize)];
                kernelMle.AsReadOnlySpan().CopyTo(kernelTable);
                using IMemoryOwner<byte> tableTableOwner = pool.Rent(size * ScalarSize);
                Span<byte> tableTable = tableTableOwner.Memory.Span[..(size * ScalarSize)];
                tableEvaluations.CopyTo(tableTable);
                using IMemoryOwner<byte> witnessTablesOwner = pool.Rent(witnessColumnCount * size * ScalarSize);
                Span<byte> witnessTables = witnessTablesOwner.Memory.Span[..(witnessColumnCount * size * ScalarSize)];
                witnessEvaluations.CopyTo(witnessTables);

                roundOwner = pool.Rent(variableCount * evaluationCount * ScalarSize);
                Span<byte> roundEvaluations = roundOwner.Memory.Span[..(variableCount * evaluationCount * ScalarSize)];
                using IMemoryOwner<byte> challengesOwner = pool.Rent(variableCount * ScalarSize);
                Span<byte> challenges = challengesOwner.Memory.Span[..(variableCount * ScalarSize)];

                int currentSize = size;
                for(int round = 0; round < variableCount; round++)
                {
                    int remainingVariables = variableCount - round;
                    Span<byte> roundMessage = roundEvaluations.Slice(round * evaluationCount * ScalarSize, evaluationCount * ScalarSize);
                    LogUpSumcheck.ComputeRoundEvaluations(
                        helperTable[..(currentSize * ScalarSize)],
                        multiplicityTable[..(currentSize * ScalarSize)],
                        kernelTable[..(currentSize * ScalarSize)],
                        tableTable[..(currentSize * ScalarSize)],
                        witnessTables,
                        size,
                        remainingVariables,
                        witnessColumnCount,
                        denominatorChallenge,
                        foldingChallenge,
                        roundMessage,
                        add, subtract, multiply, curve, pool);

                    transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.SumcheckRoundPolynomial), roundMessage, hash);
                    Span<byte> challenge = challenges.Slice(round * ScalarSize, ScalarSize);
                    SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.SumcheckRoundChallenge, challenge, squeeze, hash, reduce, curve);

                    LogUpSumcheck.FoldInPlace(helperTable, currentSize, challenge, add, subtract, multiply, curve);
                    LogUpSumcheck.FoldInPlace(multiplicityTable, currentSize, challenge, add, subtract, multiply, curve);
                    LogUpSumcheck.FoldInPlace(kernelTable, currentSize, challenge, add, subtract, multiply, curve);
                    LogUpSumcheck.FoldInPlace(tableTable, currentSize, challenge, add, subtract, multiply, curve);
                    for(int column = 0; column < witnessColumnCount; column++)
                    {
                        LogUpSumcheck.FoldInPlace(witnessTables.Slice(column * size * ScalarSize, currentSize * ScalarSize), currentSize, challenge, add, subtract, multiply, curve);
                    }

                    currentSize >>= 1;
                }

                //Terminating fold values are the column evaluations at the
                //challenge point; absorb them, then open in the same order.
                claimedOwner = pool.Rent(committedColumnCount * ScalarSize);
                Span<byte> claimedEvaluations = claimedOwner.Memory.Span[..(committedColumnCount * ScalarSize)];
                for(int column = 0; column < witnessColumnCount; column++)
                {
                    witnessTables.Slice(column * size * ScalarSize, ScalarSize).CopyTo(claimedEvaluations.Slice(column * ScalarSize, ScalarSize));
                    transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.WitnessEvaluation), claimedEvaluations.Slice(column * ScalarSize, ScalarSize), hash);
                }

                multiplicityTable[..ScalarSize].CopyTo(claimedEvaluations.Slice(witnessColumnCount * ScalarSize, ScalarSize));
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.MultiplicityEvaluation), claimedEvaluations.Slice(witnessColumnCount * ScalarSize, ScalarSize), hash);
                helperTable[..ScalarSize].CopyTo(claimedEvaluations.Slice((witnessColumnCount + 1) * ScalarSize, ScalarSize));
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.HelperEvaluation), claimedEvaluations.Slice((witnessColumnCount + 1) * ScalarSize, ScalarSize), hash);

                Scalar[] openingPoint = ToScalarArray(challenges, variableCount, curve, pool);
                try
                {
                    for(int column = 0; column < committedColumnCount; column++)
                    {
                        (PolynomialOpening opening, Scalar claimedValue) = pcs.Open(
                            commitments[column], blinds[column], columnMles[column], openingPoint, transcript, pool);
                        openings.Add(opening);
                        using(claimedValue)
                        {
                            //The opening's claimed value must equal the
                            //terminating fold value — a divergence means the
                            //fold and evaluation variable orders drifted apart,
                            //which is a library defect, not bad input.
                            if(!claimedValue.AsReadOnlySpan().SequenceEqual(claimedEvaluations.Slice(column * ScalarSize, ScalarSize)))
                            {
                                throw new InvalidOperationException($"Opening {column} evaluated to a value different from the sumcheck's terminating fold; the fold and opening conventions diverged.");
                            }
                        }
                    }
                }
                finally
                {
                    foreach(Scalar coordinate in openingPoint)
                    {
                        coordinate.Dispose();
                    }
                }

                PolynomialCommitment[] witnessCommitmentArray = new PolynomialCommitment[witnessColumnCount];
                PolynomialOpening[] witnessOpeningArray = new PolynomialOpening[witnessColumnCount];
                for(int column = 0; column < witnessColumnCount; column++)
                {
                    witnessCommitmentArray[column] = commitments[column];
                    witnessOpeningArray[column] = openings[column];
                }

                return new LogUpProof(
                    variableCount,
                    witnessColumnCount,
                    curve,
                    witnessCommitmentArray,
                    commitments[witnessColumnCount],
                    commitments[witnessColumnCount + 1],
                    roundOwner,
                    claimedOwner,
                    witnessOpeningArray,
                    openings[witnessColumnCount],
                    openings[witnessColumnCount + 1]);
            }
            finally
            {
                foreach(Scalar coordinate in kernelPoint)
                {
                    coordinate.Dispose();
                }
            }
        }
        catch
        {
            foreach(PolynomialCommitment commitment in commitments)
            {
                commitment.Dispose();
            }
            foreach(PolynomialOpening opening in openings)
            {
                opening.Dispose();
            }
            roundOwner?.Dispose();
            claimedOwner?.Dispose();
            throw;
        }
        finally
        {
            foreach(PolynomialCommitmentBlind blind in blinds)
            {
                blind.Dispose();
            }
            foreach(MultilinearExtension mle in columnMles)
            {
                mle.Dispose();
            }
        }
    }


    internal static void ValidateShape(ReadOnlySpan<byte> tableEvaluations, ReadOnlySpan<byte> witnessEvaluations, int variableCount, int witnessColumnCount)
    {
        if(variableCount < 1 || variableCount > MaximumVariableCount)
        {
            throw new ArgumentOutOfRangeException(nameof(variableCount), variableCount, $"The variable count must lie in [1, {MaximumVariableCount}].");
        }

        if(witnessColumnCount < 1 || witnessColumnCount > MaximumWitnessColumnCount)
        {
            throw new ArgumentOutOfRangeException(nameof(witnessColumnCount), witnessColumnCount, $"The witness-column count must lie in [1, {MaximumWitnessColumnCount}].");
        }

        //Lengths are computed in long so an out-of-range shape can never wrap
        //the expectation into something a hostile span could satisfy.
        long size = 1L << variableCount;
        long expectedTableBytes = size * ScalarSize;
        if(tableEvaluations.Length != expectedTableBytes)
        {
            throw new ArgumentException($"A {variableCount}-variable table must be {expectedTableBytes} bytes; received {tableEvaluations.Length}.", nameof(tableEvaluations));
        }

        long expectedWitnessBytes = witnessColumnCount * size * ScalarSize;
        if(witnessEvaluations.Length != expectedWitnessBytes)
        {
            throw new ArgumentException($"{witnessColumnCount} witness columns of {variableCount} variables must be {expectedWitnessBytes} bytes; received {witnessEvaluations.Length}.", nameof(witnessEvaluations));
        }
    }


    internal static void AbsorbInstanceShape(FiatShamirTranscript transcript, int variableCount, int witnessColumnCount, CurveParameterSet curve, FiatShamirHashDelegate hash)
    {
        AbsorbShape(transcript, WellKnownLogUpTranscriptLabels.InstanceShape, variableCount, witnessColumnCount, curve, hash);
    }


    internal static void AbsorbGkrInstanceShape(FiatShamirTranscript transcript, int variableCount, int witnessColumnCount, CurveParameterSet curve, FiatShamirHashDelegate hash)
    {
        AbsorbShape(transcript, WellKnownLogUpTranscriptLabels.GkrInstanceShape, variableCount, witnessColumnCount, curve, hash);
    }


    private static void AbsorbShape(FiatShamirTranscript transcript, string label, int variableCount, int witnessColumnCount, CurveParameterSet curve, FiatShamirHashDelegate hash)
    {
        Span<byte> shape = stackalloc byte[3 * sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(shape, variableCount);
        BinaryPrimitives.WriteInt32BigEndian(shape[sizeof(int)..], witnessColumnCount);
        BinaryPrimitives.WriteInt32BigEndian(shape[(2 * sizeof(int))..], curve.Code);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(label), shape, hash);
    }


    internal static void SqueezeChallenge(FiatShamirTranscript transcript, string label, Span<byte> destination, FiatShamirSqueezeDelegate squeeze, FiatShamirHashDelegate hash, ScalarReduceDelegate reduce, CurveParameterSet curve)
    {
        Span<byte> wide = stackalloc byte[SqueezeWideBytes];
        transcript.SqueezeBytes(new FiatShamirOperationLabel(label), wide, squeeze, hash);
        reduce(wide, destination, curve);
    }


    internal static Scalar[] SqueezeKernelPoint(FiatShamirTranscript transcript, int variableCount, FiatShamirSqueezeDelegate squeeze, FiatShamirHashDelegate hash, ScalarReduceDelegate reduce, CurveParameterSet curve, BaseMemoryPool pool)
    {
        Scalar[] kernelPoint = new Scalar[variableCount];
        try
        {
            for(int i = 0; i < variableCount; i++)
            {
                kernelPoint[i] = transcript.SqueezeScalar(
                    new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.KernelPoint), squeeze, hash, reduce, curve, pool);
            }

            return kernelPoint;
        }
        catch
        {
            foreach(Scalar coordinate in kernelPoint)
            {
                coordinate?.Dispose();
            }
            throw;
        }
    }


    internal static Scalar[] ToScalarArray(ReadOnlySpan<byte> challenges, int count, CurveParameterSet curve, BaseMemoryPool pool)
    {
        Scalar[] scalars = new Scalar[count];
        try
        {
            for(int i = 0; i < count; i++)
            {
                scalars[i] = Scalar.FromCanonical(challenges.Slice(i * ScalarSize, ScalarSize), curve, pool);
            }

            return scalars;
        }
        catch
        {
            foreach(Scalar scalar in scalars)
            {
                scalar?.Dispose();
            }
            throw;
        }
    }


    internal static void ThrowIfNonCanonical(ReadOnlySpan<byte> scalars, CurveParameterSet curve, string parameterName)
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
