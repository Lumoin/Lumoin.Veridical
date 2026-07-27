using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The LogUp-GKR lookup-argument prover (Papini–Haböck, ePrint 2023/1284):
/// proves that every value of the witness columns appears in the public table
/// while committing only ONE additional column — the counted multiplicities.
/// The fractional sum is evaluated by a binary tree of projective fraction
/// additions and proven layer by layer with cascaded degree-3 sumchecks; no
/// helper column and no prover-side field inversion exist in this variant.
/// </summary>
/// <remarks>
/// <para>
/// Transcript schedule (mirrored exactly by <see cref="LogUpGkrVerifier"/>):
/// instance shape and table bytes, witness commitments, multiplicity
/// commitment — then the denominator challenge — then the four root values —
/// then per layer: the batching challenge, the sumcheck rounds, the
/// terminating quad, and the line-merge challenge — then the claimed
/// evaluations and the openings. The multiplicity column is counted here from
/// the witness and table, never accepted from the caller.
/// </para>
/// <para>
/// Sound but not hiding: openings disclose the opened evaluations.
/// </para>
/// </remarks>
public static class LogUpGkrProver
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Proves that every value of the <paramref name="witnessEvaluations"/>
    /// columns appears in <paramref name="tableEvaluations"/>.
    /// </summary>
    /// <param name="tableEvaluations">The public table column, <c>2^variableCount × 32</c> canonical bytes; duplicates allowed.</param>
    /// <param name="witnessEvaluations">The witness columns concatenated.</param>
    /// <param name="variableCount">The row variable count; <c>variableCount + ⌈log2(M+1)⌉</c> must stay within <see cref="LogUpProver.MaximumVariableCount"/>.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>.</param>
    /// <param name="pcs">The polynomial-commitment provider.</param>
    /// <param name="transcript">The Fiat-Shamir transcript; the caller separates domains.</param>
    /// <param name="hash">The transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="reduce">The wide-bytes-to-scalar reduction backend.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="mleEvaluate">The multilinear-evaluation backend for the claimed terminal evaluations.</param>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <returns>The proof; ownership transfers to the caller.</returns>
    /// <exception cref="ArgumentException">When an input is malformed or a witness value is absent from the table.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of commitments and openings transfers to the returned LogUpGkrProof; exceptional paths dispose the accumulated parts in the catch block.")]
    public static LogUpGkrProof Prove(
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
        MleEvaluateDelegate mleEvaluate,
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
        ArgumentNullException.ThrowIfNull(mleEvaluate);
        ArgumentNullException.ThrowIfNull(pool);
        LogUpProver.ValidateShape(tableEvaluations, witnessEvaluations, variableCount, witnessColumnCount);

        int selectorVariableCount = LogUpGkrProof.SelectorVariableCountFor(witnessColumnCount);
        int totalVariableCount = variableCount + selectorVariableCount;
        if(totalVariableCount > LogUpProver.MaximumVariableCount)
        {
            throw new ArgumentOutOfRangeException(nameof(variableCount), variableCount, $"The row variable count plus {selectorVariableCount} selector variables exceeds the operational maximum of {LogUpProver.MaximumVariableCount} tree variables.");
        }

        CurveParameterSet curve = pcs.Curve;
        LogUpProver.ThrowIfNonCanonical(tableEvaluations, curve, nameof(tableEvaluations));
        LogUpProver.ThrowIfNonCanonical(witnessEvaluations, curve, nameof(witnessEvaluations));

        int rowCount = 1 << variableCount;
        int leafCount = 1 << totalVariableCount;

        LogUpProver.AbsorbGkrInstanceShape(transcript, variableCount, witnessColumnCount, curve, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.TableEvaluations), tableEvaluations, hash);

        var commitments = new List<PolynomialCommitment>(witnessColumnCount + 1);
        var blinds = new List<PolynomialCommitmentBlind>(witnessColumnCount + 1);
        var columnMles = new List<MultilinearExtension>(witnessColumnCount + 1);
        var openings = new List<PolynomialOpening>(witnessColumnCount + 1);
        IMemoryOwner<byte>? rootOwner = null;
        IMemoryOwner<byte>? layersOwner = null;
        IMemoryOwner<byte>? claimedOwner = null;
        IMemoryOwner<byte>[]? treeLayers = null;
        try
        {
            for(int column = 0; column < witnessColumnCount; column++)
            {
                MultilinearExtension witnessMle = MultilinearExtension.FromEvaluations(
                    witnessEvaluations.Slice(column * rowCount * ScalarSize, rowCount * ScalarSize), variableCount, curve, pool);
                columnMles.Add(witnessMle);
                (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = pcs.Commit(witnessMle, pool);
                commitments.Add(commitment);
                blinds.Add(blind);
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.WitnessCommitment), commitment.AsReadOnlySpan(), hash);
            }

            using IMemoryOwner<byte> multiplicityColumnOwner = LogUpColumns.BuildMultiplicities(
                tableEvaluations, witnessEvaluations, variableCount, witnessColumnCount, pool);
            ReadOnlySpan<byte> multiplicityColumn = multiplicityColumnOwner.Memory.Span[..(rowCount * ScalarSize)];

            MultilinearExtension multiplicityMle = MultilinearExtension.FromEvaluations(multiplicityColumn, variableCount, curve, pool);
            columnMles.Add(multiplicityMle);
            (PolynomialCommitment multiplicityCommitment, PolynomialCommitmentBlind multiplicityBlind) = pcs.Commit(multiplicityMle, pool);
            commitments.Add(multiplicityCommitment);
            blinds.Add(multiplicityBlind);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.MultiplicityCommitment), multiplicityCommitment.AsReadOnlySpan(), hash);

            Span<byte> denominatorChallenge = stackalloc byte[ScalarSize];
            LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrDenominatorChallenge, denominatorChallenge, squeeze, hash, reduce, curve);

            //The fraction tree: leaves, then every layer down to the two
            //values below the root.
            using IMemoryOwner<byte> leafNumeratorOwner = pool.Rent(leafCount * ScalarSize);
            Span<byte> leafNumerators = leafNumeratorOwner.Memory.Span[..(leafCount * ScalarSize)];
            using IMemoryOwner<byte> leafDenominatorOwner = pool.Rent(leafCount * ScalarSize);
            Span<byte> leafDenominators = leafDenominatorOwner.Memory.Span[..(leafCount * ScalarSize)];
            LogUpGkrCircuit.BuildLeaves(
                tableEvaluations, witnessEvaluations, multiplicityColumn, denominatorChallenge,
                variableCount, witnessColumnCount, selectorVariableCount,
                leafNumerators, leafDenominators, subtract, curve);

            treeLayers = LogUpGkrCircuit.BuildLayers(leafNumerators, leafDenominators, totalVariableCount, add, multiply, curve, pool);

            //Root message: the two fractions below the root, absorbed before
            //the first line-merge challenge.
            rootOwner = pool.Rent(LogUpGkrProof.QuadScalarCount * ScalarSize);
            Span<byte> rootValues = rootOwner.Memory.Span[..(LogUpGkrProof.QuadScalarCount * ScalarSize)];
            ReadOnlySpan<byte> layerOne = treeLayers[1].Memory.Span[..(2 * 2 * ScalarSize)];
            layerOne[..(2 * ScalarSize)].CopyTo(rootValues[..(2 * ScalarSize)]);
            layerOne.Slice(2 * ScalarSize, 2 * ScalarSize).CopyTo(rootValues.Slice(2 * ScalarSize, 2 * ScalarSize));
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.GkrRootValues), rootValues, hash);

            layersOwner = pool.Rent(LogUpGkrProof.GetLayerMessagesLength(totalVariableCount));
            Span<byte> layerMessages = layersOwner.Memory.Span[..LogUpGkrProof.GetLayerMessagesLength(totalVariableCount)];
            using IMemoryOwner<byte> pointOwner = pool.Rent(totalVariableCount * ScalarSize);
            Span<byte> point = pointOwner.Memory.Span[..(totalVariableCount * ScalarSize)];

            //Line-merge at the root: claims move to the point (μ₀).
            Span<byte> lineChallenge = stackalloc byte[ScalarSize];
            LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLineChallenge, lineChallenge, squeeze, hash, reduce, curve);
            lineChallenge.CopyTo(point[..ScalarSize]);

            int layerMessageOffset = 0;
            Span<byte> foldingChallenge = stackalloc byte[ScalarSize];
            Span<byte> roundChallenge = stackalloc byte[ScalarSize];
            for(int layer = 1; layer < totalVariableCount; layer++)
            {
                int layerSize = 1 << layer;
                LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLayerFoldingChallenge, foldingChallenge, squeeze, hash, reduce, curve);

                //Working copies: the kernel over the current point and the
                //four halves of the upper layer (the leaves when the upper
                //layer is the input layer).
                using IMemoryOwner<byte> kernelOwner = pool.Rent(layerSize * ScalarSize);
                Span<byte> kernelTable = kernelOwner.Memory.Span[..(layerSize * ScalarSize)];
                LogUpGkrSumcheck.BuildKernelTable(point[..(layer * ScalarSize)], layer, kernelTable, subtract, multiply, curve);

                ReadOnlySpan<byte> upperNumerators = layer + 1 == totalVariableCount
                    ? leafNumerators
                    : treeLayers[layer + 1].Memory.Span[..((1 << (layer + 1)) * ScalarSize)];
                ReadOnlySpan<byte> upperDenominators = layer + 1 == totalVariableCount
                    ? leafDenominators
                    : treeLayers[layer + 1].Memory.Span.Slice((1 << (layer + 1)) * ScalarSize, (1 << (layer + 1)) * ScalarSize);

                //Four separate rents: a combined buffer would need
                //4 · 2^24 · 32 = 2^31 bytes at the maximum tree shape —
                //past what an int-length span can address — while each half
                //stays comfortably inside it.
                using IMemoryOwner<byte> numeratorLowOwner = pool.Rent(layerSize * ScalarSize);
                Span<byte> numeratorLow = numeratorLowOwner.Memory.Span[..(layerSize * ScalarSize)];
                using IMemoryOwner<byte> numeratorHighOwner = pool.Rent(layerSize * ScalarSize);
                Span<byte> numeratorHigh = numeratorHighOwner.Memory.Span[..(layerSize * ScalarSize)];
                using IMemoryOwner<byte> denominatorLowOwner = pool.Rent(layerSize * ScalarSize);
                Span<byte> denominatorLow = denominatorLowOwner.Memory.Span[..(layerSize * ScalarSize)];
                using IMemoryOwner<byte> denominatorHighOwner = pool.Rent(layerSize * ScalarSize);
                Span<byte> denominatorHigh = denominatorHighOwner.Memory.Span[..(layerSize * ScalarSize)];
                upperNumerators[..(layerSize * ScalarSize)].CopyTo(numeratorLow);
                upperNumerators.Slice(layerSize * ScalarSize, layerSize * ScalarSize).CopyTo(numeratorHigh);
                upperDenominators[..(layerSize * ScalarSize)].CopyTo(denominatorLow);
                upperDenominators.Slice(layerSize * ScalarSize, layerSize * ScalarSize).CopyTo(denominatorHigh);

                int currentSize = layerSize;
                for(int round = 0; round < layer; round++)
                {
                    Span<byte> roundMessage = layerMessages.Slice(layerMessageOffset, LogUpGkrSumcheck.RoundEvaluationCount * ScalarSize);
                    LogUpGkrSumcheck.ComputeRoundEvaluations(
                        kernelTable[..(currentSize * ScalarSize)],
                        numeratorLow[..(currentSize * ScalarSize)],
                        numeratorHigh[..(currentSize * ScalarSize)],
                        denominatorLow[..(currentSize * ScalarSize)],
                        denominatorHigh[..(currentSize * ScalarSize)],
                        layer - round,
                        foldingChallenge,
                        roundMessage,
                        add, subtract, multiply, curve);

                    transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.GkrLayerRoundPolynomial), roundMessage, hash);
                    LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLayerRoundChallenge, roundChallenge, squeeze, hash, reduce, curve);
                    roundChallenge.CopyTo(point.Slice(round * ScalarSize, ScalarSize));

                    LogUpSumcheck.FoldInPlace(kernelTable, currentSize, roundChallenge, add, subtract, multiply, curve);
                    LogUpSumcheck.FoldInPlace(numeratorLow, currentSize, roundChallenge, add, subtract, multiply, curve);
                    LogUpSumcheck.FoldInPlace(numeratorHigh, currentSize, roundChallenge, add, subtract, multiply, curve);
                    LogUpSumcheck.FoldInPlace(denominatorLow, currentSize, roundChallenge, add, subtract, multiply, curve);
                    LogUpSumcheck.FoldInPlace(denominatorHigh, currentSize, roundChallenge, add, subtract, multiply, curve);
                    layerMessageOffset += LogUpGkrSumcheck.RoundEvaluationCount * ScalarSize;
                    currentSize >>= 1;
                }

                //Terminating quad: the four half-table evaluations at the
                //sumcheck point, absorbed before the line-merge challenge.
                Span<byte> quad = layerMessages.Slice(layerMessageOffset, LogUpGkrProof.QuadScalarCount * ScalarSize);
                numeratorLow[..ScalarSize].CopyTo(quad[..ScalarSize]);
                numeratorHigh[..ScalarSize].CopyTo(quad.Slice(ScalarSize, ScalarSize));
                denominatorLow[..ScalarSize].CopyTo(quad.Slice(2 * ScalarSize, ScalarSize));
                denominatorHigh[..ScalarSize].CopyTo(quad.Slice(3 * ScalarSize, ScalarSize));
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.GkrLayerTerminatingValues), quad, hash);
                layerMessageOffset += LogUpGkrProof.QuadScalarCount * ScalarSize;

                LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLineChallenge, lineChallenge, squeeze, hash, reduce, curve);
                lineChallenge.CopyTo(point.Slice(layer * ScalarSize, ScalarSize));
            }

            //Claimed terminal evaluations at the row part of the final point,
            //absorbed, then opened in the same order.
            claimedOwner = pool.Rent((witnessColumnCount + 1) * ScalarSize);
            Span<byte> claimedEvaluations = claimedOwner.Memory.Span[..((witnessColumnCount + 1) * ScalarSize)];
            Scalar[] rowPoint = LogUpProver.ToScalarArray(point[..(variableCount * ScalarSize)], variableCount, curve, pool);
            try
            {
                for(int column = 0; column <= witnessColumnCount; column++)
                {
                    using Scalar evaluation = columnMles[column].Evaluate(rowPoint, mleEvaluate, pool);
                    evaluation.AsReadOnlySpan().CopyTo(claimedEvaluations.Slice(column * ScalarSize, ScalarSize));
                    string label = column < witnessColumnCount
                        ? WellKnownLogUpTranscriptLabels.GkrWitnessEvaluation
                        : WellKnownLogUpTranscriptLabels.GkrMultiplicityEvaluation;
                    transcript.AbsorbBytes(new FiatShamirOperationLabel(label), claimedEvaluations.Slice(column * ScalarSize, ScalarSize), hash);
                }

                for(int column = 0; column <= witnessColumnCount; column++)
                {
                    (PolynomialOpening opening, Scalar claimedValue) = pcs.Open(
                        commitments[column], blinds[column], columnMles[column], rowPoint, transcript, pool);
                    openings.Add(opening);
                    using(claimedValue)
                    {
                        if(!claimedValue.AsReadOnlySpan().SequenceEqual(claimedEvaluations.Slice(column * ScalarSize, ScalarSize)))
                        {
                            throw new InvalidOperationException($"Opening {column} evaluated to a value different from the claimed terminal evaluation; the point conventions diverged.");
                        }
                    }
                }
            }
            finally
            {
                foreach(Scalar coordinate in rowPoint)
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

            return new LogUpGkrProof(
                variableCount,
                witnessColumnCount,
                curve,
                witnessCommitmentArray,
                commitments[witnessColumnCount],
                rootOwner,
                layersOwner,
                claimedOwner,
                witnessOpeningArray,
                openings[witnessColumnCount]);
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
            rootOwner?.Dispose();
            layersOwner?.Dispose();
            claimedOwner?.Dispose();
            throw;
        }
        finally
        {
            if(treeLayers is not null)
            {
                for(int layer = 1; layer < treeLayers.Length; layer++)
                {
                    treeLayers[layer]?.Dispose();
                }
            }
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
}
