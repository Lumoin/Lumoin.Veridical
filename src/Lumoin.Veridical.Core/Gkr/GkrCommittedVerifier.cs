using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The committed-witness GKR verifier: absorbs the witness commitment's tableau root from the
/// received opening proof (replaying the prover's commit-then-challenge order), runs the
/// data-parallel GKR walk down to the input claims, derives the opening seed from the walk's end
/// state, and Ligero-verifies the two linear openings of the commitment at the tensor points.
/// The verifier never sees the inputs — circuit, outputs and proof are its whole view.
/// </summary>
internal static class GkrCommittedVerifier
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    public static bool Verify(
        GkrCircuit circuit,
        ReadOnlySpan<byte> outputs,
        int copyCount,
        GkrCommittedProof proof,
        LigeroParameters parameters,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm,
        BaseMemoryPool pool) =>
        Verify(
            circuit, outputs, copyCount, proof, parameters, [], [], [],
            add, subtract, multiply, invert, reduce, curve,
            transcript, squeeze, hash, columnHash, merkleHash, hashAlgorithm, pool);


    /// <summary>
    /// Verifies a proof carrying additional public statement constraints over the committed
    /// witness — sparse linear constraints (copy-to-copy equalities, public-value pins) and
    /// quadratic bitness-style constraints — checked in the same witness-opening Ligero proof
    /// as the walk's two tensor openings. The verifier builds the statement itself from public
    /// data; a proof over a witness violating any of it does not verify.
    /// </summary>
    public static bool Verify(
        GkrCircuit circuit,
        ReadOnlySpan<byte> outputs,
        int copyCount,
        GkrCommittedProof proof,
        LigeroParameters parameters,
        ReadOnlySpan<LigeroLinearConstraint> statementConstraints,
        ReadOnlySpan<byte> statementTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> statementQuadratics,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        return Verify(
            [new GkrCommittedInstance(circuit, copyCount)], outputs, proof, parameters,
            statementConstraints, statementTargets, statementQuadratics,
            add, subtract, multiply, invert, reduce, curve,
            transcript, squeeze, hash, columnHash, merkleHash, hashAlgorithm, pool);
    }


    /// <summary>
    /// Verifies several circuit instances against one shared commitment: the claimed outputs
    /// are the concatenation of each instance's copy-major output table in declaration order,
    /// the walks replay sequentially on the shared transcript, and every walk's two tensor
    /// openings join the public statement constraints in the single witness-opening Ligero
    /// check. The statement addresses the concatenated witness, relating wires across
    /// instances.
    /// </summary>
    public static bool Verify(
        GkrCommittedInstance[] instances,
        ReadOnlySpan<byte> outputs,
        GkrCommittedProof proof,
        LigeroParameters parameters,
        ReadOnlySpan<LigeroLinearConstraint> statementConstraints,
        ReadOnlySpan<byte> statementTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> statementQuadratics,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(instances);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);
        if(instances.Length == 0 || proof.CircuitProofs.Length != instances.Length)
        {
            throw new ArgumentException($"The proof carries {proof.CircuitProofs.Length} circuit proofs for {instances.Length} instances.", nameof(instances));
        }

        int witnessCount = 0;
        int outputLength = 0;
        foreach(GkrCommittedInstance instance in instances)
        {
            ArgumentNullException.ThrowIfNull(instance.Circuit, nameof(instances));
            witnessCount += instance.CopyCount * instance.Circuit.InputCount;
            outputLength += instance.CopyCount * instance.Circuit.Layers[0].OutputCount * ScalarSize;
        }

        if(parameters.WitnessCount != witnessCount || parameters.QuadraticConstraintCount != statementQuadratics.Length)
        {
            throw new ArgumentException($"The commitment parameters must cover exactly the {witnessCount} input wires and the {statementQuadratics.Length} statement quadratic constraints.", nameof(parameters));
        }

        if(outputs.Length != outputLength)
        {
            throw new ArgumentException($"The concatenated instance outputs need {outputLength} bytes; received {outputs.Length}.", nameof(outputs));
        }

        if(statementTargets.Length % ScalarSize != 0)
        {
            throw new ArgumentException($"Statement targets must be whole canonical scalars; received {statementTargets.Length} bytes.", nameof(statementTargets));
        }

        int statementCount = statementTargets.Length / ScalarSize;
        int openingCount = 2 * instances.Length;

        //The commitment fixes the witness before any challenge.
        AbsorbCommitmentRoot(proof, transcript, hash);

        return VerifyFromAbsorbedRoot(
            instances, outputs, proof, parameters, statementConstraints, statementTargets, statementQuadratics,
            add, subtract, multiply, invert, reduce, curve, transcript, squeeze, hash, columnHash, merkleHash, hashAlgorithm, pool);
    }


    /// <summary>
    /// Absorbs the proof's commitment root into the shared transcript — the verifier's half of
    /// the commit-then-challenge split. The caller may then squeeze the same post-commitment
    /// challenges the prover did (a MAC key, a wiring constant), build the instances and
    /// statement that depend on them, and finish with <see cref="VerifyFromAbsorbedRoot"/>.
    /// </summary>
    public static void AbsorbCommitmentRoot(GkrCommittedProof proof, FiatShamirTranscript transcript, FiatShamirHashDelegate hash)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);

        transcript.AbsorbLigeroTableauRoot(proof.WitnessProof.Root, hash);
    }


    /// <summary>
    /// Verifies against a transcript that has already absorbed the commitment root via
    /// <see cref="AbsorbCommitmentRoot"/> — the instances and the linear statement may depend
    /// on challenges squeezed in between.
    /// </summary>
    public static bool VerifyFromAbsorbedRoot(
        GkrCommittedInstance[] instances,
        ReadOnlySpan<byte> outputs,
        GkrCommittedProof proof,
        LigeroParameters parameters,
        ReadOnlySpan<LigeroLinearConstraint> statementConstraints,
        ReadOnlySpan<byte> statementTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> statementQuadratics,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(instances);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);

        int witnessCount = 0;
        foreach(GkrCommittedInstance instance in instances)
        {
            witnessCount += instance.CopyCount * instance.Circuit.InputCount;
        }

        int statementCount = statementTargets.Length / ScalarSize;
        int openingCount = 2 * instances.Length;

        int coefficientCount = 2 * witnessCount;
        using IMemoryOwner<byte> coefficientOwner = pool.Rent(coefficientCount * ScalarSize);
        using IMemoryOwner<byte> targetOwner = pool.Rent((openingCount + statementCount) * ScalarSize);
        Span<byte> combinedTargets = targetOwner.Memory.Span[..((openingCount + statementCount) * ScalarSize)];
        var constraints = new LigeroLinearConstraint[coefficientCount + statementConstraints.Length];
        int witnessOffset = 0;
        int coefficientOffset = 0;
        int outputOffset = 0;
        for(int k = 0; k < instances.Length; k++)
        {
            GkrCircuit circuit = instances[k].Circuit;
            int copyCount = instances[k].CopyCount;
            int segment = copyCount * circuit.InputCount;
            int outputBytes = copyCount * circuit.Layers[0].OutputCount * ScalarSize;

            int logCopies = BitOperations.Log2((uint)copyCount);
            int inputLogWidth = BitOperations.Log2((uint)circuit.InputCount);
            using IMemoryOwner<byte> claimOwner = pool.Rent((logCopies + (2 * inputLogWidth)) * ScalarSize);
            Span<byte> copyPoint = claimOwner.Memory.Span[..(logCopies * ScalarSize)];
            Span<byte> leftPoint = claimOwner.Memory.Span.Slice(logCopies * ScalarSize, inputLogWidth * ScalarSize);
            Span<byte> rightPoint = claimOwner.Memory.Span.Slice((logCopies + inputLogWidth) * ScalarSize, inputLogWidth * ScalarSize);
            Span<byte> targets = combinedTargets.Slice(2 * k * ScalarSize, 2 * ScalarSize);

            if(!GkrDataParallelVerifier.VerifyToInputClaims(
                circuit, outputs.Slice(outputOffset, outputBytes), copyCount, proof.CircuitProofs[k],
                copyPoint, leftPoint, rightPoint, targets[..ScalarSize], targets[ScalarSize..],
                add, subtract, multiply, invert, reduce, curve, transcript, squeeze, hash, pool))
            {
                return false;
            }

            GkrInputOpening.BuildConstraints(
                copyPoint, leftPoint, rightPoint, copyCount, circuit.InputCount,
                coefficientOwner.Memory.Slice(coefficientOffset * ScalarSize, 2 * segment * ScalarSize),
                constraints.AsSpan(coefficientOffset, 2 * segment),
                2 * k, witnessOffset,
                subtract, multiply, curve, pool);

            witnessOffset += segment;
            coefficientOffset += 2 * segment;
            outputOffset += outputBytes;
        }

        //The opening seed is derived from the same end state the prover squeezed.
        Span<byte> openingSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(GkrTranscriptLabels.WitnessOpening, openingSeed, squeeze, hash);

        //The statement constraints follow the openings, re-indexed past them.
        for(int i = 0; i < statementConstraints.Length; i++)
        {
            LigeroLinearConstraint term = statementConstraints[i];
            constraints[coefficientCount + i] = new LigeroLinearConstraint(term.ConstraintIndex + openingCount, term.WitnessIndex, term.Coefficient);
        }

        statementTargets.CopyTo(combinedTargets[(openingCount * ScalarSize)..]);

        return LigeroVerifier.Verify(
            parameters, proof.WitnessProof, openingCount + statementCount, constraints, combinedTargets, statementQuadratics, openingSeed,
            add, subtract, multiply, invert, reduce, hash, squeeze, columnHash, merkleHash, hashAlgorithm, curve, pool);
    }
}
