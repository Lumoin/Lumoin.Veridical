using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The committed-witness GKR prover — the zk-wrapper shape Longfellow deploys, with Ligero in its
/// small role: the private inputs are committed via a Ligero tableau whose Merkle root is absorbed
/// into the transcript <em>before</em> any GKR challenge (fixing the witness first — the
/// commit-then-challenge order the walk's soundness rests on), the linear-time data-parallel GKR
/// run reduces the public output claim to two input claims at transcript-derived tensor points,
/// and Ligero proves just those two linear openings of the commitment. The verifier never sees
/// the inputs.
/// </summary>
/// <remarks>
/// The witness commitment is a standing <see cref="LigeroCommitment"/>: the tableau (witness +
/// quadratic-operand + masking rows) is built and encoded once, its root seeds the walks, and
/// the same commitment answers the opening proof after the challenges exist — the linear
/// constraints do not participate in the tableau, so they can bind late. The randomness factory
/// is drawn once per prove; it remains a factory only for signature stability. The flagged
/// follow-up that remains is padding the sumcheck transcript itself (full zero-knowledge of the
/// intermediate wire evaluations, reference zk/zk_prover.h).
/// </remarks>
internal static class GkrCommittedProver
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    public static GkrCommittedProof Prove(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        int copyCount,
        LigeroParameters parameters,
        Func<ScalarRandomDelegate> randomFactory,
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
        Prove(
            circuit, inputs, copyCount, parameters, [], [], [], randomFactory,
            add, subtract, multiply, invert, reduce, curve,
            transcript, squeeze, hash, columnHash, merkleHash, hashAlgorithm, pool);


    /// <summary>
    /// Proves the circuit with additional public statement constraints over the committed
    /// witness: sparse linear constraints (copy-to-copy equalities, public-value pins) and
    /// quadratic constraints (<c>W[z] = W[x]·W[y]</c>, e.g. bitness as <c>x = y = z</c>),
    /// proven in the same witness-opening Ligero proof as the walk's two tensor openings. The
    /// statement constraints are public data the verifier reconstructs itself; binding them
    /// into the transcript is the caller's statement absorb, like the outputs.
    /// </summary>
    public static GkrCommittedProof Prove(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        int copyCount,
        LigeroParameters parameters,
        ReadOnlySpan<LigeroLinearConstraint> statementConstraints,
        ReadOnlySpan<byte> statementTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> statementQuadratics,
        Func<ScalarRandomDelegate> randomFactory,
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
        Prove(
            [new GkrCommittedInstance(circuit, copyCount)], inputs, parameters,
            statementConstraints, statementTargets, statementQuadratics, randomFactory,
            add, subtract, multiply, invert, reduce, curve,
            transcript, squeeze, hash, columnHash, merkleHash, hashAlgorithm, pool);


    /// <summary>
    /// Proves several circuit instances against one shared commitment: the witness is the
    /// concatenation of each instance's copy-major input table in declaration order, committed
    /// once before any challenge; the data-parallel walks run sequentially on the shared
    /// transcript; and every walk's two tensor openings join the public statement constraints
    /// in a single witness-opening Ligero proof. Statement constraints address the concatenated
    /// witness, which is how wires of different instances relate (copy-to-copy glue across
    /// circuits, public-value pins, quadratic bitness).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Each walk's prover result is disposed by its using; the circuit proof it carries transfers ownership to the returned GkrCommittedProof, which disposes it.")]
    public static GkrCommittedProof Prove(
        GkrCommittedInstance[] instances,
        ReadOnlySpan<byte> witness,
        LigeroParameters parameters,
        ReadOnlySpan<LigeroLinearConstraint> statementConstraints,
        ReadOnlySpan<byte> statementTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> statementQuadratics,
        Func<ScalarRandomDelegate> randomFactory,
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
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(randomFactory);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);
        if(instances.Length == 0)
        {
            throw new ArgumentException("At least one circuit instance is required.", nameof(instances));
        }

        int witnessCount = 0;
        foreach(GkrCommittedInstance instance in instances)
        {
            ArgumentNullException.ThrowIfNull(instance.Circuit, nameof(instances));
            witnessCount += instance.CopyCount * instance.Circuit.InputCount;
        }

        if(parameters.WitnessCount != witnessCount || parameters.QuadraticConstraintCount != statementQuadratics.Length)
        {
            throw new ArgumentException($"The commitment parameters must cover exactly the {witnessCount} input wires and the {statementQuadratics.Length} statement quadratic constraints.", nameof(parameters));
        }

        if(witness.Length != witnessCount * ScalarSize)
        {
            throw new ArgumentException($"The concatenated instance inputs need {witnessCount * ScalarSize} bytes; received {witness.Length}.", nameof(witness));
        }

        if(statementTargets.Length % ScalarSize != 0)
        {
            throw new ArgumentException($"Statement targets must be whole canonical scalars; received {statementTargets.Length} bytes.", nameof(statementTargets));
        }

        int statementCount = statementTargets.Length / ScalarSize;

        //Fail fast on an unsatisfied public statement before paying for the tableau encode or
        //the walks; the quadratic constraints are checked by the tableau build itself.
        LigeroProver.AssertLinearConstraintsSatisfied(parameters, witness, statementCount, statementConstraints, statementTargets, add, multiply, subtract, curve, pool);

        using LigeroCommitment commitment = Commit(
            witness, parameters, statementQuadratics, randomFactory,
            add, subtract, multiply, invert, curve, transcript, hash, columnHash, merkleHash, hashAlgorithm, pool);

        return Prove(
            commitment, instances, statementConstraints, statementTargets,
            add, subtract, multiply, invert, reduce, curve, transcript, squeeze, hash, pool);
    }


    /// <summary>
    /// Commits the concatenated instance witness and absorbs its tableau root into the shared
    /// transcript — the first half of the commit-then-challenge split. Splitting lets the
    /// caller squeeze post-commitment challenges (a MAC key, a wiring constant) and build
    /// circuit instances or linear statement constraints that depend on them before calling
    /// <see cref="Prove(LigeroCommitment, GkrCommittedInstance[], ReadOnlySpan{LigeroLinearConstraint}, ReadOnlySpan{byte}, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarReduceDelegate, CurveParameterSet, FiatShamirTranscript, FiatShamirSqueezeDelegate, FiatShamirHashDelegate, BaseMemoryPool)"/>
    /// — the witness is fixed first, so such challenges remain sound. The quadratic statement
    /// constraints participate in the tableau and so must be known at commit time; linear
    /// constraints bind at prove time.
    /// </summary>
    public static LigeroCommitment Commit(
        ReadOnlySpan<byte> witness,
        LigeroParameters parameters,
        ReadOnlySpan<LigeroQuadraticConstraint> statementQuadratics,
        Func<ScalarRandomDelegate> randomFactory,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(randomFactory);
        ArgumentNullException.ThrowIfNull(transcript);

        if(witness.Length != parameters.WitnessCount * ScalarSize)
        {
            throw new ArgumentException($"The witness needs {parameters.WitnessCount * ScalarSize} bytes; received {witness.Length}.", nameof(witness));
        }

        LigeroCommitment commitment = LigeroProver.Commit(
            parameters, witness, statementQuadratics, randomFactory(),
            add, subtract, multiply, invert, columnHash, hashAlgorithm, merkleHash, curve, pool);
        transcript.AbsorbLigeroTableauRoot(commitment.Root, hash);

        return commitment;
    }


    /// <summary>
    /// Proves circuit instances against a standing commitment whose root the transcript has
    /// already absorbed — the second half of the split. The instances and the linear statement
    /// constraints may depend on challenges squeezed after the commit; the witness is read
    /// from the commitment. The commitment is not consumed; the caller disposes it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Each walk's prover result is disposed by its using; the circuit proof it carries transfers ownership to the returned GkrCommittedProof, which disposes it.")]
    public static GkrCommittedProof Prove(
        LigeroCommitment commitment,
        GkrCommittedInstance[] instances,
        ReadOnlySpan<LigeroLinearConstraint> statementConstraints,
        ReadOnlySpan<byte> statementTargets,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(instances);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);
        if(instances.Length == 0)
        {
            throw new ArgumentException("At least one circuit instance is required.", nameof(instances));
        }

        ReadOnlySpan<byte> witness = commitment.Witnesses;
        int witnessCount = 0;
        foreach(GkrCommittedInstance instance in instances)
        {
            ArgumentNullException.ThrowIfNull(instance.Circuit, nameof(instances));
            witnessCount += instance.CopyCount * instance.Circuit.InputCount;
        }

        if(commitment.Parameters.WitnessCount != witnessCount)
        {
            throw new ArgumentException($"The instances cover {witnessCount} input wires; the commitment holds {commitment.Parameters.WitnessCount}.", nameof(instances));
        }

        if(statementTargets.Length % ScalarSize != 0)
        {
            throw new ArgumentException($"Statement targets must be whole canonical scalars; received {statementTargets.Length} bytes.", nameof(statementTargets));
        }

        int statementCount = statementTargets.Length / ScalarSize;
        int openingCount = 2 * instances.Length;

        //The linear-time GKR walks over the private witness segments, sequentially on the
        //shared transcript; each yields two openings of the commitment at its tensor points.
        int coefficientCount = 2 * witnessCount;
        using IMemoryOwner<byte> coefficientOwner = pool.Rent(coefficientCount * ScalarSize);
        using IMemoryOwner<byte> targetOwner = pool.Rent((openingCount + statementCount) * ScalarSize);
        Span<byte> targets = targetOwner.Memory.Span[..((openingCount + statementCount) * ScalarSize)];
        var constraints = new LigeroLinearConstraint[coefficientCount + statementConstraints.Length];
        var circuitProofs = new GkrDataParallelProof[instances.Length];
        int witnessOffset = 0;
        int coefficientOffset = 0;
        for(int k = 0; k < instances.Length; k++)
        {
            GkrCircuit circuit = instances[k].Circuit;
            int copyCount = instances[k].CopyCount;
            int segment = copyCount * circuit.InputCount;
            using(GkrDataParallelProverResult result = GkrDataParallelProver.Prove(
                circuit, witness.Slice(witnessOffset * ScalarSize, segment * ScalarSize), copyCount,
                add, subtract, multiply, reduce, curve, transcript, squeeze, hash, pool))
            {
                circuitProofs[k] = result.Proof;
                GkrInputOpening.BuildConstraints(
                    result.CopyPoint.Span, result.InputLeftPoint.Span, result.InputRightPoint.Span,
                    copyCount, circuit.InputCount,
                    coefficientOwner.Memory.Slice(coefficientOffset * ScalarSize, 2 * segment * ScalarSize),
                    constraints.AsSpan(coefficientOffset, 2 * segment),
                    2 * k, witnessOffset,
                    subtract, multiply, curve, pool);
            }

            ReadOnlySpan<byte> finalValues = circuitProofs[k].LayerProofs[^1].HandProof.FinalValues.Span;
            finalValues.Slice(ScalarSize, 2 * ScalarSize).CopyTo(targets.Slice(2 * k * ScalarSize, 2 * ScalarSize));

            witnessOffset += segment;
            coefficientOffset += 2 * segment;
        }

        //The statement constraints follow the openings, re-indexed past them.
        for(int i = 0; i < statementConstraints.Length; i++)
        {
            LigeroLinearConstraint term = statementConstraints[i];
            constraints[coefficientCount + i] = new LigeroLinearConstraint(term.ConstraintIndex + openingCount, term.WitnessIndex, term.Coefficient);
        }

        statementTargets.CopyTo(targets[(openingCount * ScalarSize)..]);

        //The opening proof's own transcript is seeded from the walks' end state, binding it to
        //the whole interaction (the claims were absorbed before this squeeze).
        Span<byte> openingSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(GkrTranscriptLabels.WitnessOpening, openingSeed, squeeze, hash);

        LigeroProof witnessProof = LigeroProver.Prove(
            commitment, openingCount + statementCount, constraints, targets, openingSeed,
            add, subtract, multiply, invert, reduce, hash, squeeze, curve, pool);

        return new GkrCommittedProof(circuitProofs, witnessProof);
    }
}
