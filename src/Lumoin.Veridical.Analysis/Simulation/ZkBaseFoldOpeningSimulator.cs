using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Analysis.Simulation;

/// <summary>
/// The witness-free simulator of the full zero-knowledge BaseFold opening —
/// the running counterpart of <c>ZK-STATMASK-DESIGN.md</c> Appendix A's
/// simulator construction, and the artifact §7 recorded as the open
/// follow-on. Given only the public statement (the evaluation point
/// <c>z</c> and the claimed value <c>y</c>), it produces a commitment and
/// an opening that verify against <c>(z, y)</c> under a programmed
/// Fiat-Shamir oracle, without ever holding a witness that evaluates to
/// <c>y</c>.
/// </summary>
/// <remarks>
/// <para>
/// The construction leans on the protocol's own algebra instead of
/// re-deriving messages backwards. The simulator runs the honest prover
/// over a uniformly random fake witness <c>f*</c> (recording every oracle
/// response), obtaining a valid proof of <c>y* = f*(z)</c>, and then patches
/// the single revealed mask sum: <c>σ′ = σ + (y* − y)·ρ⁻¹</c>. The
/// verifier's initial claim <c>y + ρ·σ′</c> then equals the fake run's
/// <c>y* + ρ·σ</c>, every round polynomial decompresses against the same
/// running claim, and the terminal derivation
/// <c>s(r) = (claim − f(r)·eq_z(r))·ρ⁻¹</c> sees identical operands — the
/// entire numeric chain is byte-identical to the honest fake run. The one
/// thing the patch breaks is challenge <em>derivation</em>: σ′ is absorbed
/// before ρ is squeezed, so every post-divergence transcript state differs.
/// That is exactly the gap random-oracle programming closes — verification
/// runs against <see cref="ProgrammableFiatShamirOracle.CreateReplaySqueeze"/>,
/// which answers the verifier's queries with the recorded responses.
/// </para>
/// <para>
/// Distributionally the output is a real proof of a uniformly random
/// witness with σ shifted by a public function of <c>(y*, y, ρ)</c> —
/// σ remains uniform, and by the Appendix A ledger lemma the joint message
/// distribution matches real proofs of real witnesses up to the lemma's
/// failure measure. The indistinguishability gates assert this empirically.
/// </para>
/// </remarks>
public static class ZkBaseFoldOpeningSimulator
{
    private const int ScalarSize = Scalar.SizeBytes;

    //SqueezeScalar squeezes this many wide bytes before reducing; the blend
    //challenge ρ is recovered from the recorded response the same way.
    private const int SqueezeWideBytes = 64;


    /// <summary>
    /// Simulates a full zero-knowledge BaseFold opening for the statement
    /// (<paramref name="evaluationPoint"/>, <paramref name="claimedValue"/>)
    /// without a witness.
    /// </summary>
    /// <param name="providerSeed">The provider seed the real protocol runs under.</param>
    /// <param name="evaluationPoint">The public evaluation point <c>z</c>; its length is the witness variable count.</param>
    /// <param name="claimedValue">The public claimed value <c>y</c> the simulated opening must verify against.</param>
    /// <param name="extraVariableCount">The hiding lift <c>t</c> the provider shape uses.</param>
    /// <param name="curve">The wired curve.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="transcript">A fresh transcript initialised exactly as the real prover's opening transcript.</param>
    /// <param name="merkleHash">The Merkle two-to-one hash backend.</param>
    /// <param name="hash">The Fiat-Shamir fixed-output hash backend.</param>
    /// <param name="squeeze">The real XOF backend; the simulator wraps it in a recording oracle.</param>
    /// <param name="reduce">Scalar-reduce backend.</param>
    /// <param name="add">Scalar-addition backend.</param>
    /// <param name="subtract">Scalar-subtraction backend.</param>
    /// <param name="multiply">Scalar-multiplication backend.</param>
    /// <param name="invert">Scalar-inversion backend.</param>
    /// <param name="scalarRandom">The randomness source for the fake witness, salts, and masks.</param>
    /// <param name="hashToScalar">Hash-to-scalar backend (the provider's code derivation).</param>
    /// <param name="pool">The pool for scratch and result buffers.</param>
    /// <param name="digestSizeBytes">The Merkle digest size.</param>
    /// <returns>
    /// The simulated commitment, the simulated opening, and the oracle whose
    /// <see cref="ProgrammableFiatShamirOracle.CreateReplaySqueeze"/> a
    /// verifier of the simulated opening must be given. The caller owns
    /// disposal of the commitment and the opening.
    /// </returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the recorded run is structurally unexpected (no single blend-challenge squeeze, or a zero blend challenge — probability <c>1/|F|</c>; rerun).</exception>
    public static (PolynomialCommitment Commitment, PolynomialOpening Opening, ProgrammableFiatShamirOracle Oracle) Simulate(
        ReadOnlySpan<byte> providerSeed,
        ReadOnlySpan<Scalar> evaluationPoint,
        Scalar claimedValue,
        int extraVariableCount,
        CurveParameterSet curve,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate scalarRandom,
        ScalarHashToScalarDelegate hashToScalar,
        SensitiveMemoryPool<byte> pool,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(claimedValue);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(pool);

        int variableCount = evaluationPoint.Length;
        var oracle = new ProgrammableFiatShamirOracle();
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            providerSeed, curve, queryCount, merkleHash, hash, oracle.CreateRecordingSqueeze(squeeze), reduce,
            add, subtract, multiply, invert, scalarRandom, hashToScalar, extraVariableCount, digestSizeBytes);

        //The fake witness f*: uniformly random, no relation to the statement.
        int evaluationCount = 1 << variableCount;
        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);
        using IMemoryOwner<byte> fakeTableOwner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> fakeTable = fakeTableOwner.Memory.Span[..(evaluationCount * ScalarSize)];
        for(int i = 0; i < evaluationCount; i++)
        {
            _ = scalarRandom(fakeTable.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
        }

        using MultilinearExtension fakeWitness = MultilinearExtension.FromEvaluations(fakeTable, variableCount, curve, pool);

        //The honest run over f*, every oracle response recorded: a valid
        //proof of y* = f*(z) whose σ the patch below retargets to y.
        (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(fakeWitness, pool);
        try
        {
            using(blind)
            {
                (PolynomialOpening fakeOpening, Scalar fakeValue) = provider.Open(commitment, blind, fakeWitness, evaluationPoint, transcript, pool);
                using(fakeOpening)
                {
                    using(fakeValue)
                    {
                        using Scalar rho = RecoverBlendChallenge(oracle, reduce, curve, pool);

                        //σ′ = σ + (y* − y)·ρ⁻¹.
                        Span<byte> delta = stackalloc byte[ScalarSize];
                        Span<byte> rhoInverse = stackalloc byte[ScalarSize];
                        subtract(fakeValue.AsReadOnlySpan(), claimedValue.AsReadOnlySpan(), delta, curve);
                        invert(rho.AsReadOnlySpan(), rhoInverse, curve);
                        multiply(delta, rhoInverse, delta, curve);

                        PolynomialOpening simulated = PatchSigma(
                            fakeOpening, delta, variableCount, extraVariableCount, curve, queryCount, digestSizeBytes, add, pool);

                        return (commitment, simulated, oracle);
                    }
                }
            }
        }
        catch
        {
            commitment.Dispose();

            throw;
        }
    }


    //The blend challenge ρ is the unique recorded squeeze whose XOF input
    //embeds the mask-blend operation label (the transcript writes labels
    //verbatim into the challenge input); its scalar is the recorded wide
    //response reduced exactly as SqueezeScalar reduces it.
    private static Scalar RecoverBlendChallenge(
        ProgrammableFiatShamirOracle oracle,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        byte[] labelBytes = new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskBlendChallenge).Bytes;
        int found = -1;
        for(int i = 0; i < oracle.RecordedCount; i++)
        {
            if(oracle.GetRecordedInput(i).IndexOf(labelBytes) >= 0)
            {
                if(found >= 0)
                {
                    throw new InvalidOperationException("The recorded run contains more than one blend-challenge squeeze.");
                }

                found = i;
            }
        }

        if(found < 0)
        {
            throw new InvalidOperationException("The recorded run contains no blend-challenge squeeze; the provider did not run the zero-knowledge opening.");
        }

        ReadOnlySpan<byte> wide = oracle.GetRecordedOutput(found);
        if(wide.Length != SqueezeWideBytes)
        {
            throw new InvalidOperationException($"The blend-challenge squeeze recorded {wide.Length} bytes; expected {SqueezeWideBytes}.");
        }

        Scalar rho = Scalar.FromBytesReduced(wide, reduce, curve, pool);
        if(IsZero(rho.AsReadOnlySpan()))
        {
            rho.Dispose();

            throw new InvalidOperationException("The recorded blend challenge is zero (probability 1/|F|); rerun the simulation.");
        }

        return rho;
    }


    //σ sits behind the witness-side sections and the mask commitment root,
    //in front of σ_F and the nested hiding weighted opening — the offset is
    //fully determined by the public shape helpers.
    private static PolynomialOpening PatchSigma(
        PolynomialOpening fakeOpening,
        ReadOnlySpan<byte> delta,
        int variableCount,
        int extraVariableCount,
        CurveParameterSet curve,
        int queryCount,
        int digestSizeBytes,
        ScalarAddDelegate add,
        SensitiveMemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> fakeBytes = fakeOpening.AsReadOnlySpan();
        int expectedLength = ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(
            variableCount, extraVariableCount, curve, queryCount, digestSizeBytes);
        if(fakeBytes.Length != expectedLength)
        {
            throw new InvalidOperationException($"The fake opening is {fakeBytes.Length} bytes; the shape helper expects {expectedLength}.");
        }

        StatisticalMaskParameters maskParameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(
            variableCount + extraVariableCount, curve, queryCount);
        int nestedLength = ZkBaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            maskParameters.LiftedVariableCount, curve, queryCount, digestSizeBytes);
        int sigmaOffset = expectedLength - nestedLength - (2 * ScalarSize);

        using IMemoryOwner<byte> patchedOwner = pool.Rent(expectedLength);
        Span<byte> patched = patchedOwner.Memory.Span[..expectedLength];
        fakeBytes.CopyTo(patched);
        Span<byte> sigma = patched.Slice(sigmaOffset, ScalarSize);
        add(sigma, delta, sigma, curve);

        return PolynomialOpening.FromBytes(patched, curve, CommitmentScheme.BaseFold, pool);
    }


    private static bool IsZero(ReadOnlySpan<byte> scalar)
    {
        for(int i = 0; i < scalar.Length; i++)
        {
            if(scalar[i] != 0)
            {
                return false;
            }
        }

        return true;
    }
}
