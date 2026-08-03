using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Analysis.Simulation;

/// <summary>
/// The witness-free simulator of the hiding WHIR opening (HVZK-WHIR,
/// eprint 2026/391 Construction 9.7) — the WHIR counterpart of
/// <see cref="ZkBaseFoldOpeningSimulator"/>. Given only the public statement
/// (the evaluation point <c>z</c> and the claimed value <c>y</c>), it
/// produces a commitment and an opening that verify against <c>(z, y)</c>
/// under a programmed Fiat-Shamir oracle, without ever holding a witness
/// that evaluates to <c>y</c>.
/// </summary>
/// <remarks>
/// <para>
/// The construction leans on the protocol's own algebra. The simulator runs
/// the protocol-following prover over a uniformly random fake witness
/// <c>f*</c> (recording every oracle response), obtaining a valid proof of
/// <c>y* = f*(z)</c>, and then patches the single batch-0 mask total:
/// <c>μ̃′ = μ̃ + ε·(y* − y)</c> for the recorded batch-0 combination
/// challenge <c>ε</c>. The verifier's batch-0 chain start
/// <c>ε·y + μ̃′</c> then equals the fake run's <c>ε·y* + μ̃</c>; the public
/// claim anchors nothing else — every later batch replays against
/// proof-internal values — so the entire numeric chain, through the
/// code-switch rounds to the base case's joint check, sees identical
/// operands. The one thing the patch breaks is challenge
/// <em>derivation</em>: μ̃′ is absorbed before ε is squeezed, so every
/// post-divergence transcript state differs. That is exactly the gap
/// random-oracle programming closes — verification runs against
/// <see cref="ProgrammableFiatShamirOracle.CreateReplaySqueeze"/>, which
/// answers the verifier's queries with the recorded responses.
/// </para>
/// <para>
/// Distributionally the output is a real proof of a uniformly random witness
/// with μ̃ shifted by a public function of <c>(y*, y, ε)</c> — μ̃ is a fresh
/// mask total and remains uniform under the shift, and the mask codes'
/// Reed-Solomon encodings simulate the spot-checked positions exactly; the
/// residual distance is the private out-of-domain admissibility union the
/// <see cref="WhirZkParameters.PrivacyErrorBits"/> figure prices. The
/// indistinguishability gates assert this empirically.
/// </para>
/// </remarks>
public static class ZkWhirOpeningSimulator
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The wide byte count the transcript's scalar squeezes draw before
    /// reducing; the combination challenge <c>ε</c> is recovered from the
    /// recorded response the same way.
    /// </summary>
    private const int SqueezeWideBytes = 64;


    /// <summary>
    /// Simulates a hiding WHIR opening for the statement
    /// (<paramref name="evaluationPoint"/>, <paramref name="claimedValue"/>)
    /// without a witness.
    /// </summary>
    /// <param name="evaluationPoint">The public evaluation point <c>z</c>; its length is the witness variable count.</param>
    /// <param name="claimedValue">The public claimed value <c>y</c> the simulated opening must verify against.</param>
    /// <param name="curve">The wired curve.</param>
    /// <param name="initialRateLog2">The initial inverse-rate exponent the real protocol runs under.</param>
    /// <param name="transcript">A fresh transcript initialised exactly as the real prover's opening transcript.</param>
    /// <param name="merkleHash">The Merkle two-to-one hash backend.</param>
    /// <param name="hash">The Fiat-Shamir fixed-output hash backend.</param>
    /// <param name="squeeze">The real XOF backend; the simulator wraps it in a recording oracle.</param>
    /// <param name="reduce">Scalar-reduce backend.</param>
    /// <param name="add">Scalar-addition backend.</param>
    /// <param name="subtract">Scalar-subtraction backend.</param>
    /// <param name="multiply">Scalar-multiplication backend.</param>
    /// <param name="invert">Scalar-inversion backend.</param>
    /// <param name="scalarRandom">The randomness source for the fake witness, the encoding randomness and the masks.</param>
    /// <param name="pool">The pool for scratch and result buffers.</param>
    /// <param name="foldingParameter">The folding parameter the real protocol runs under.</param>
    /// <param name="securityLevelBits">The per-round soundness target the real protocol runs under.</param>
    /// <param name="regime">The soundness regime the real protocol runs under.</param>
    /// <param name="digestSizeBytes">The Merkle digest size.</param>
    /// <param name="maskMessageLength">The mask message length the real protocol runs under.</param>
    /// <param name="maskRateLog2">The mask-code inverse-rate exponent the real protocol runs under.</param>
    /// <returns>
    /// The simulated commitment, the simulated opening, and the oracle whose
    /// <see cref="ProgrammableFiatShamirOracle.CreateReplaySqueeze"/> a
    /// verifier of the simulated opening must be given. The caller owns
    /// disposal of the commitment and the opening.
    /// </returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the recorded run is structurally unexpected (no combination-challenge squeeze, or an unexpected squeeze width).</exception>
    public static (PolynomialCommitment Commitment, PolynomialOpening Opening, ProgrammableFiatShamirOracle Oracle) Simulate(
        ReadOnlySpan<Scalar> evaluationPoint,
        Scalar claimedValue,
        CurveParameterSet curve,
        int initialRateLog2,
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
        BaseMemoryPool pool,
        int foldingParameter = WellKnownWhirParameters.DefaultFoldingParameter,
        int securityLevelBits = WellKnownWhirParameters.ClassicalSecurityLevelBits,
        WhirSoundnessRegime regime = WellKnownWhirParameters.ClassicalSecurityRegime,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes,
        int maskMessageLength = WhirZkParameters.DefaultMaskMessageLength,
        int maskRateLog2 = WhirZkParameters.DefaultMaskRateLog2)
    {
        ArgumentNullException.ThrowIfNull(claimedValue);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
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
        using PolynomialCommitmentProvider provider = WhirPolynomialCommitmentScheme.CreateZeroKnowledge(
            curve, initialRateLog2, merkleHash, hash, oracle.CreateRecordingSqueeze(squeeze), reduce,
            add, subtract, multiply, invert, scalarRandom,
            foldingParameter, securityLevelBits, regime, digestSizeBytes, maskMessageLength, maskRateLog2);

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

        //The run over f*, every oracle response recorded: a valid proof of
        //y* = f*(z) whose batch-0 mask total the patch below retargets to y.
        (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(fakeWitness, pool);
        try
        {
            using(blind)
            {
                (PolynomialOpening fakeOpening, Scalar fakeValue) = provider.Open(commitment, blind, fakeWitness, evaluationPoint, transcript, pool);
                using(fakeOpening)
                using(fakeValue)
                {
                    using Scalar epsilon = RecoverBatchZeroCombinationChallenge(oracle, reduce, curve, pool);

                    //μ̃′ = μ̃ + ε·(y* − y): no inversion — the claim enters
                    //the chain start pre-multiplied by ε.
                    Span<byte> delta = stackalloc byte[ScalarSize];
                    subtract(fakeValue.AsReadOnlySpan(), claimedValue.AsReadOnlySpan(), delta, curve);
                    multiply(delta, epsilon.AsReadOnlySpan(), delta, curve);

                    PolynomialOpening simulated = PatchMaskTotal(
                        fakeOpening, delta, variableCount, curve, initialRateLog2, foldingParameter,
                        securityLevelBits, regime, digestSizeBytes, maskMessageLength, maskRateLog2, add, pool);

                    return (commitment, simulated, oracle);
                }
            }
        }
        catch
        {
            commitment.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Recovers the batch-0 combination challenge <c>ε</c>: the FIRST
    /// recorded squeeze whose XOF input embeds the mask-combination
    /// operation label (the transcript writes labels verbatim into the
    /// challenge input; each later batch squeezes the same label again, so
    /// only the first occurrence is batch 0). Its scalar is the recorded
    /// wide response reduced exactly as the transcript reduces it.
    /// </summary>
    private static Scalar RecoverBatchZeroCombinationChallenge(
        ProgrammableFiatShamirOracle oracle,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        byte[] labelBytes = new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.MaskCombinationChallenge).Bytes;
        int found = -1;
        for(int i = 0; i < oracle.RecordedCount; i++)
        {
            if(oracle.GetRecordedInput(i).IndexOf(labelBytes) >= 0)
            {
                found = i;
                break;
            }
        }

        if(found < 0)
        {
            throw new InvalidOperationException("The recorded run contains no mask-combination squeeze; the provider did not run the hiding opening.");
        }

        ReadOnlySpan<byte> wide = oracle.GetRecordedOutput(found);
        if(wide.Length != SqueezeWideBytes)
        {
            throw new InvalidOperationException($"The mask-combination squeeze recorded {wide.Length} bytes; expected {SqueezeWideBytes}.");
        }

        return Scalar.FromBytesReduced(wide, reduce, curve, pool);
    }


    /// <summary>
    /// Applies the retargeting shift to the batch-0 mask total at the
    /// codec's published seam offset; the patched buffer round-trips
    /// through the public opening leaf type.
    /// </summary>
    private static PolynomialOpening PatchMaskTotal(
        PolynomialOpening fakeOpening,
        ReadOnlySpan<byte> delta,
        int variableCount,
        CurveParameterSet curve,
        int initialRateLog2,
        int foldingParameter,
        int securityLevelBits,
        WhirSoundnessRegime regime,
        int digestSizeBytes,
        int maskMessageLength,
        int maskRateLog2,
        ScalarAddDelegate add,
        BaseMemoryPool pool)
    {
        WhirZkParameters parameters = WhirZkParameters.Create(
            WhirParameterSchedule.Create(curve, variableCount, initialRateLog2, foldingParameter, securityLevelBits, regime),
            maskMessageLength,
            maskRateLog2);

        ReadOnlySpan<byte> fakeBytes = fakeOpening.AsReadOnlySpan();
        int expectedLength = ZkWhirProofSerialization.ComputeLength(parameters, digestSizeBytes);
        if(fakeBytes.Length != expectedLength)
        {
            throw new InvalidOperationException($"The fake opening is {fakeBytes.Length} bytes; the shape helper expects {expectedLength}.");
        }

        int maskTotalOffset = ZkWhirProofSerialization.ComputeMaskTotalOffset(parameters, 0, digestSizeBytes);
        using IMemoryOwner<byte> patchedOwner = pool.Rent(expectedLength);
        Span<byte> patched = patchedOwner.Memory.Span[..expectedLength];
        fakeBytes.CopyTo(patched);
        Span<byte> maskTotal = patched.Slice(maskTotalOffset, ScalarSize);
        add(maskTotal, delta, maskTotal, curve);

        return PolynomialOpening.FromBytes(patched, curve, CommitmentScheme.Whir, pool);
    }
}
