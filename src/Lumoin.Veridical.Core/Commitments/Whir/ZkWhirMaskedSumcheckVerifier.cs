using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The verifier side of one masked-sumcheck fold batch of the hiding WHIR
/// path (eprint 2026/391 Construction 6.3): replays the transcript in the
/// prover's order — joint claim, mask oracle root, mask total <c>μ̃</c>,
/// combining challenge <c>ε</c>, then per round the wire polynomial and fold
/// challenge — reconstructing every elided linear coefficient from the
/// running chain and carrying the chained target
/// <c>h_j(0) + h_j(1) = h_(j-1)(γ_(j-1))</c> forward from the opening claim
/// <c>ε·μ + μ̃</c>, where <c>μ</c> is the joint claim: the source claim plus
/// the carried mask-claim total riding the batch as its auxiliary constant.
/// </summary>
/// <remarks>
/// The replay is deterministic bookkeeping, not an accept/reject decision:
/// the <c>c_1</c> reconstruction makes each chain equation hold by
/// definition, exactly as in the non-hiding compressed convention, and
/// soundness is enforced where the residual claim meets the oracles — the
/// code-switch rounds and the masked base case of Construction 9.7. The
/// residual this replay hands off satisfies
/// <c>residual = ε·(plain final claim) + Σ_j s_j(γ_j) + ε·aux·2^(-k)</c> for
/// an honest prover; the mask parts are later discharged through the mask
/// oracles' openings via the residual covectors, the carried ones rescaled by
/// <c>ε·2^(-k)</c>.
/// </remarks>
public static class ZkWhirMaskedSumcheckVerifier
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Replays one masked fold batch and hands off the chained residual
    /// claim.
    /// </summary>
    /// <param name="wires">The batch's compressed wire polynomials in round order.</param>
    /// <param name="maskOracleRoot">The batch's mask oracle root, absorbed as the prover did.</param>
    /// <param name="maskTotal">The mask total <c>μ̃</c>, one element.</param>
    /// <param name="sourceClaim">The batch's incoming source sumcheck claim, one element.</param>
    /// <param name="auxClaim">The carried mask-claim total entering the batch as its auxiliary constant, one element; zero for the initial batch.</param>
    /// <param name="maskMessageLength">The mask message length <c>ℓ_zk</c> both endpoints derive from the public parameters; fixes the expected wire degree <c>max(ℓ_zk - 1, 2)</c>.</param>
    /// <param name="transcript">The Fiat-Shamir transcript.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The curve whose scalar field the batch lives in.</param>
    /// <param name="pool">The pool challenge scalars rent from.</param>
    /// <param name="epsilon">Receives the combining challenge <c>ε</c>, one element.</param>
    /// <param name="challenges">Receives the fold challenges <c>γ_1..γ_k</c>, one element per wire.</param>
    /// <param name="residualClaim">Receives the chained residual claim <c>h_k(γ_k)</c>, one element.</param>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape or a wire's degree is not the expected <c>max(ℓ_zk - 1, 2)</c>.</exception>
    public static void ReplayBatch(
        IReadOnlyList<CompressedRoundPolynomial> wires,
        MerkleRoot maskOracleRoot,
        ReadOnlySpan<byte> maskTotal,
        ReadOnlySpan<byte> sourceClaim,
        ReadOnlySpan<byte> auxClaim,
        int maskMessageLength,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Span<byte> epsilon,
        Span<byte> challenges,
        Span<byte> residualClaim)
    {
        ArgumentNullException.ThrowIfNull(wires);
        ArgumentNullException.ThrowIfNull(maskOracleRoot);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(maskMessageLength, WhirZkParameters.MinimumMaskMessageLength);

        int expectedDegree = Math.Max(maskMessageLength - 1, 2);
        ValidateReplayShape(wires.Count, maskTotal.Length, sourceClaim.Length, epsilon.Length, challenges.Length, residualClaim.Length);
        if(auxClaim.Length != ScalarSize)
        {
            throw new ArgumentException($"The auxiliary claim must be one element ({ScalarSize} bytes); received {auxClaim.Length}.", nameof(auxClaim));
        }

        //The joint claim μ binds first so every batch transcript is
        //self-contained, mirroring the reference domain-separator order.
        Span<byte> jointClaim = stackalloc byte[ScalarSize];
        add(sourceClaim, auxClaim, jointClaim, curve);
        transcript.AbsorbWhirMaskBatchClaim(jointClaim, hash);

        transcript.AbsorbWhirMaskOracleRoot(maskOracleRoot, hash);
        transcript.AbsorbWhirMaskTotal(maskTotal, hash);
        using(Scalar epsilonScalar = transcript.SqueezeWhirMaskCombinationChallenge(squeeze, hash, reduce, curve, pool))
        {
            epsilonScalar.AsReadOnlySpan().CopyTo(epsilon);
        }

        //The opening claim of the chain: ε·μ + μ̃, established before any
        //wire is read.
        Span<byte> target = stackalloc byte[ScalarSize];
        multiply(jointClaim, epsilon, target, curve);
        add(target, maskTotal, target, curve);

        Span<byte> linearTerm = stackalloc byte[ScalarSize];
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        for(int round = 0; round < wires.Count; round++)
        {
            CompressedRoundPolynomial wire = wires[round];
            ArgumentNullException.ThrowIfNull(wire, nameof(wires));
            if(wire.Degree != expectedDegree)
            {
                throw new ArgumentException(
                    $"Round {round}'s wire polynomial has degree {wire.Degree}; the masked batch expects max(ℓ_zk - 1, 2) = {expectedDegree}.",
                    nameof(wires));
            }

            transcript.AbsorbWhirSumcheckPolynomial(wire, hash);
            using Scalar challenge = transcript.SqueezeWhirFoldChallenge(squeeze, hash, reduce, curve, pool);
            ReadOnlySpan<byte> challengeBytes = challenge.AsReadOnlySpan();
            challengeBytes.CopyTo(challenges.Slice(round * ScalarSize, ScalarSize));

            //Reconstruct the elided linear coefficient from the chain:
            //c_1 = target − 2·c_0 − Σ_(i≥2) c_i.
            ReadOnlySpan<byte> constantTerm = wire.GetConstantTermBytes();
            target.CopyTo(linearTerm);
            subtract(linearTerm, constantTerm, linearTerm, curve);
            subtract(linearTerm, constantTerm, linearTerm, curve);
            for(int slot = 1; slot < wire.StoredCoefficientCount; slot++)
            {
                subtract(linearTerm, wire.GetStoredCoefficientBytes(slot), linearTerm, curve);
            }

            //Horner over the full coefficients (c_0, c_1, c_2, ..., c_d):
            //the value becomes the next round's chained target.
            wire.GetStoredCoefficientBytes(wire.StoredCoefficientCount - 1).CopyTo(accumulator);
            for(int degree = expectedDegree - 1; degree >= 0; degree--)
            {
                multiply(accumulator, challengeBytes, accumulator, curve);
                ReadOnlySpan<byte> coefficient = degree switch
                {
                    0 => constantTerm,
                    1 => linearTerm,
                    _ => wire.GetStoredCoefficientBytes(degree - 1)
                };
                add(accumulator, coefficient, accumulator, curve);
            }

            accumulator.CopyTo(target);
        }

        target.CopyTo(residualClaim);
    }


    /// <summary>
    /// Writes the residual covector of one mask — the powers
    /// <c>(1, γ_j, γ_j², ..., γ_j^(ℓ_zk - 1))</c> whose dot product with the
    /// mask's coefficients equals <c>s_j(γ_j)</c>. The code-switch
    /// composition carries these as the fresh mask-oracle claims discharging
    /// the mask part of the residual.
    /// </summary>
    /// <param name="challenge">The round's fold challenge <c>γ_j</c>, one element.</param>
    /// <param name="length">The covector element count, the mask message length <c>ℓ_zk</c>.</param>
    /// <param name="destination">Receives the <paramref name="length"/> powers.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The curve whose scalar field the powers live in.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="multiply"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="length"/> is not positive.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public static void WriteMaskResidualCovector(
        ReadOnlySpan<byte> challenge,
        int length,
        Span<byte> destination,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        if(challenge.Length != ScalarSize || destination.Length != length * ScalarSize)
        {
            throw new ArgumentException(
                $"The challenge must be one element and the destination {length} elements; received {challenge.Length} and {destination.Length} bytes.");
        }

        WriteCanonicalUInt(1, destination[..ScalarSize]);
        for(int power = 1; power < length; power++)
        {
            multiply(
                destination.Slice((power - 1) * ScalarSize, ScalarSize),
                challenge,
                destination.Slice(power * ScalarSize, ScalarSize),
                curve);
        }
    }


    /// <summary>
    /// Validates the replay's span shapes against the wire count.
    /// </summary>
    private static void ValidateReplayShape(
        int wireCount,
        int maskTotalLength,
        int plainClaimLength,
        int epsilonLength,
        int challengesLength,
        int residualClaimLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(wireCount);
        if(maskTotalLength != ScalarSize || plainClaimLength != ScalarSize || epsilonLength != ScalarSize || residualClaimLength != ScalarSize)
        {
            throw new ArgumentException(
                $"The mask total, plain claim, epsilon and residual spans must each carry one element ({ScalarSize} bytes).");
        }

        if(challengesLength != wireCount * ScalarSize)
        {
            throw new ArgumentException(
                $"The challenges destination must carry {wireCount} elements ({wireCount * ScalarSize} bytes); received {challengesLength}.");
        }
    }


    /// <summary>
    /// Writes a small integer as a canonical big-endian field element.
    /// </summary>
    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
