using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// The <c>add_zkp_info</c> output of blind BBS proof generation per IETF
/// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.3.4 step 17:
/// the committed-disclosure commitments <c>(C_1, ..., C_N)</c> together
/// with the Pedersen randomness <c>(s_1, ..., s_N)</c> that opens them.
/// The prover feeds these into follow-on zero-knowledge protocols about
/// the committed messages (range proofs, set membership, re-commitment).
/// </summary>
/// <remarks>
/// <para>
/// SECRECY OBLIGATION (Section 4.2.3 / Section 8): this value MUST stay
/// with the prover. It is never serialized by this library and MUST NOT
/// be sent to the verifier or any other party — the randomness
/// <c>s_i</c> together with the commitment <c>C_i</c> opens the hidden
/// message value <c>msg_i</c> to anyone who can enumerate candidate
/// messages, collapsing exactly the hiding the proof was built to
/// provide. The commitments themselves already travel inside the framed
/// proof; only this pairing of commitment and randomness is sensitive.
/// </para>
/// <para>
/// Disposing the openings disposes every held commitment point and
/// randomness scalar, clearing their pool-backed buffers.
/// </para>
/// </remarks>
public sealed class BbsBlindProofCommitmentOpenings: IDisposable
{
    private readonly G1Point[] _commitments;
    private readonly Scalar[] _randomness;


    /// <summary>The number of committed-disclosure openings (<c>N</c>).</summary>
    public int Count => _commitments.Length;


    internal BbsBlindProofCommitmentOpenings(G1Point[] commitments, Scalar[] randomness)
    {
        ArgumentNullException.ThrowIfNull(commitments);
        ArgumentNullException.ThrowIfNull(randomness);
        if(commitments.Length != randomness.Length)
        {
            throw new ArgumentException("Commitments and randomness must have the same length.", nameof(randomness));
        }

        _commitments = commitments;
        _randomness = randomness;
    }


    /// <summary>Returns the <paramref name="index"/>-th committed-disclosure commitment <c>C_i</c>. The point stays owned by this container.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public G1Point GetCommitment(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, _commitments.Length);

        return _commitments[index];
    }


    /// <summary>Returns the Pedersen randomness <c>s_i</c> opening the <paramref name="index"/>-th commitment. The scalar stays owned by this container.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public Scalar GetRandomness(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, _randomness.Length);

        return _randomness[index];
    }


    /// <summary>Disposes every held commitment point and randomness scalar, clearing their pool-backed buffers.</summary>
    public void Dispose()
    {
        for(int i = 0; i < _commitments.Length; i++)
        {
            _commitments[i]?.Dispose();
        }
        for(int i = 0; i < _randomness.Length; i++)
        {
            _randomness[i]?.Dispose();
        }
    }
}
