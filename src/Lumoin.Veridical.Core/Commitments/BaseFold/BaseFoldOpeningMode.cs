namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The privacy mode a <see cref="BaseFoldEvaluationProof"/> was produced under,
/// fixing both the prover/verifier construction and the wire layout the
/// serialization reads and writes. The mode is agreed out of band (the provider
/// that produced the proof knows it); it is not carried in the proof bytes, so a
/// reader must be told which mode to parse.
/// </summary>
/// <remarks>
/// The three modes form an inclusion chain — each adds randomness the prior one
/// lacks, closing one more leakage channel of an honest opening:
/// <list type="bullet">
///   <item><description><see cref="Plain"/>: the non-hiding BaseFold opening. Merkle leaves are codeword values verbatim; the opening is a deterministic function of the witness.</description></item>
///   <item><description><see cref="Hiding"/>: salted-Merkle leaves <c>hash(value ‖ salt)</c> (ZK.1), so the commitment root and every in-proof fold root are hiding, and each revealed fold pair carries its two leaf salts.</description></item>
///   <item><description><see cref="ZeroKnowledge"/>: <see cref="Hiding"/> plus the CFS-2017 sumcheck mask — a second salted BaseFold codeword <c>s</c> folded in lockstep whose blend randomises the round polynomials, with <c>σ = Σ_b s(b)</c>, the mask fold roots, the mask base oracle, and the mask query openings appended to the wire form.</description></item>
/// </list>
/// </remarks>
public enum BaseFoldOpeningMode
{
    /// <summary>The non-hiding opening: codeword values are the Merkle leaves verbatim.</summary>
    Plain,

    /// <summary>The hiding opening: salted-Merkle leaves and per-step leaf salts (ZK.1).</summary>
    Hiding,

    /// <summary>The zero-knowledge opening: hiding plus the lockstep CFS-2017 sumcheck mask (ZK.2b.2).</summary>
    ZeroKnowledge
}
