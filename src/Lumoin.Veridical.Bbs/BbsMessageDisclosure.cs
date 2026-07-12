namespace Lumoin.Veridical.Bbs;

/// <summary>
/// The per-message disclosure choice for blind BBS proof generation per
/// IETF <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.2.3
/// (BlindProofGen): each message in the signed vector is either revealed
/// to the verifier, kept hidden inside the zero-knowledge proof, or kept
/// hidden while additionally producing a committed-disclosure Pedersen
/// commitment the prover can open or prove statements about in follow-on
/// protocols.
/// </summary>
/// <remarks>
/// <see cref="Hide"/> is the zero value so a default-initialized
/// disclosure vector is the privacy-preserving choice: nothing is
/// revealed unless a position is explicitly set.
/// </remarks>
public enum BbsMessageDisclosure
{
    /// <summary>The message stays hidden; only its Schnorr response scalar appears in the proof.</summary>
    Hide = 0,

    /// <summary>The message is revealed to the verifier and bound into the proof challenge.</summary>
    Disclose = 1,

    /// <summary>
    /// The message stays hidden AND the proof carries a committed-disclosure
    /// commitment <c>C_i = Y_0 * s_i + Y_1 * msg_i</c> proven consistent
    /// with the hidden message. Committed messages are by construction
    /// undisclosed.
    /// </summary>
    Commit = 2,
}
