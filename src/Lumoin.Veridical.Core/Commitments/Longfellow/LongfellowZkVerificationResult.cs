namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The verdict of the end-to-end ZK proof verification, a structured counterpart of the reference's
/// <c>why</c> string in google/longfellow-zk's <c>ZkVerifier::verify</c> (<c>lib/zk/zk_verifier.h</c>).
/// </summary>
/// <remarks>
/// The ZK verifier parses the envelope, replays the sumcheck to build the Ligero constraint system, and
/// runs the Ligero verifier. A rejection therefore comes from one of three places: the envelope failed
/// to parse (<see cref="MalformedProof"/>), or the Ligero verifier rejected the constraint system
/// (<see cref="LigeroRejected"/> — the specific Ligero cause is available from the inner verifier). A
/// tampered sumcheck segment or public input diverges the squeezed challenge stream and surfaces as a
/// Ligero rejection (the derived constraints or the re-derived opened columns no longer match the
/// commitment).
/// </remarks>
internal enum LongfellowZkVerificationResult
{
    /// <summary>The full proof verified: the envelope parsed and the Ligero verifier accepted the derived constraint system (the reference's <c>"ok"</c>).</summary>
    Accepted = 0,

    /// <summary>The envelope could not be parsed — a segment was truncated or a length was malformed (the reference's <c>read</c> returning <see langword="false"/>).</summary>
    MalformedProof = 1,

    /// <summary>The Ligero verifier rejected the derived constraint system (the reference's <c>LigeroVerifier::verify</c> returning <see langword="false"/>).</summary>
    LigeroRejected = 2,
}
