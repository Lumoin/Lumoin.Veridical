namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The verdict of the zk sumcheck layer-walk replay, a partial counterpart of the reference's <c>why</c>
/// string in google/longfellow-zk's <c>VerifierLayers::layers</c> (<c>lib/sumcheck/verifier_layers.h</c>).
/// </summary>
/// <remarks>
/// <para>
/// This replay is the transcript half of the verifier: it reconstructs every Fiat–Shamir challenge and
/// folds the running claim down the layers. Because the wire omits <c>p(1)</c> (the <c>k != 1</c>
/// optimization), the per-round split <c>claim = p(0) + p(1)</c> reconstructs <c>p(1)</c> rather than
/// checking it; the soundness of the reconstructed values is established downstream — by the input
/// binding in the non-ZK verifier, or by the Ligero opening in the ZK verifier (the
/// <c>ZkCommon::verifier_constraints</c> → <c>LigeroVerifier</c> composition, above this replay). A
/// tampered round polynomial or claim is caught here only indirectly: it diverges the squeezed challenge
/// stream, which a conformance gate detects against the reference's dumped challenges.
/// </para>
/// <para>
/// The replay therefore returns <see cref="Accepted"/> for any well-formed walk over a parseable proof;
/// the malformed-proof rejection lives in the byte reader (a truncated segment fails to parse), and the
/// tamper rejection lives in the challenge-stream comparison.
/// </para>
/// </remarks>
internal enum LongfellowSumcheckVerificationResult
{
    /// <summary>The layer walk completed: every challenge was reconstructed and every claim folded (the reference's <c>"ok"</c> for the layer transcript).</summary>
    Accepted = 0,
}
