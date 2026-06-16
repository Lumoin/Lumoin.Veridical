namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The verdict of the dual-field mdoc proof verification, a structured counterpart of the reference's
/// <c>MdocVerifierErrorCode</c> in google/longfellow-zk's <c>run_mdoc_verifier</c>
/// (<c>lib/circuits/mdoc/mdoc_zk.cc:560-695</c>).
/// </summary>
/// <remarks>
/// The driver parses the <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c> envelope, absorbs both
/// commitment roots, squeezes the shared MAC key <c>a_v</c>, splices the macs and <c>a_v</c> into the two
/// public-input vectors, guards their final sizes against the circuits' <c>npub_in</c>, and runs the two
/// ZK verifiers. A rejection therefore comes from one of four places: the envelope failed to parse
/// (<see cref="MalformedEnvelope"/> — the reference's <c>HASH_PARSING_FAILURE</c> /
/// <c>SIGNATURE_PARSING_FAILURE</c>), the spliced public-input vectors did not match the circuits'
/// declared public-input counts (<see cref="AttributeNumberMismatch"/> — the reference's
/// <c>ATTRIBUTE_NUMBER_MISMATCH</c> guard at <c>mdoc_zk.cc:686-689</c>), the hash circuit's ZK proof was
/// rejected (<see cref="HashRejected"/>), or the signature circuit's ZK proof was rejected
/// (<see cref="SigRejected"/>). The reference folds the last two into a single <c>GENERAL_FAILURE</c>
/// (<c>ok &amp;&amp; ok2</c>); the driver reports which half rejected for diagnosis.
/// </remarks>
internal enum LongfellowMdocVerificationResult
{
    /// <summary>Both ZK proofs verified against the spliced public inputs (the reference's <c>MDOC_VERIFIER_SUCCESS</c>).</summary>
    Accepted = 0,

    /// <summary>The envelope could not be split into its MAC region, hash proof and signature proof, or a proof segment failed to parse (the reference's <c>HASH_PARSING_FAILURE</c> / <c>SIGNATURE_PARSING_FAILURE</c>).</summary>
    MalformedEnvelope = 1,

    /// <summary>A spliced public-input vector did not reach its circuit's <c>npub_in</c> (the reference's <c>MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH</c> guard).</summary>
    AttributeNumberMismatch = 2,

    /// <summary>The GF(2^128) hash circuit's ZK proof was rejected (the reference's <c>ok == false</c> half of <c>ok &amp;&amp; ok2</c>).</summary>
    HashRejected = 3,

    /// <summary>The P-256 base-field signature circuit's ZK proof was rejected (the reference's <c>ok2 == false</c> half of <c>ok &amp;&amp; ok2</c>).</summary>
    SigRejected = 4,
}
