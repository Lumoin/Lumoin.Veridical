namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The outcome of verifying a Longfellow dual-field mdoc proof. The public mirror of the driver's internal
/// result so the verdict cause is observable without exposing the internal verifier surface.
/// </summary>
public enum LongfellowMdocVerdict
{
    /// <summary>Both the hash and signature proofs verified; the disclosure is sound.</summary>
    Accepted = 0,

    /// <summary>The envelope could not be parsed into its MAC prefix and two sub-proofs.</summary>
    MalformedEnvelope = 1,

    /// <summary>The spliced public-input vector did not match a circuit's declared public-input count.</summary>
    AttributeNumberMismatch = 2,

    /// <summary>The GF(2^128) hash-circuit proof was rejected.</summary>
    HashRejected = 3,

    /// <summary>The P-256 signature-circuit proof was rejected.</summary>
    SignatureRejected = 4
}
