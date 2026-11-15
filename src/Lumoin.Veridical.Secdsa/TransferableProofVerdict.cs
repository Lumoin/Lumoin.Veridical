namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The outcome of the third-party verification of a transferable proof (Verheul Algorithm 24). The inputs are wire
/// data from other parties, so a rejection is an expected result and is returned as a value, never thrown; the value
/// says which check rejected.
/// </summary>
public enum TransferableProofVerdict
{
    /// <summary>Accept: both signatures verify and <c>H2 = H(H1)</c>, so Statement (9) holds for the statement.</summary>
    Accept = 0,

    /// <summary>Reject: the challenge and the response were not formed under the same layout profile, or not under the verifier's.</summary>
    RejectProfileMismatch = 1,

    /// <summary>Reject: the additional authenticated data of the challenge is not the data of the statement the verifier checks.</summary>
    RejectStatementMismatch = 2,

    /// <summary>Reject: the challenge signature <c>Sig</c> does not verify (Algorithm 24 step 4).</summary>
    RejectChallengeSignature = 3,

    /// <summary>Reject: the response signature <c>SigP</c> does not verify (Algorithm 24 step 5).</summary>
    RejectResponseSignature = 4,

    /// <summary>Reject: <c>H2 ≠ H(H1)</c> (Algorithm 24 step 6).</summary>
    RejectDigest = 5
}
