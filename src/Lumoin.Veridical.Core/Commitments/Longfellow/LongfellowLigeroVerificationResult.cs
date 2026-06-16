namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The verdict of <see cref="LongfellowLigeroVerifier"/>, the typed counterpart of the reference's
/// <c>why</c> string in google/longfellow-zk's <c>LigeroVerifier::verify</c>
/// (<c>lib/ligero/ligero_verifier.h</c>). On a rejected proof it names the check that caught the fault,
/// in the order the reference runs them; <see cref="Accepted"/> is the reference's <c>"ok"</c>.
/// </summary>
internal enum LongfellowLigeroVerificationResult
{
    /// <summary>The proof passed every check (the reference's <c>"ok"</c>).</summary>
    Accepted = 0,

    /// <summary>The Merkle opening did not recompute the committed root (<c>"merkle_check failed"</c>).</summary>
    MerkleCheckFailed,

    /// <summary>The low-degree (Reed–Solomon consistency) test failed (<c>"low_degree_check failed"</c>).</summary>
    LowDegreeCheckFailed,

    /// <summary>The dot-product (linear) column-consistency test failed (<c>"dot_check failed"</c>).</summary>
    DotCheckFailed,

    /// <summary>The inner-product value did not match the public constraint targets (<c>"wrong dot product"</c>).</summary>
    WrongDotProduct,

    /// <summary>The quadratic-constraint test failed (<c>"quadratic_check failed"</c>).</summary>
    QuadraticCheckFailed,
}
