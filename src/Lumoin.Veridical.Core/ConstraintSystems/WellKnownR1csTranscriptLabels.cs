namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Stable Fiat-Shamir operation labels used when absorbing R1CS
/// instances into a transcript. Pinned strings so protocol implementers
/// in different runtimes can reproduce identical transcript states
/// from identical inputs.
/// </summary>
public static class WellKnownR1csTranscriptLabels
{
    /// <summary>Label for the dimensions absorb (m, n, public-input count, nnz_A, nnz_B, nnz_C).</summary>
    public const string Dimensions = "r1cs.instance.dimensions";

    /// <summary>Label for the absorb of matrix <c>A</c>.</summary>
    public const string MatrixA = "r1cs.instance.matrix.A";

    /// <summary>Label for the absorb of matrix <c>B</c>.</summary>
    public const string MatrixB = "r1cs.instance.matrix.B";

    /// <summary>Label for the absorb of matrix <c>C</c>.</summary>
    public const string MatrixC = "r1cs.instance.matrix.C";

    /// <summary>Label for the absorb of the public-input vector.</summary>
    public const string PublicInputs = "r1cs.instance.publicInputs";

    /// <summary>Label for the absorb of the relaxation scalar <c>u</c> of a relaxed R1CS instance.</summary>
    public const string RelaxationScalar = "r1cs.instance.u";

    /// <summary>Label for the absorb of the Hyrax commitment to the error vector <c>E</c> of a relaxed R1CS instance.</summary>
    public const string ErrorCommitment = "r1cs.instance.error-commitment";
}