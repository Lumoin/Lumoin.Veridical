using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Commits to a multilinear polynomial, returning the commitment and the
/// blind retained for the matching open. One operation of the
/// polynomial-commitment surface; a concrete scheme (Hyrax today) provides
/// an implementation with its commitment key and algebraic backends
/// captured, so the call site supplies only the polynomial and a pool.
/// </summary>
/// <remarks>
/// Mirrors the <c>commit</c> method of Microsoft Research's Spartan2
/// <c>PCSEngineTrait</c> (with the key and randomness backend captured
/// rather than passed per call); structural inspiration only, no code
/// dependency. See microsoft/Spartan2 on GitHub.
/// </remarks>
/// <param name="polynomial">The multilinear polynomial to commit to.</param>
/// <param name="pool">The pool the commitment and blind buffers are rented from.</param>
/// <returns>The commitment and the blind (kept by the prover for the future open).</returns>
public delegate (PolynomialCommitment Commitment, PolynomialCommitmentBlind Blind) PolynomialCommitDelegate(
    MultilinearExtension polynomial,
    BaseMemoryPool pool);
