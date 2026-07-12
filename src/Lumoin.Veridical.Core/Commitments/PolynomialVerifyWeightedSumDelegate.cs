using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Verifies that a vector commitment produced via
/// <see cref="PolynomialCommitmentProvider.CommitVector"/> opens to the
/// claimed inner product <c>⟨vector, weights⟩</c> against the public weight
/// vector under <paramref name="opening"/>. The weighted analogue of
/// <see cref="PolynomialVerifyEvaluationDelegate"/>; exception-safe against
/// malformed opening bytes — it returns <see langword="false"/> rather than
/// throwing.
/// </summary>
/// <remarks>
/// Statement-binding is the caller's obligation, exactly as for
/// <see cref="PolynomialVerifyEvaluationDelegate"/>: the argument binds
/// <paramref name="weights"/> and <paramref name="claimedValue"/> only through
/// the shared <paramref name="transcript"/>. A composing protocol absorbs them
/// before calling; a standalone caller must absorb them itself.
/// </remarks>
/// <param name="commitment">The vector commitment being checked.</param>
/// <param name="weights">The public weight vector, carried as an MLE.</param>
/// <param name="claimedValue">The claimed inner-product value.</param>
/// <param name="opening">The weighted-opening argument to verify.</param>
/// <param name="transcript">The live Fiat-Shamir transcript the verification replays.</param>
/// <param name="pool">The pool for scratch allocations.</param>
/// <returns><see langword="true"/> iff the opening attests the claimed weighted sum.</returns>
public delegate bool PolynomialVerifyWeightedSumDelegate(
    PolynomialCommitment commitment,
    MultilinearExtension weights,
    Scalar claimedValue,
    PolynomialOpening opening,
    FiatShamirTranscript transcript,
    BaseMemoryPool pool);
