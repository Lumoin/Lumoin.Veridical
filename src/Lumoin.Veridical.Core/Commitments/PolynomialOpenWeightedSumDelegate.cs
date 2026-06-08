using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Produces a weighted-opening argument attesting that a vector committed via
/// <see cref="PolynomialCommitmentProvider.CommitVector"/> has the inner
/// product <c>⟨vector, weights⟩</c> with a <em>public</em> weight vector
/// (returned alongside the argument). The weighted analogue of
/// <see cref="PolynomialOpenDelegate"/>: where an evaluation opening binds a
/// point, this binds an arbitrary public linear functional of the committed
/// coordinates — the binding the statistical sumcheck mask uses for its
/// coefficient vector (<c>ZK-STATMASK-DESIGN.md</c> §2 v3).
/// </summary>
/// <remarks>
/// The weight vector is public protocol shape — the verifier derives it from
/// its own challenges — so it is neither committed nor transmitted. Schemes
/// that internally enlarge the committed vector (the ZK BaseFold dimension
/// lift) extend the weights with zeros over the internal block, keeping the
/// claimed value the inner product over the caller's coordinates.
/// </remarks>
/// <param name="commitment">The vector commitment being opened.</param>
/// <param name="blind">The blind retained from the vector commit.</param>
/// <param name="vector">The committed vector, carried as an MLE.</param>
/// <param name="weights">The public weight vector, carried as an MLE of the same shape.</param>
/// <param name="transcript">The live Fiat-Shamir transcript the opening sub-protocol drives.</param>
/// <param name="pool">The pool the opening buffer is rented from.</param>
/// <returns>The weighted opening and the claimed inner-product value.</returns>
public delegate (PolynomialOpening Opening, Scalar ClaimedValue) PolynomialOpenWeightedSumDelegate(
    PolynomialCommitment commitment,
    PolynomialCommitmentBlind blind,
    MultilinearExtension vector,
    MultilinearExtension weights,
    FiatShamirTranscript transcript,
    SensitiveMemoryPool<byte> pool);
