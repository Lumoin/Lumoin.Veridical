using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// The initial claim of a sumcheck instance: the prover asserts that
/// the multilinear sum of some polynomial over <c>{0,1}^NumRounds</c>
/// equals <see cref="ClaimedSum"/>, with every per-round univariate
/// polynomial of degree at most <see cref="DegreeBound"/>.
/// </summary>
/// <param name="ClaimedSum">The scalar the prover asserts the sumcheck terminates against. The caller owns the scalar's lifetime; the claim does not.</param>
/// <param name="NumRounds">The number of sumcheck rounds, equal to the number of variables of the underlying polynomial.</param>
/// <param name="DegreeBound">The maximum algebraic degree of each round polynomial; e.g. 3 for the outer Spartan sumcheck and 2 for the inner.</param>
/// <remarks>
/// <para>
/// The struct is a thin metadata header — the bulk of the proof lives
/// in the per-round messages, not here. It is used twice in one
/// sumcheck run: once by the prover as the running-claim seed, and
/// once by the verifier as the assertion against which the
/// per-round polynomials' boundary identities are checked.
/// </para>
/// <para>
/// The struct does not own the <see cref="ClaimedSum"/> scalar's
/// buffer. Callers must keep the scalar alive while any consumer of
/// the claim still holds a copy of the struct.
/// </para>
/// </remarks>
public readonly record struct SumcheckClaim(
    Scalar ClaimedSum,
    int NumRounds,
    int DegreeBound);