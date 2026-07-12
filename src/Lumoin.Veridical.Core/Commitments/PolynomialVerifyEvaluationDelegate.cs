using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Verifies that <paramref name="commitment"/> opens to
/// <paramref name="claimedValue"/> at <paramref name="evaluationPoint"/>
/// under <paramref name="opening"/>. One operation of the
/// polynomial-commitment surface; returns whether the evaluation argument
/// checks out.
/// </summary>
/// <remarks>
/// <para>
/// Threaded through the Fiat-Shamir transcript, mirroring the
/// <c>verify</c> method of Microsoft Research's Spartan2
/// <c>PCSEngineTrait</c>; structural inspiration only, no code dependency.
/// See microsoft/Spartan2. The implementation is exception-safe against
/// malformed opening bytes — it returns <see langword="false"/> rather
/// than throwing.
/// </para>
/// <para>
/// Statement-binding is the caller's obligation. The opening argument binds
/// <paramref name="evaluationPoint"/> and <paramref name="claimedValue"/>
/// only through the shared <paramref name="transcript"/>; the sub-protocol
/// does not itself absorb them. A protocol that composes this delegate (as
/// Spartan does) absorbs the evaluation point and claimed value into the
/// transcript before calling it, so those values are bound for the composed
/// proof. A caller wiring this delegate standalone must do the same
/// absorption itself before invoking it — otherwise a prover could fix the
/// challenge first and back-solve the claim.
/// </para>
/// </remarks>
/// <param name="commitment">The commitment being checked.</param>
/// <param name="evaluationPoint">The point at which the evaluation is claimed.</param>
/// <param name="claimedValue">The claimed evaluation value.</param>
/// <param name="opening">The evaluation argument to verify.</param>
/// <param name="transcript">The live Fiat-Shamir transcript the verification replays.</param>
/// <param name="pool">The pool for scratch allocations.</param>
/// <returns><see langword="true"/> iff the opening attests the claimed evaluation.</returns>
public delegate bool PolynomialVerifyEvaluationDelegate(
    PolynomialCommitment commitment,
    ReadOnlySpan<Scalar> evaluationPoint,
    Scalar claimedValue,
    PolynomialOpening opening,
    FiatShamirTranscript transcript,
    BaseMemoryPool pool);
