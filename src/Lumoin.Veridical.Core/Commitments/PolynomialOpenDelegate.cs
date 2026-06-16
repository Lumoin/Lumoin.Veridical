using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Produces an evaluation argument attesting that a committed polynomial
/// evaluates at <paramref name="evaluationPoint"/> to a value (returned
/// alongside the argument). One operation of the polynomial-commitment
/// surface; the implementation has its commitment key and algebraic
/// backends captured, so the call site supplies the commitment, its blind,
/// the polynomial, the point, and the live transcript.
/// </summary>
/// <remarks>
/// The argument is threaded through the Fiat-Shamir transcript (the
/// scheme's opening sub-protocol absorbs and squeezes), mirroring the
/// <c>prove</c> method of Microsoft Research's Spartan2 <c>PCSEngineTrait</c>;
/// structural inspiration only, no code dependency. See microsoft/Spartan2.
/// </remarks>
/// <param name="commitment">The commitment being opened.</param>
/// <param name="blind">The blind retained from the commit that produced <paramref name="commitment"/>.</param>
/// <param name="polynomial">The committed polynomial.</param>
/// <param name="evaluationPoint">The point at which to open.</param>
/// <param name="transcript">The live Fiat-Shamir transcript the opening sub-protocol drives.</param>
/// <param name="pool">The pool the opening buffer is rented from.</param>
/// <returns>The opening (evaluation argument) and the claimed evaluation value.</returns>
public delegate (PolynomialOpening Opening, Scalar ClaimedValue) PolynomialOpenDelegate(
    PolynomialCommitment commitment,
    PolynomialCommitmentBlind blind,
    MultilinearExtension polynomial,
    ReadOnlySpan<Scalar> evaluationPoint,
    FiatShamirTranscript transcript,
    BaseMemoryPool pool);
