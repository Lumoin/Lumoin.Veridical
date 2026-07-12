using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// The outcome of running a sumcheck protocol's verifier: either the
/// proof verified and the result carries the terminating algebraic
/// material the caller's outer protocol needs, or the proof was
/// rejected with a structured reason.
/// </summary>
/// <remarks>
/// <para>
/// Discriminated union via abstract record + sealed nested records.
/// Pattern match on the case:
/// </para>
/// <code>
/// switch(result)
/// {
///     case SumcheckResult.Verified v:
///         // v.FinalEvaluation, v.Challenges
///         break;
///     case SumcheckResult.Rejected r:
///         // r.Reason, r.RoundIndex
///         break;
/// }
/// </code>
/// <para>
/// The result is <see cref="IDisposable"/> because
/// <see cref="Verified"/> carries pool-rented scalar handles that must
/// be returned. <see cref="Rejected"/>'s dispose is a no-op so
/// callers can <c>using</c> the result unconditionally.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "Nested sealed records form the closed-hierarchy discriminated union pattern.")]
public abstract record SumcheckResult: IDisposable
{
    //Private base constructor + sealed nested subclasses: only the two
    //cases below can extend the result type.
    private SumcheckResult() { }


    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }


    /// <summary>Override in concrete subclasses to release resources.</summary>
    /// <param name="disposing"><see langword="true"/> when called from <see cref="Dispose()"/>; <see langword="false"/> from a finalizer.</param>
    protected virtual void Dispose(bool disposing) { }


    /// <summary>
    /// The sumcheck verifier accepted the proof. The result carries
    /// the terminating evaluation at the squeezed challenge vector and
    /// the per-round challenges, both of which the outer protocol
    /// typically continues to consume.
    /// </summary>
    /// <param name="FinalEvaluation">The scalar value the prover claims for the polynomial evaluated at the challenge vector — what the outer protocol checks against its own commitment opening.</param>
    /// <param name="Challenges">The verifier challenges in round order, of length equal to the sumcheck's <c>NumRounds</c>.</param>
    public sealed record Verified(
        Scalar FinalEvaluation,
        IReadOnlyList<Scalar> Challenges): SumcheckResult
    {
        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if(disposing)
            {
                FinalEvaluation?.Dispose();
                if(Challenges is not null)
                {
                    foreach(Scalar challenge in Challenges)
                    {
                        challenge?.Dispose();
                    }
                }
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// The sumcheck verifier rejected the proof. <see cref="Reason"/>
    /// describes the failing invariant; <see cref="RoundIndex"/> is the
    /// zero-based round where the violation was detected, or <c>-1</c>
    /// when the rejection is not round-specific (e.g.,
    /// <see cref="SumcheckRejectionReason.RoundCountMismatch"/>).
    /// </summary>
    /// <param name="Reason">The failure category.</param>
    /// <param name="RoundIndex">The round index at which the failure was detected, or <c>-1</c> when not applicable.</param>
    public sealed record Rejected(
        SumcheckRejectionReason Reason,
        int RoundIndex): SumcheckResult
    { }
}