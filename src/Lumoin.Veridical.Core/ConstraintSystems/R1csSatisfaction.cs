using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The result of an R1CS satisfaction check: either every constraint
/// holds, or the check stopped at a specific failing constraint and
/// reports what went wrong.
/// </summary>
/// <remarks>
/// <para>
/// Discriminated union via abstract record + sealed nested records.
/// Use pattern matching to handle the cases:
/// </para>
/// <code>
/// switch(result)
/// {
///     case R1csSatisfaction.Satisfied:
///         // every constraint held.
///         break;
///     case R1csSatisfaction.Violated v:
///         // v.ConstraintIndex, v.LeftHandSide, etc.
///         break;
/// }
/// </code>
/// <para>
/// The result type is <see cref="IDisposable"/> because the
/// <see cref="Violated"/> case carries pool-rented scalars whose
/// backing buffers must be returned. <see cref="Satisfied"/>'s
/// <see cref="Dispose()"/> is a no-op; callers can <c>using</c> the
/// result unconditionally.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "Nested sealed records form the closed-hierarchy discriminated union pattern; the cases are intrinsically part of the result type and pulling them into siblings would lose the closed-hierarchy property.")]
public abstract record R1csSatisfaction: IDisposable
{
    //Private constructor + nested sealed subclasses give a closed
    //hierarchy: only the two cases below can extend this base.
    private R1csSatisfaction() { }


    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Override in concrete subclasses to release resources.
    /// </summary>
    /// <param name="disposing"><see langword="true"/> when called from <see cref="Dispose()"/>; <see langword="false"/> from a finalizer (the records here have no native resources so finalisation is not used).</param>
    protected virtual void Dispose(bool disposing) { }


    /// <summary>
    /// The witness satisfies every constraint of the instance.
    /// </summary>
    public sealed record Satisfied: R1csSatisfaction { }


    /// <summary>
    /// At least one constraint failed; the first failure's details are
    /// reported. The satisfaction check returns on the first violation;
    /// later violations are not detected.
    /// </summary>
    /// <param name="ConstraintIndex">The constraint row that failed.</param>
    /// <param name="LeftHandSide">The computed value <c>(A·z)[i] · (B·z)[i] mod r</c>.</param>
    /// <param name="RightHandSide">The expected value <c>(C·z)[i] mod r</c>.</param>
    /// <param name="InvolvedVariables">Sorted unique variable indices with non-zero coefficients in row <c>i</c> of A, B, or C. Useful for diagnostic narrowing.</param>
    public sealed record Violated(
        R1csConstraintIndex ConstraintIndex,
        Scalar LeftHandSide,
        Scalar RightHandSide,
        IReadOnlyList<R1csVariableIndex> InvolvedVariables): R1csSatisfaction
    {
        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if(disposing)
            {
                LeftHandSide?.Dispose();
                RightHandSide?.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}