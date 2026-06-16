using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Thrown when a witness does not satisfy the R1CS instance it is
/// being proved against. The exception carries the first violated
/// constraint's index, the computed left-hand-side and right-hand-side
/// values, and the list of variable indices appearing in the violated
/// constraint, to support diagnosing witness-generation bugs in caller
/// code.
/// </summary>
/// <remarks>
/// <para>
/// The scalar fields are captured as hex strings rather than as
/// <see cref="Scalar"/> instances because the
/// <see cref="R1csSatisfaction.Violated"/> discriminator's scalars are
/// pool-rented and released when the satisfaction check's <c>using</c>
/// scope exits. The hex strings persist beyond that scope.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1032", Justification = "The exception's purpose is to surface a structured R1csSatisfaction.Violated diagnostic; constructors that omit the discriminator would produce a malformed instance with no diagnostic state.")]
public sealed class R1csNotSatisfiedException: InvalidOperationException
{
    /// <summary>The index of the first violated constraint.</summary>
    public R1csConstraintIndex ConstraintIndex { get; }

    /// <summary>The standard human-readable form of <see cref="ConstraintIndex"/>.</summary>
    public string ConstraintIndexDisplay => ConstraintIndex.ToString();

    /// <summary>The computed left-hand-side <c>(A·z)[i] · (B·z)[i]</c> in canonical big-endian hex.</summary>
    public string LeftHandSideHex { get; }

    /// <summary>The expected right-hand-side <c>(C·z)[i]</c> in canonical big-endian hex.</summary>
    public string RightHandSideHex { get; }

    /// <summary>The variable indices appearing with non-zero coefficient in the violated constraint's row of any of <c>A</c>, <c>B</c>, <c>C</c>.</summary>
    public IReadOnlyList<R1csVariableIndex> InvolvedVariables { get; }


    /// <summary>
    /// Constructs the exception from a
    /// <see cref="R1csSatisfaction.Violated"/> discriminator. The
    /// constructor reads the scalars and the variable list out of the
    /// discriminator immediately; the caller can dispose the
    /// discriminator after the exception is constructed.
    /// </summary>
    /// <param name="violated">The discriminator carrying the violated constraint's diagnostic state.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="violated"/> is <see langword="null"/>.</exception>
    public R1csNotSatisfiedException(R1csSatisfaction.Violated violated)
        : base(BuildMessage(violated))
    {
        ArgumentNullException.ThrowIfNull(violated);

        ConstraintIndex = violated.ConstraintIndex;
        LeftHandSideHex = violated.LeftHandSide.ToHexString();
        RightHandSideHex = violated.RightHandSide.ToHexString();
        InvolvedVariables = violated.InvolvedVariables.ToArray();
    }


    private static string BuildMessage(R1csSatisfaction.Violated violated)
    {
        ArgumentNullException.ThrowIfNull(violated);

        return $"R1CS instance not satisfied by witness at constraint {violated.ConstraintIndex}: " +
               $"LHS = {violated.LeftHandSide.ToHexString()}, " +
               $"RHS = {violated.RightHandSide.ToHexString()}.";
    }
}