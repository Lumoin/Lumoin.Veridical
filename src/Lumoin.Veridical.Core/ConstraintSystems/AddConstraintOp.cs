namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Adds one rank-1 constraint <c>(Left) · (Middle) = (Right)</c>, where
/// each operand is a linear combination of variables. This is the only
/// primitive constraint op; every predicate composes down to a sequence
/// of these (plus the auxiliary variable declarations they need).
/// </summary>
/// <param name="Left">The left factor's linear combination (a row of the <c>A</c> matrix).</param>
/// <param name="Middle">The right factor's linear combination (a row of the <c>B</c> matrix).</param>
/// <param name="Right">The product's linear combination (a row of the <c>C</c> matrix).</param>
public sealed record AddConstraintOp(
    R1csLinearCombination Left,
    R1csLinearCombination Middle,
    R1csLinearCombination Right): IR1csOp;
