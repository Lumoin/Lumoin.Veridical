using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A single term of the linear half of the constraint system: it contributes
/// <c>coefficient · W[witnessIndex]</c> to linear constraint
/// <paramref name="ConstraintIndex"/>. A linear constraint <c>c</c> is the sum
/// of all terms sharing its index, asserted equal to that constraint's target
/// <c>b[c]</c> — so a constraint with several witnesses on its left-hand side is
/// expressed as several terms with the same <paramref name="ConstraintIndex"/>.
/// </summary>
/// <param name="ConstraintIndex">The linear constraint this term belongs to; in <c>[0, linearConstraintCount)</c>.</param>
/// <param name="WitnessIndex">The witness position the coefficient multiplies; in <c>[0, witnessCount)</c>.</param>
/// <param name="Coefficient">The field coefficient, one canonical big-endian scalar (<see cref="Lumoin.Veridical.Core.Algebraic.Scalar.SizeBytes"/> bytes).</param>
/// <remarks>
/// This is the sparse, coordinate-style counterpart to
/// <see cref="LigeroQuadraticConstraint"/>: the quadratic constraints carry the
/// multiplication gates, the linear terms carry the additive (and copy) wiring.
/// The dot-product test folds all terms into the constraint matrix <c>A</c> with
/// the per-constraint challenge <c>αl[c]</c>, and its value check confirms
/// <c>Σ_c b[c]·αl[c]</c> against the prover's response, so a witness violating
/// any linear constraint is caught with overwhelming probability.
/// </remarks>
public readonly record struct LigeroLinearConstraint(int ConstraintIndex, int WitnessIndex, ReadOnlyMemory<byte> Coefficient);
