namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A single multiplication constraint <c>W[z] = W[x]·W[y]</c> over the witness
/// vector, naming the three witness positions it relates. The Ligero tableau
/// lays the <c>x</c>, <c>y</c> and <c>z</c> operands of a batch of these into
/// the three rows of a quadratic-row triple; the verifier's quadratic test
/// then checks the product relation holds across the committed columns.
/// </summary>
/// <param name="XIndex">The witness index of the left multiplicand <c>x</c>.</param>
/// <param name="YIndex">The witness index of the right multiplicand <c>y</c>.</param>
/// <param name="ZIndex">The witness index of the product <c>z</c>.</param>
/// <remarks>
/// The indices address the witness vector the tableau is built over; each must
/// be in <c>[0, witnessCount)</c>. The constraint is the quadratic half of the
/// rank-one form a circuit reduces to — the linear half is carried separately by
/// the dot-product test's constraint matrix.
/// </remarks>
public readonly record struct LigeroQuadraticConstraint(int XIndex, int YIndex, int ZIndex);
