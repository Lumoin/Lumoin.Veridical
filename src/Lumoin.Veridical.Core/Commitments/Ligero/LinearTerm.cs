using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// One term <c>coefficient · W[wire]</c> of a linear constraint being assembled
/// by <see cref="LigeroConstraintSystemBuilder"/>. It is the builder-time, wire-
/// relative counterpart of <see cref="LigeroLinearConstraint"/> (which is
/// constraint-relative): the builder assigns the constraint index when the
/// terms are submitted to <see cref="LigeroConstraintSystemBuilder.AddLinear"/>.
/// </summary>
/// <param name="Wire">The wire (witness position) the coefficient multiplies.</param>
/// <param name="Coefficient">The field coefficient as one canonical big-endian scalar (<see cref="Lumoin.Veridical.Core.Algebraic.Scalar.SizeBytes"/> bytes).</param>
internal readonly record struct LinearTerm(int Wire, ReadOnlyMemory<byte> Coefficient);
