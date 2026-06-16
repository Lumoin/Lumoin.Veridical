using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// One operation in a circuit's canonical operations list. A circuit is
/// an ordered, immutable sequence of these; the fluent
/// <see cref="R1csCircuitBuilder"/> is notation for constructing the
/// sequence, and compilation folds over it.
/// </summary>
/// <remarks>
/// <para>
/// This is a deliberately closed hierarchy: the only implementations are
/// the <c>sealed record</c> op types in this namespace
/// (<see cref="DeclareConstantOneOp"/>, <see cref="DeclarePublicInputOp"/>,
/// <see cref="DeclareWitnessVariableOp"/>,
/// <see cref="DeclareIntermediateVariableOp"/>,
/// <see cref="AddConstraintOp"/>). External implementations are not
/// supported — the compiler switches exhaustively over the known set, and
/// predicates emit ops from this set rather than introducing new ones.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1040:Avoid empty interfaces", Justification = "Deliberate closed-hierarchy discriminator: the op types carry no common member, only a shared marker the compiler switches over exhaustively. A member would be artificial.")]
public interface IR1csOp
{
}
