using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Common;

/// <summary>
/// Marker interface for builder state types — the side-channel a
/// <see cref="R1csBuilder{TResult, TState, TBuilder}"/> threads through its
/// fold so transformations can consult build context that is not the result.
/// </summary>
/// <remarks>
/// Mirrors the <c>IBuilderState</c> marker in the Verifiable library. Marker
/// interfaces are an exception to the general preference against interfaces:
/// this one exists for type identity in the builder's generic constraint
/// (<c>where TState : IBuilderState</c>), not for extensibility.
/// </remarks>
[SuppressMessage("Design", "CA1040:Avoid empty interfaces", Justification = "Marker interface tagging builder state types for the generic constraint on R1csBuilder; not an extensibility surface.")]
public interface IBuilderState
{
}
