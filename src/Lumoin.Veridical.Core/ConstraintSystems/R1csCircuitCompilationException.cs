using System;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Thrown when compiling an <see cref="R1csCircuit"/> against a set of input
/// bindings fails: a required input value is missing, the circuit has no
/// constraints, or — the load-bearing case — the supplied assignment does
/// not satisfy the circuit's constraints. The last is almost always a bug in
/// a predicate generator (the constraints it emitted disagree with the
/// auxiliary values it asked the caller to supply); catching it at compile
/// time surfaces it far more clearly than a later proof rejection would.
/// </summary>
public sealed class R1csCircuitCompilationException: Exception
{
    /// <inheritdoc/>
    public R1csCircuitCompilationException()
    {
    }

    /// <inheritdoc/>
    public R1csCircuitCompilationException(string message)
        : base(message)
    {
    }

    /// <inheritdoc/>
    public R1csCircuitCompilationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
