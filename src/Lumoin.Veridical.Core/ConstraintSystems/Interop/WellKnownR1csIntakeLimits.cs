using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Well-known intake ceilings for the <c>maximumIntakeBytes</c> parameter of
/// <see cref="R1csPipeReaderDelegate"/> and <see cref="R1csWitnessPipeReaderDelegate"/>.
/// </summary>
public static class WellKnownR1csIntakeLimits
{
    /// <summary>
    /// The runtime's own addressable ceiling (<see cref="Array.MaxLength"/>), not a safety limit.
    /// Passing it admits any input the runtime could hold in one array regardless of size, so a
    /// caller reaching for it is making the deliberate choice to impose no budget of its own; that
    /// choice then reads plainly at the call site rather than as an accidental default.
    /// </summary>
    public static long Unbounded { get; } = Array.MaxLength;
}
