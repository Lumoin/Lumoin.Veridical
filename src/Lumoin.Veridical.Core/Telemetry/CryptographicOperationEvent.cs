using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Telemetry;

/// <summary>
/// A single cryptographic-operation observation: the kind of operation,
/// the curve it ran over, the count it represents, and a timestamp tick
/// for ordering against other events.
/// </summary>
/// <param name="Kind">The category of operation.</param>
/// <param name="Curve">The curve parameter set the operation ran over. <see cref="CurveParameterSet.None"/> when the operation is curve-agnostic.</param>
/// <param name="Delta">The number of operations this event represents. For batched ops, this is the batch count rather than one.</param>
/// <param name="TimestampTicks">A monotonically increasing tick value, obtained from <see cref="Stopwatch.GetTimestamp"/>. Suitable for ordering events but not for wall-clock time.</param>
/// <remarks>
/// <para>
/// Emitted on the <see cref="CryptographicOperationCounters"/> observable
/// stream when observation is enabled. Subscribers receive these in
/// emission order from each emitting thread. There is no global
/// happens-before guarantee across emitting threads — for that, callers
/// should provide their own synchronisation.
/// </para>
/// </remarks>
public readonly record struct CryptographicOperationEvent(
    CryptographicOperationKind Kind,
    CurveParameterSet Curve,
    long Delta,
    long TimestampTicks);