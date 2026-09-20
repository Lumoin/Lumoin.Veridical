using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Thrown by an R1CS pipe reader when the accumulated input exceeds the caller's declared intake
/// ceiling. The exception is a resource-budget concern, distinct from a malformed-input concern such
/// as <see cref="R1csUnsupportedFieldException"/>, so a host parsing untrusted streams can tell "the
/// input is too large" apart from "the input is malformed" and answer each differently.
/// </summary>
public sealed class R1csIntakeLimitExceededException: Exception
{
    /// <summary>The ceiling the caller declared, in bytes.</summary>
    public long MaximumIntakeBytes { get; }

    /// <summary>The buffered length, in bytes, observed when the ceiling was exceeded.</summary>
    public long ObservedIntakeBytes { get; }


    /// <summary>Initialises the exception with the ceiling and the buffered length that exceeded it.</summary>
    public R1csIntakeLimitExceededException(
        long maximumIntakeBytes,
        long observedIntakeBytes)
        : base(BuildMessage(maximumIntakeBytes, observedIntakeBytes))
    {
        MaximumIntakeBytes = maximumIntakeBytes;
        ObservedIntakeBytes = observedIntakeBytes;
    }


    /// <inheritdoc/>
    public R1csIntakeLimitExceededException()
        : this(0, 0)
    {
    }


    /// <inheritdoc/>
    public R1csIntakeLimitExceededException(string message)
        : base(message)
    {
        MaximumIntakeBytes = 0;
        ObservedIntakeBytes = 0;
    }


    /// <inheritdoc/>
    public R1csIntakeLimitExceededException(string message, Exception innerException)
        : base(message, innerException)
    {
        MaximumIntakeBytes = 0;
        ObservedIntakeBytes = 0;
    }


    /// <summary>Formats the exception message from the declared ceiling and the buffered length that exceeded it.</summary>
    private static string BuildMessage(long maximumIntakeBytes, long observedIntakeBytes) =>
        $"The R1CS pipe intake ceiling of {maximumIntakeBytes} byte(s) was exceeded; the buffered input reached {observedIntakeBytes} byte(s). Pass a larger maximumIntakeBytes, or WellKnownR1csIntakeLimits.Unbounded when the input is trusted to be this large.";
}
