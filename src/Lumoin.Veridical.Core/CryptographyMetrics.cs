namespace Lumoin.Veridical.Core;

/// <summary>
/// Centralised constants for Lumoin.Veridical library metrics and meter names.
/// Provides a single discoverable location for consumers who need to reference
/// metric names for monitoring, alerting, or dashboard configuration.
/// </summary>
/// <remarks>
/// <para>
/// Meter names are used by metrics collection infrastructure (such as
/// OpenTelemetry) to register which meters to collect from. When you register a
/// meter name like <c>Lumoin.Veridical</c>, the collector will gather all
/// instruments (counters, histograms, gauges) created by any <c>Meter</c>
/// instance with that exact name.
/// </para>
/// <para>
/// Example usage in application startup:
/// </para>
/// <code>
/// services.AddOpenTelemetry()
///     .WithMetrics(builder => builder
///         .AddMeter(CryptographyMetrics.MeterName)
///         .AddPrometheusExporter());
/// </code>
/// <para>
/// Individual metric names are used by monitoring dashboards, alert rules, and
/// analysis tools to query specific metrics. The naming follows the pattern
/// <c>Lumoin.Veridical.&lt;Component&gt;.&lt;Metric&gt;</c> so consumers can
/// scope queries by component prefix.
/// </para>
/// </remarks>
public static class CryptographyMetrics
{
    /// <summary>
    /// Primary meter name for Lumoin.Veridical components. Register this meter
    /// name in your metrics collection configuration to collect all library
    /// metrics including memory pool operations, prover phase timings, and
    /// allocation efficiency counters.
    /// </summary>
    /// <remarks>
    /// When registered, this meter will collect metrics from all components that
    /// create <c>Meter</c> instances with this name, including
    /// <c>SensitiveMemoryPool</c> instances and any prover- or verifier-side
    /// components that emit telemetry through the library's standard channel.
    /// </remarks>
    public static string MeterName { get; } = "Lumoin.Veridical";


    /// <summary>
    /// Observable counter tracking the total number of memory slabs across all
    /// buffer sizes. Higher values may indicate memory pressure or fragmentation
    /// across many distinct allocation sizes.
    /// Unit: slabs (count).
    /// </summary>
    public static string SensitiveMemoryPoolTotalSlabs { get; } = "Lumoin.Veridical.SensitiveMemoryPool.TotalSlabs";

    /// <summary>
    /// Observable counter tracking total memory allocated across all slabs.
    /// Includes both currently-rented and available segments.
    /// Unit: bytes.
    /// </summary>
    public static string SensitiveMemoryPoolTotalMemoryAllocated { get; } = "Lumoin.Veridical.SensitiveMemoryPool.TotalMemoryAllocated";

    /// <summary>
    /// Observable counter tracking the number of currently rented memory
    /// segments. Indicates current memory pressure and the count of active
    /// cryptographic operations holding pool-backed buffers.
    /// Unit: segments (count).
    /// </summary>
    public static string SensitiveMemoryPoolActiveRentals { get; } = "Lumoin.Veridical.SensitiveMemoryPool.ActiveRentals";

    /// <summary>
    /// Observable counter tracking allocation efficiency as a percentage.
    /// Calculated as <c>(active rentals / total allocated segments) * 100</c>.
    /// Persistently low values suggest the pool is over-provisioned for the
    /// current workload; consider <c>TrimExcess</c>.
    /// Unit: percent (0–100).
    /// </summary>
    public static string SensitiveMemoryPoolAllocationEfficiency { get; } = "Lumoin.Veridical.SensitiveMemoryPool.AllocationEfficiency";

    /// <summary>
    /// Histogram tracking the distribution of requested buffer sizes. Used to
    /// identify the dominant allocation sizes a workload exercises, which
    /// informs capacity-strategy tuning.
    /// Unit: bytes.
    /// </summary>
    public static string SensitiveMemoryPoolBufferSizeDistribution { get; } = "Lumoin.Veridical.SensitiveMemoryPool.BufferSizeDistribution";

    /// <summary>
    /// Counter tracking the total number of successful rent operations. Used
    /// alongside <see cref="SensitiveMemoryPoolReturnOperationsTotal"/> to
    /// detect leaks (rent count growing without matching return count).
    /// Unit: operations (cumulative count).
    /// </summary>
    public static string SensitiveMemoryPoolRentOperationsTotal { get; } = "Lumoin.Veridical.SensitiveMemoryPool.RentOperationsTotal";

    /// <summary>
    /// Counter tracking the total number of memory return operations. Should
    /// correlate with <see cref="SensitiveMemoryPoolRentOperationsTotal"/> for
    /// proper resource management.
    /// Unit: operations (cumulative count).
    /// </summary>
    public static string SensitiveMemoryPoolReturnOperationsTotal { get; } = "Lumoin.Veridical.SensitiveMemoryPool.ReturnOperationsTotal";
}