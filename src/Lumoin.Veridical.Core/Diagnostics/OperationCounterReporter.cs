using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Formats <see cref="CryptographicOperationCounters"/> snapshots for
/// human inspection and computes diffs between two snapshots.
/// </summary>
/// <remarks>
/// <para>
/// The counter surface itself returns <see cref="IReadOnlyDictionary{TKey, TValue}"/>
/// — efficient to consume programmatically, but awkward to read in a test
/// failure message or a benchmark log. The reporter exists to turn a
/// snapshot into a single-string table, ordered by descending count, with
/// a totals row at the bottom.
/// </para>
/// <para>
/// <see cref="ComputeDelta"/> turns a "before" and "after" pair into the
/// per-kind change, dropping any kind whose count did not move. Bench
/// harnesses use this to print the operation count attributable to a
/// single benchmarked call rather than the cumulative process count.
/// </para>
/// <para>
/// The reporter is a pure read-only verb: it does not call
/// <see cref="CryptographicOperationCounters.Snapshot"/> implicitly except
/// in the no-argument <see cref="FormatCurrentSnapshot"/> convenience.
/// Callers wanting test-deterministic reports take a snapshot at a
/// well-defined moment and pass it explicitly to
/// <see cref="FormatSnapshot"/>.
/// </para>
/// </remarks>
public static class OperationCounterReporter
{
    private const string EmptySnapshotPlaceholder = "(no operations recorded)";

    private const int CountColumnWidth = 14;


    /// <summary>
    /// Calls <see cref="CryptographicOperationCounters.Snapshot"/> and
    /// formats the result. Convenience for ad-hoc debugger and post-mortem
    /// use; tests should prefer <see cref="FormatSnapshot"/> with an
    /// explicit snapshot to keep the read deterministic.
    /// </summary>
    public static string FormatCurrentSnapshot()
    {
        return FormatSnapshot(CryptographicOperationCounters.Snapshot());
    }


    /// <summary>
    /// Formats <paramref name="snapshot"/> as a left-padded name column
    /// followed by a right-padded count column. Rows are sorted by
    /// descending count; a separator and a totals row follow the data.
    /// </summary>
    /// <param name="snapshot">The snapshot to format.</param>
    /// <returns>The formatted multi-line string, or a placeholder when <paramref name="snapshot"/> is empty.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="snapshot"/> is <see langword="null"/>.</exception>
    public static string FormatSnapshot(IReadOnlyDictionary<CryptographicOperationKind, long> snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        if(snapshot.Count == 0)
        {
            return EmptySnapshotPlaceholder;
        }

        int nameColumnWidth = ComputeNameColumnWidth(snapshot.Keys);
        long totalCount = 0;
        var orderedEntries = snapshot.OrderByDescending(kvp => kvp.Value).ToList();
        var builder = new StringBuilder();

        foreach(KeyValuePair<CryptographicOperationKind, long> entry in orderedEntries)
        {
            string name = CryptographicOperationKindNames.GetName(entry.Key);
            builder.Append(name.PadRight(nameColumnWidth));
            builder.Append(' ');
            builder.Append(entry.Value.ToString("N0", CultureInfo.InvariantCulture).PadLeft(CountColumnWidth));
            builder.AppendLine();
            totalCount += entry.Value;
        }

        builder.AppendLine(new string('-', nameColumnWidth + 1 + CountColumnWidth));
        builder.Append("Total".PadRight(nameColumnWidth));
        builder.Append(' ');
        builder.Append(totalCount.ToString("N0", CultureInfo.InvariantCulture).PadLeft(CountColumnWidth));

        return builder.ToString();
    }


    /// <summary>
    /// Returns the per-kind difference <c>after - before</c>, with entries
    /// whose count did not move filtered out. A kind that disappears
    /// between the two snapshots (only possible after a
    /// <see cref="CryptographicOperationCounters.Reset"/>) shows up with a
    /// negative delta.
    /// </summary>
    /// <param name="before">The earlier snapshot.</param>
    /// <param name="after">The later snapshot.</param>
    /// <returns>A dictionary of non-zero deltas keyed by operation kind.</returns>
    /// <exception cref="ArgumentNullException">When either snapshot is <see langword="null"/>.</exception>
    public static IReadOnlyDictionary<CryptographicOperationKind, long> ComputeDelta(
        IReadOnlyDictionary<CryptographicOperationKind, long> before,
        IReadOnlyDictionary<CryptographicOperationKind, long> after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var result = new Dictionary<CryptographicOperationKind, long>();

        foreach(KeyValuePair<CryptographicOperationKind, long> entry in after)
        {
            long previous = before.TryGetValue(entry.Key, out long b) ? b : 0;
            long delta = entry.Value - previous;
            if(delta != 0)
            {
                result[entry.Key] = delta;
            }
        }

        foreach(KeyValuePair<CryptographicOperationKind, long> entry in before)
        {
            if(!after.ContainsKey(entry.Key) && entry.Value != 0)
            {
                result[entry.Key] = -entry.Value;
            }
        }


        return result;
    }


    private static int ComputeNameColumnWidth(IEnumerable<CryptographicOperationKind> kinds)
    {
        int width = "Total".Length;
        foreach(CryptographicOperationKind kind in kinds)
        {
            int candidate = CryptographicOperationKindNames.GetName(kind).Length;
            if(candidate > width)
            {
                width = candidate;
            }
        }


        return width;
    }
}