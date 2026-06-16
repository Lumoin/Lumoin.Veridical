using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Telemetry;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Behavioural tests for <see cref="OperationCounterReporter"/>. Verify
/// the formatted snapshot string for the empty and non-empty cases and
/// the per-kind delta computation against canonical input/output pairs.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="OperationCounterReporter.FormatSnapshot"/> formats an
/// explicit snapshot dictionary; <see cref="OperationCounterReporter.FormatCurrentSnapshot"/>
/// reads from process-wide counter state, which would couple this class
/// to ordering against other tests. Tests here use the explicit-snapshot
/// overload to stay deterministic.
/// </para>
/// </remarks>
[TestClass]
internal sealed class OperationCounterReporterTests
{
    [TestMethod]
    public void FormatEmptySnapshotReturnsPlaceholder()
    {
        var emptySnapshot = new Dictionary<CryptographicOperationKind, long>();

        string formatted = OperationCounterReporter.FormatSnapshot(emptySnapshot);

        Assert.AreEqual("(no operations recorded)", formatted);
    }


    [TestMethod]
    public void FormatNonEmptySnapshotContainsKindNameAndCount()
    {
        var snapshot = new Dictionary<CryptographicOperationKind, long>
        {
            [CryptographicOperationKind.ScalarAdd] = 1234,
            [CryptographicOperationKind.G1Add] = 5
        };

        string formatted = OperationCounterReporter.FormatSnapshot(snapshot);

        Assert.Contains("ScalarAdd", formatted);
        Assert.Contains("G1Add", formatted);
        Assert.Contains("1,234", formatted);
        Assert.Contains("Total", formatted);
        Assert.Contains("1,239", formatted);
    }


    [TestMethod]
    public void FormatNonEmptySnapshotOrdersByDescendingCount()
    {
        // ScalarAdd has the largest count and should appear before G1Add in
        // the formatted output. Order is observable by index-of comparison.
        var snapshot = new Dictionary<CryptographicOperationKind, long>
        {
            [CryptographicOperationKind.G1Add] = 5,
            [CryptographicOperationKind.ScalarAdd] = 1234
        };

        string formatted = OperationCounterReporter.FormatSnapshot(snapshot);

        // Slice everything before the G1Add row and confirm ScalarAdd
        // appears there: this verifies the descending-count ordering
        // without comparing two integers directly, which is what the MSTest
        // analyzers want anyway.
        int g1AddIndex = formatted.IndexOf("G1Add", System.StringComparison.Ordinal);
        Assert.AreNotEqual(-1, g1AddIndex, "G1Add must appear in the output.");
        string sectionBeforeG1Add = formatted[..g1AddIndex];
        Assert.Contains("ScalarAdd", sectionBeforeG1Add);
    }


    [TestMethod]
    public void ComputeDeltaReturnsPerKindDifferences()
    {
        var before = new Dictionary<CryptographicOperationKind, long>
        {
            [CryptographicOperationKind.ScalarAdd] = 100,
            [CryptographicOperationKind.ScalarMultiply] = 50
        };

        var after = new Dictionary<CryptographicOperationKind, long>
        {
            [CryptographicOperationKind.ScalarAdd] = 150,
            [CryptographicOperationKind.ScalarMultiply] = 50,
            [CryptographicOperationKind.G1Add] = 7
        };

        IReadOnlyDictionary<CryptographicOperationKind, long> delta =
            OperationCounterReporter.ComputeDelta(before, after);

        // Unchanged kinds should be filtered out.
        Assert.IsFalse(delta.ContainsKey(CryptographicOperationKind.ScalarMultiply), "Kinds whose count did not move should be filtered out.");
        Assert.AreEqual(50L, delta[CryptographicOperationKind.ScalarAdd]);
        Assert.AreEqual(7L, delta[CryptographicOperationKind.G1Add]);
    }


    [TestMethod]
    public void ComputeDeltaSurfacesNegativeDeltaForVanishedKind()
    {
        // A kind present in before but absent from after — this can happen
        // after CryptographicOperationCounters.Reset between snapshots —
        // shows up with a negative delta equal to its previous count.
        var before = new Dictionary<CryptographicOperationKind, long>
        {
            [CryptographicOperationKind.ScalarAdd] = 42
        };

        var after = new Dictionary<CryptographicOperationKind, long>();

        IReadOnlyDictionary<CryptographicOperationKind, long> delta =
            OperationCounterReporter.ComputeDelta(before, after);

        Assert.AreEqual(-42L, delta[CryptographicOperationKind.ScalarAdd]);
    }


    [TestMethod]
    public void FormatCurrentSnapshotDoesNotThrow()
    {
        // Smoke test for the no-argument overload. It reads process-wide
        // state, so the contents aren't asserted; what matters is that the
        // method runs end-to-end without exceptions.
        string result = OperationCounterReporter.FormatCurrentSnapshot();

        Assert.IsNotNull(result);
    }
}