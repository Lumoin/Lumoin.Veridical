using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Verbose inspector for <see cref="RawR1csInstance"/>.
/// </summary>
public static class RawR1csInstanceInspector
{
    /// <summary>Inspects <paramref name="instance"/> and returns the bundled report.</summary>
    public static RawR1csInstanceReport Inspect(RawR1csInstance instance)
    {
        ArgumentNullException.ThrowIfNull(instance);

        return new RawR1csInstanceReport(
            Dimensions: instance.Dimensions,
            NonzeroCounts: new RawR1csInstanceNonzeroCounts(instance.A.NonzeroCount, instance.B.NonzeroCount, instance.C.NonzeroCount),
            Curve: instance.Curve,
            TagSummary: RenderTagSummary(instance.Tag));
    }


    private static string RenderTagSummary(Tag tag)
    {
        var builder = new StringBuilder();
        bool first = true;
        foreach(var entry in tag.Entries)
        {
            if(!first)
            {
                builder.Append(", ");
            }

            builder.Append(entry.Key.Name);
            builder.Append('=');
            builder.Append(entry.Value);
            first = false;
        }


        return builder.ToString();
    }
}


/// <summary>Bundled facts about a single <see cref="RawR1csInstance"/>.</summary>
public sealed record RawR1csInstanceReport(
    R1csDimensions Dimensions,
    RawR1csInstanceNonzeroCounts NonzeroCounts,
    CurveParameterSet Curve,
    string TagSummary);


/// <summary>The per-matrix non-zero counts of an R1CS instance.</summary>
public readonly record struct RawR1csInstanceNonzeroCounts(int A, int B, int C);