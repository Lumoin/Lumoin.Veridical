using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Verbose inspector for <see cref="R1csMatrix"/>.
/// </summary>
public static class R1csMatrixInspector
{
    private const int MaximumTriplesToRender = 8;


    /// <summary>Inspects <paramref name="matrix"/> and returns the bundled report.</summary>
    public static R1csMatrixReport Inspect(R1csMatrix matrix)
    {
        ArgumentNullException.ThrowIfNull(matrix);

        int rendered = Math.Min(matrix.NonzeroCount, MaximumTriplesToRender);
        var builder = new StringBuilder();
        for(int i = 0; i < rendered; i++)
        {
            (int row, int column) = matrix.GetTriplePosition(i);
            if(i > 0)
            {
                builder.Append("; ");
            }

            builder.Append('(').Append(row).Append(", ").Append(column).Append(", ").Append(Convert.ToHexStringLower(matrix.GetValueBytes(i))).Append(')');
        }


        return new R1csMatrixReport(
            RowCount: matrix.RowCount,
            ColumnCount: matrix.ColumnCount,
            NonzeroCount: matrix.NonzeroCount,
            Curve: matrix.Curve,
            FirstTriplesRendered: rendered,
            FirstTriplesSummary: builder.ToString(),
            TagSummary: RenderTagSummary(matrix.Tag));
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


/// <summary>Bundled facts about a single <see cref="R1csMatrix"/>.</summary>
public sealed record R1csMatrixReport(
    int RowCount,
    int ColumnCount,
    int NonzeroCount,
    CurveParameterSet Curve,
    int FirstTriplesRendered,
    string FirstTriplesSummary,
    string TagSummary);