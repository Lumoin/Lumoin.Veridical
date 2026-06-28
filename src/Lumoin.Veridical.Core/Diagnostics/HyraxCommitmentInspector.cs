using Lumoin.Veridical.Core.Commitments;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Verbose inspector for <see cref="HyraxCommitment"/>.
/// </summary>
public static class HyraxCommitmentInspector
{
    /// <summary>Inspects <paramref name="commitment"/> and returns the bundled report.</summary>
    public static HyraxCommitmentReport Inspect(HyraxCommitment commitment)
    {
        ArgumentNullException.ThrowIfNull(commitment);

        string firstRowHex = commitment.RowCount == 0
            ? string.Empty
            : Convert.ToHexStringLower(commitment.GetRowCommitment(0));

        return new HyraxCommitmentReport(
            RowCount: commitment.RowCount,
            ColumnCount: commitment.ColumnCount,
            VariableCount: commitment.VariableCount,
            Curve: commitment.Curve,
            FirstRowCommitmentHex: firstRowHex,
            TagSummary: RenderTagSummary(commitment.Tag));
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


/// <summary>Bundled facts about a single <see cref="HyraxCommitment"/>.</summary>
public sealed record HyraxCommitmentReport(
    int RowCount,
    int ColumnCount,
    int VariableCount,
    CurveParameterSet Curve,
    string FirstRowCommitmentHex,
    string TagSummary);