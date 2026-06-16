using Lumoin.Veridical.Core.Spartan;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Verbose inspector for <see cref="SpartanProof"/>. Returns a
/// structured summary of the proof's dimensions, total wire size,
/// curve, and tag entries.
/// </summary>
public static class SpartanProofInspector
{
    /// <summary>Inspects <paramref name="proof"/> and returns the bundled report.</summary>
    public static SpartanProofReport Inspect(SpartanProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);

        return new SpartanProofReport(
            WitnessCommitmentRowCount: proof.WitnessCommitmentRowCount,
            OuterRoundCount: proof.OuterRoundCount,
            InnerRoundCount: proof.InnerRoundCount,
            IpaRoundCount: proof.IpaRoundCount,
            TotalByteLength: proof.AsReadOnlySpan().Length,
            Curve: proof.Curve,
            TagSummary: RenderTagSummary(proof.Tag));
    }


    private static string RenderTagSummary(Tag tag)
    {
        var builder = new StringBuilder();
        bool first = true;
        foreach(var entry in tag.Data)
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


/// <summary>Bundled facts about a single <see cref="SpartanProof"/>.</summary>
public sealed record SpartanProofReport(
    int WitnessCommitmentRowCount,
    int OuterRoundCount,
    int InnerRoundCount,
    int IpaRoundCount,
    int TotalByteLength,
    CurveParameterSet Curve,
    string TagSummary);