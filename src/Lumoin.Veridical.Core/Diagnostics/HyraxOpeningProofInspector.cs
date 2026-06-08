using Lumoin.Veridical.Core.Commitments;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Verbose inspector for <see cref="HyraxOpeningProof"/>.
/// </summary>
public static class HyraxOpeningProofInspector
{
    /// <summary>Inspects <paramref name="proof"/> and returns the bundled report.</summary>
    public static HyraxOpeningProofReport Inspect(HyraxOpeningProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);

        return new HyraxOpeningProofReport(
            IpaRoundCount: proof.IpaRoundCount,
            Curve: proof.Curve,
            FCommitmentHex: Convert.ToHexStringLower(proof.GetFCommitment()),
            FinalScalarHex: Convert.ToHexStringLower(proof.GetFinalScalar()),
            FinalBlindingHex: Convert.ToHexStringLower(proof.GetFinalBlinding()),
            BlindingCorrectionHex: Convert.ToHexStringLower(proof.GetBlindingCorrection()),
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


/// <summary>Bundled facts about a single <see cref="HyraxOpeningProof"/>.</summary>
public sealed record HyraxOpeningProofReport(
    int IpaRoundCount,
    CurveParameterSet Curve,
    string FCommitmentHex,
    string FinalScalarHex,
    string FinalBlindingHex,
    string BlindingCorrectionHex,
    string TagSummary);