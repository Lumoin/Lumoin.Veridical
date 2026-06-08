using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Verbose inspector for <see cref="RawR1csWitness"/>.
/// </summary>
public static class RawR1csWitnessInspector
{
    private const int MaximumScalarsToRender = 8;


    /// <summary>Inspects <paramref name="witness"/> and returns the bundled report.</summary>
    public static RawR1csWitnessReport Inspect(RawR1csWitness witness)
    {
        ArgumentNullException.ThrowIfNull(witness);

        int scalarSize = Scalar.SizeBytes;
        int rendered = Math.Min(witness.WitnessVariableCount, MaximumScalarsToRender);
        ReadOnlySpan<byte> bytes = witness.GetWitnessBytes();
        string hex = rendered == 0 ? string.Empty : Convert.ToHexStringLower(bytes[..(rendered * scalarSize)]);

        return new RawR1csWitnessReport(
            WitnessVariableCount: witness.WitnessVariableCount,
            Curve: witness.Curve,
            FirstScalarsRendered: rendered,
            FirstScalarsHex: hex,
            TagSummary: RenderTagSummary(witness.Tag));
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


/// <summary>Bundled facts about a single <see cref="RawR1csWitness"/>.</summary>
public sealed record RawR1csWitnessReport(
    int WitnessVariableCount,
    CurveParameterSet Curve,
    int FirstScalarsRendered,
    string FirstScalarsHex,
    string TagSummary);