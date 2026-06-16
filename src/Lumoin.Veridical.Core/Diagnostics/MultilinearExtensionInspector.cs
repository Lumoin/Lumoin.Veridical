using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural facts about a
/// <see cref="MultilinearExtension"/> without performing arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// Same pattern as the scalar and G1-point inspectors landed in the
/// consolidation batch: a pure read-only verb that observes the MLE
/// through the public surface and returns a single
/// <see cref="MultilinearExtensionReport"/>. No backend delegates are
/// called, so this is safe to use inside test assertions, debugger
/// displays, and post-mortem dumps.
/// </para>
/// <para>
/// The hex snippet truncates to the first eight evaluations when the
/// MLE is larger; full-buffer rendering would dominate the report for
/// MLEs over many variables. Eight slots is enough to recognise common
/// patterns at a glance (all-zero high bytes, ascending sequence, the
/// canonical scalar one) without flooding the output.
/// </para>
/// </remarks>
public static class MultilinearExtensionInspector
{
    private const int MaximumEvaluationsToRender = 8;


    /// <summary>
    /// Inspects <paramref name="mle"/> and returns the bundled report.
    /// </summary>
    /// <param name="mle">The MLE to inspect.</param>
    /// <returns>The inspection report.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="mle"/> is <see langword="null"/>.</exception>
    public static MultilinearExtensionReport Inspect(MultilinearExtension mle)
    {
        ArgumentNullException.ThrowIfNull(mle);

        ReadOnlySpan<byte> bytes = mle.AsReadOnlySpan();
        int elementSize = mle.FieldElementSizeBytes;
        int evaluationsToRender = Math.Min(mle.EvaluationCount, MaximumEvaluationsToRender);
        int renderLength = evaluationsToRender * elementSize;

        string firstEvaluationsHex = renderLength == 0
            ? string.Empty
            : Convert.ToHexStringLower(bytes[..renderLength]);

        return new MultilinearExtensionReport(
            VariableCount: mle.VariableCount,
            EvaluationCount: mle.EvaluationCount,
            FieldElementSizeBytes: elementSize,
            Curve: mle.Curve,
            IsZero: mle.IsZero,
            IsConstant: mle.IsConstant,
            FirstEvaluationsHex: firstEvaluationsHex,
            FirstEvaluationsRendered: evaluationsToRender,
            TagSummary: RenderTagSummary(mle.Tag));
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


/// <summary>
/// Bundled facts about a single <see cref="MultilinearExtension"/>.
/// </summary>
/// <param name="VariableCount">The number of variables <c>n</c>.</param>
/// <param name="EvaluationCount">The number of evaluations stored (<c>2^n</c>).</param>
/// <param name="FieldElementSizeBytes">The byte size of one field element.</param>
/// <param name="Curve">The curve identifying the field.</param>
/// <param name="IsZero">True when every evaluation is the field zero.</param>
/// <param name="IsConstant">True when every evaluation is the same field element.</param>
/// <param name="FirstEvaluationsHex">Lowercase hex of the first <paramref name="FirstEvaluationsRendered"/> evaluations, concatenated. Truncated when the MLE has more than that many evaluations.</param>
/// <param name="FirstEvaluationsRendered">The number of evaluations the hex snippet covers; equals <c>min(EvaluationCount, 8)</c>.</param>
/// <param name="TagSummary">A human-readable rendering of the MLE's tag entries.</param>
public sealed record MultilinearExtensionReport(
    int VariableCount,
    int EvaluationCount,
    int FieldElementSizeBytes,
    CurveParameterSet Curve,
    bool IsZero,
    bool IsConstant,
    string FirstEvaluationsHex,
    int FirstEvaluationsRendered,
    string TagSummary);