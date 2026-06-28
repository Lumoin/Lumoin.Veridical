using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural facts about a <see cref="Polynomial"/> without
/// performing arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// Same pattern as the other inspectors. Returns one
/// <see cref="PolynomialReport"/> bundling every fact a debugger
/// typically wants to see at once.
/// </para>
/// <para>
/// The coefficients hex renders the full buffer for polynomials of
/// storage degree up to and including 16 (17 slots, ~544 bytes for
/// BLS12-381). For larger polynomials the snippet covers only the
/// first 17 coefficients; the rest is truncated to keep the report
/// readable.
/// </para>
/// </remarks>
public static class PolynomialInspector
{
    private const int MaximumCoefficientsToRender = 17;


    /// <summary>
    /// Inspects <paramref name="polynomial"/> and returns the bundled report.
    /// </summary>
    /// <param name="polynomial">The polynomial to inspect.</param>
    /// <returns>The inspection report.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="polynomial"/> is <see langword="null"/>.</exception>
    public static PolynomialReport Inspect(Polynomial polynomial)
    {
        ArgumentNullException.ThrowIfNull(polynomial);

        ReadOnlySpan<byte> bytes = polynomial.AsReadOnlySpan();
        int elementSize = polynomial.FieldElementSizeBytes;
        int coefficientsToRender = Math.Min(polynomial.CoefficientCount, MaximumCoefficientsToRender);
        int renderLength = coefficientsToRender * elementSize;

        string coefficientsHex = renderLength == 0
            ? string.Empty
            : Convert.ToHexStringLower(bytes[..renderLength]);

        return new PolynomialReport(
            Degree: polynomial.Degree,
            FieldElementSizeBytes: elementSize,
            Curve: polynomial.Curve,
            IsZero: polynomial.IsZero,
            IsConstant: polynomial.IsConstant,
            IsLinear: polynomial.IsLinear,
            CoefficientsHex: coefficientsHex,
            CoefficientsRendered: coefficientsToRender,
            TagSummary: RenderTagSummary(polynomial.Tag));
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


/// <summary>
/// Bundled facts about a single <see cref="Polynomial"/>.
/// </summary>
/// <param name="Degree">The storage degree; <c>Degree + 1</c> coefficients are stored.</param>
/// <param name="FieldElementSizeBytes">The byte size of one coefficient.</param>
/// <param name="Curve">The curve identifying the field.</param>
/// <param name="IsZero">True when every coefficient is the field zero.</param>
/// <param name="IsConstant">True when the polynomial represents a constant — degree zero, or every non-constant coefficient is zero.</param>
/// <param name="IsLinear">True when the storage degree is exactly one.</param>
/// <param name="CoefficientsHex">Lowercase hex of the first <paramref name="CoefficientsRendered"/> coefficients, concatenated low-degree first.</param>
/// <param name="CoefficientsRendered">The number of coefficients the hex snippet covers; equals <c>min(Degree + 1, 17)</c>.</param>
/// <param name="TagSummary">A human-readable rendering of the polynomial's tag entries.</param>
public sealed record PolynomialReport(
    int Degree,
    int FieldElementSizeBytes,
    CurveParameterSet Curve,
    bool IsZero,
    bool IsConstant,
    bool IsLinear,
    string CoefficientsHex,
    int CoefficientsRendered,
    string TagSummary);