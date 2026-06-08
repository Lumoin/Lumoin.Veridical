using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural facts about a <see cref="Fp2Element"/>'s
/// canonical byte encoding without performing Fp2 arithmetic.
/// </summary>
/// <remarks>
/// The inspector is a pure read-only verb: it observes the element
/// through the public read-only span and returns a single
/// <see cref="Fp2ElementInspectionReport"/>. No backend delegates are
/// called.
/// </remarks>
public static class Bls12Curve381Fp2ElementInspector
{
    /// <summary>
    /// Inspects <paramref name="element"/> and returns the bundled report.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="element"/> is <see langword="null"/>.</exception>
    public static Fp2ElementInspectionReport Inspect(Fp2Element element)
    {
        ArgumentNullException.ThrowIfNull(element);

        return new Fp2ElementInspectionReport(
            ByteLength: element.AsReadOnlySpan().Length,
            IsZero: element.IsZero,
            IsOne: element.IsOne,
            RealComponentHex: Convert.ToHexStringLower(element.GetRealComponentBytes()),
            ImaginaryComponentHex: Convert.ToHexStringLower(element.GetImaginaryComponentBytes()));
    }
}


/// <summary>Bundled facts about a single <see cref="Fp2Element"/>.</summary>
/// <param name="ByteLength">Length in bytes of the canonical encoding (always 96 for well-formed inputs).</param>
/// <param name="IsZero">True when both components are the field zero.</param>
/// <param name="IsOne">True when the element is the multiplicative identity <c>(1, 0)</c>.</param>
/// <param name="RealComponentHex">Lowercase hexadecimal rendering of the 48-byte <c>c0</c> component.</param>
/// <param name="ImaginaryComponentHex">Lowercase hexadecimal rendering of the 48-byte <c>c1</c> component.</param>
public sealed record Fp2ElementInspectionReport(
    int ByteLength,
    bool IsZero,
    bool IsOne,
    string RealComponentHex,
    string ImaginaryComponentHex);