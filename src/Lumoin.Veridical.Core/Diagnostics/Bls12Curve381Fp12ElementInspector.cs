using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural facts about a <see cref="Fp12Element"/>'s
/// canonical byte encoding without performing Fp12 arithmetic.
/// </summary>
/// <remarks>
/// Pure read-only verb: it observes the element through the public
/// read-only span and returns a single
/// <see cref="Fp12ElementInspectionReport"/>. No backend delegates are
/// called.
/// </remarks>
public static class Bls12Curve381Fp12ElementInspector
{
    /// <summary>
    /// Inspects <paramref name="element"/> and returns the bundled report.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="element"/> is <see langword="null"/>.</exception>
    public static Fp12ElementInspectionReport Inspect(Fp12Element element)
    {
        ArgumentNullException.ThrowIfNull(element);

        return new Fp12ElementInspectionReport(
            ByteLength: element.AsReadOnlySpan().Length,
            IsZero: element.IsZero,
            IsOne: element.IsOne,
            C0ComponentHex: Convert.ToHexStringLower(element.GetC0ComponentBytes()),
            C1ComponentHex: Convert.ToHexStringLower(element.GetC1ComponentBytes()));
    }
}


/// <summary>Bundled facts about a single <see cref="Fp12Element"/>.</summary>
/// <param name="ByteLength">Length in bytes of the canonical encoding (always 576 for well-formed inputs).</param>
/// <param name="IsZero">True when both Fp6 components are the field zero.</param>
/// <param name="IsOne">True when the element is the multiplicative identity.</param>
/// <param name="C0ComponentHex">Lowercase hexadecimal rendering of the 288-byte <c>c0</c> Fp6 component (constant term).</param>
/// <param name="C1ComponentHex">Lowercase hexadecimal rendering of the 288-byte <c>c1</c> Fp6 component (<c>w</c>-coefficient).</param>
public sealed record Fp12ElementInspectionReport(
    int ByteLength,
    bool IsZero,
    bool IsOne,
    string C0ComponentHex,
    string C1ComponentHex);