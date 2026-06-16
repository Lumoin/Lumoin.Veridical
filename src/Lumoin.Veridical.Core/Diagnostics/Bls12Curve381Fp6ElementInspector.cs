using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural facts about a <see cref="Fp6Element"/>'s
/// canonical byte encoding without performing Fp6 arithmetic.
/// </summary>
/// <remarks>
/// Pure read-only verb: it observes the element through the public
/// read-only span and returns a single
/// <see cref="Fp6ElementInspectionReport"/>. No backend delegates are
/// called.
/// </remarks>
public static class Bls12Curve381Fp6ElementInspector
{
    /// <summary>
    /// Inspects <paramref name="element"/> and returns the bundled report.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="element"/> is <see langword="null"/>.</exception>
    public static Fp6ElementInspectionReport Inspect(Fp6Element element)
    {
        ArgumentNullException.ThrowIfNull(element);

        return new Fp6ElementInspectionReport(
            ByteLength: element.AsReadOnlySpan().Length,
            IsZero: element.IsZero,
            IsOne: element.IsOne,
            C0ComponentHex: Convert.ToHexStringLower(element.GetC0ComponentBytes()),
            C1ComponentHex: Convert.ToHexStringLower(element.GetC1ComponentBytes()),
            C2ComponentHex: Convert.ToHexStringLower(element.GetC2ComponentBytes()));
    }
}


/// <summary>Bundled facts about a single <see cref="Fp6Element"/>.</summary>
/// <param name="ByteLength">Length in bytes of the canonical encoding (always 288 for well-formed inputs).</param>
/// <param name="IsZero">True when all three Fp2 components are the field zero.</param>
/// <param name="IsOne">True when the element is the multiplicative identity.</param>
/// <param name="C0ComponentHex">Lowercase hexadecimal rendering of the 96-byte <c>c0</c> Fp2 component (constant term).</param>
/// <param name="C1ComponentHex">Lowercase hexadecimal rendering of the 96-byte <c>c1</c> Fp2 component (<c>v</c>-coefficient).</param>
/// <param name="C2ComponentHex">Lowercase hexadecimal rendering of the 96-byte <c>c2</c> Fp2 component (<c>v²</c>-coefficient).</param>
public sealed record Fp6ElementInspectionReport(
    int ByteLength,
    bool IsZero,
    bool IsOne,
    string C0ComponentHex,
    string C1ComponentHex,
    string C2ComponentHex);