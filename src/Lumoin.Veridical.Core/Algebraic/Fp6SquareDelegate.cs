using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form square <c>a²</c> of an Fp6
/// extension-field element over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp6 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form square into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// A specialised Fp6 squaring routine (Chung-Hasan variants) can save
/// Fp2 multiplications versus self-multiplication; the result must agree
/// with <c>a · a</c> byte-for-byte.
/// </remarks>
public delegate void Fp6SquareDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);