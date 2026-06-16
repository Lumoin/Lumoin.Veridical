using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form square <c>a²</c> of an Fp12
/// extension-field element over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp12 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form square into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// A specialised Fp12 squaring routine (complex squaring on the Fp6
/// halves) can save Fp6 multiplications versus self-multiplication; the
/// result must agree with <c>a · a</c> byte-for-byte. Cyclotomic
/// squaring — the substantially cheaper variant valid only inside the
/// cyclotomic subgroup — is a separate delegate introduced with the
/// pairing batch.
/// </remarks>
public delegate void Fp12SquareDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);