using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// A field's <c>sample</c> draw for elements that are not a single little-endian integer: fills the
/// working-domain canonical scalar with one uniformly random field element, drawing raw bytes through
/// <paramref name="fillBytes"/> with the field's own mask-then-reject structure. The sextic ML-DSA
/// circuit field rejects per 23-bit coordinate (the reference's <c>Fp24_6::sample</c>, six independent
/// base-field draws), which the single-integer mask of
/// <see cref="LongfellowFieldProfile.SampleElement"/> cannot express.
/// </summary>
/// <param name="fillBytes">The raw-byte fill callback (the transcript PRF squeeze or the commit's entropy source).</param>
/// <param name="working">Receives the working-domain canonical scalar; <see cref="Algebraic.Scalar.SizeBytes"/> bytes.</param>
internal delegate void LongfellowElementSampleDelegate(LongfellowRandomByteSource fillBytes, Span<byte> working);
