namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// Produces a systematic Reed–Solomon row encoder for the given message length and codeword length — the
/// wire-format Ligero flow's seam for google/longfellow-zk's <c>RSFactory::make(n, m)</c>. The binary hash
/// circuit closes the returned encoder over an <see cref="Algebraic.Lch14ReedSolomon"/>; the prime signature
/// circuit closes it over an <see cref="Algebraic.Fp256ReedSolomon"/>. The caller owns the encoder's disposal.
/// </summary>
/// <param name="dimension">The number of input evaluations (the message length <c>N</c>); at least 1.</param>
/// <param name="blockLength">The number of output evaluations (the codeword length <c>M</c>); at least <paramref name="dimension"/>.</param>
/// <returns>An encoder for the requested shape; the caller disposes it.</returns>
internal delegate LongfellowRowEncoder LongfellowRowEncoderFactory(int dimension, int blockLength);
