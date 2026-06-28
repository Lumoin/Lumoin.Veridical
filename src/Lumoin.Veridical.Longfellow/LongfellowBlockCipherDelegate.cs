using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// Encrypts a single block of <paramref name="input"/> under <paramref name="key"/> into
/// <paramref name="output"/> — the Fiat-Shamir transcript's pseudo-random permutation seam (production: a
/// single-block AES-256-ECB).
/// </summary>
/// <param name="key">The cipher key.</param>
/// <param name="input">One input block.</param>
/// <param name="output">Receives the encrypted block.</param>
public delegate void LongfellowBlockCipherDelegate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output);
