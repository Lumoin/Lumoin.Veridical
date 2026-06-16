using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// Encrypts one 16-byte block under a 32-byte key, a single AES-256 block transform in electronic
/// codebook mode (no chaining, no IV, no padding) — the pseudo-random function the Longfellow
/// transcript squeezes through, a port of google/longfellow-zk's <c>util/crypto.h</c> <c>PRF</c>
/// (<c>EVP_aes_256_ecb</c> with <c>EVP_EncryptUpdate</c> on a single block). The reference keys this
/// with the SHA-256 snapshot of the transcript so far and feeds it the little-endian block counter, so
/// the deployed Fiat–Shamir challenge stream is exactly this primitive's output; reproducing it bit
/// for bit is part of the wire format.
/// </summary>
/// <remarks>
/// <para>
/// Delegate-injected for the same reason the SHA-256 hash and the curve backends are: the transcript
/// stays primitive-agnostic, and the application wires the concrete AES-256-ECB implementation at
/// composition time. The reference uses ECB deliberately — the input blocks are never repeated within
/// one PRF (the counter strictly increments), so ECB's lack of chaining is sound here; the
/// construction exploits only AES's pseudo-random-function property, not a cipher mode's semantic
/// security.
/// </para>
/// <para>
/// The contract is exact: <paramref name="key"/> is 32 bytes (AES-256, <c>kPRFKeySize</c>),
/// <paramref name="input"/> is 16 bytes (one block, <c>kPRFInputSize</c>), and
/// <paramref name="output"/> is 16 bytes (<c>kPRFOutputSize</c>). The implementation must apply the raw
/// AES-256 block function with no padding and no mode chaining — equivalently, AES-256-ECB over a
/// single block — and must not retain the spans beyond the call.
/// </para>
/// </remarks>
/// <param name="key">The 32-byte AES-256 key (the SHA-256 snapshot of the transcript so far).</param>
/// <param name="input">The 16-byte plaintext block (the little-endian PRF block counter).</param>
/// <param name="output">The 16-byte ciphertext destination (the squeezed pseudo-random block).</param>
internal delegate void LongfellowTranscriptBlockCipher(
    ReadOnlySpan<byte> key,
    ReadOnlySpan<byte> input,
    Span<byte> output);
