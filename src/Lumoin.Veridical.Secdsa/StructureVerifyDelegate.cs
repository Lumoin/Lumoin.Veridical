using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Verifies a signature over the encoded bytes of a transferable-proof structure: the challenge signature <c>Sig</c>
/// under the public key <c>S</c> of party <c>T</c>, or the response signature <c>SigP</c> under the public key <c>V</c>
/// of the prover. The caller binds the key and the scheme; the library never chooses them.
/// </summary>
/// <param name="structure">The encoded structure, as a layout profile wrote it.</param>
/// <param name="signature">The signature to verify; wire data.</param>
/// <returns><see langword="true"/> when the signature is valid; <see langword="false"/> otherwise, including for a malformed signature, which the delegate must not report by exception.</returns>
public delegate bool StructureVerifyDelegate(ReadOnlySpan<byte> structure, ReadOnlySpan<byte> signature);
