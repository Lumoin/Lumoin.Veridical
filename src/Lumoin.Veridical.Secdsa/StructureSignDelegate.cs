using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Signs the encoded bytes of a transferable-proof structure: the challenge signature <c>Sig</c> of party <c>T</c>
/// under its challenge signing key <c>s</c> (Verheul Algorithm 22 step 7), or the response signature <c>SigP</c> of the
/// prover under its record signing key <c>v</c> (Algorithm 23 step 14). The library does not choose the signature
/// scheme or its encoding; the caller binds one, and the private key may live in an HSM or a remote service behind
/// the delegate.
/// </summary>
/// <param name="structure">The encoded structure, as a layout profile wrote it.</param>
/// <param name="signature">The buffer that receives the signature; its length is <see cref="TransferableProofAlgorithm.MaxSignatureSizeBytes"/>.</param>
/// <returns>The number of signature bytes written, between 1 and the buffer length.</returns>
public delegate int StructureSignDelegate(ReadOnlySpan<byte> structure, Span<byte> signature);
