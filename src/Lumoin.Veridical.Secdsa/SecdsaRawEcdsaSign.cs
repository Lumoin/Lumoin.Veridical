using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Raw-ECDSA-signs a 32-byte message representative under a hardware-held P-256 key, returning the raw
/// components <c>(r, s₀)</c>. This is the seam SECDSA's split sign delegates the actual signature to: the
/// device computes the blind <c>e' = P⁻¹·e</c> and the mask <c>s = P·s₀</c> around this call, while the
/// signing key <c>u</c> stays inside the hardware — a TPM <c>TPM2_Sign</c> or a PKCS#11 <c>CKM_ECDSA</c> call
/// over the device key handle. For a software-only deployment the implementation holds <c>u</c> in memory
/// instead (see <see cref="SecdsaSoftwareRawSigner"/>). Either way <see cref="SecdsaAlgorithm"/> never sees
/// <c>u</c>.
/// </summary>
/// <param name="messageRepresentative">The 32-byte big-endian value to raw-sign — the blinded hash <c>e'</c> in split sign.</param>
/// <param name="r">Receives the 32-byte component <c>r = (k·G).x mod n</c>.</param>
/// <param name="s0">Receives the 32-byte raw component <c>s₀ = k⁻¹(e' + r·u) mod n</c>.</param>
/// <remarks>
/// The implementation must return <c>r</c> and <c>s₀</c> in <c>[1, n−1]</c> (a correct ECDSA signer does;
/// a degenerate <c>r = 0</c>/<c>s₀ = 0</c> has probability ~<c>1/n</c>). Split sign defensively rejects a
/// degenerate result rather than emitting an invalid signature.
/// </remarks>
public delegate void SecdsaRawEcdsaSign(
    ReadOnlySpan<byte> messageRepresentative,
    Span<byte> r,
    Span<byte> s0);
