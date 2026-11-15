using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Derives the ECDH-MAC key <c>K</c> from the Diffie-Hellman shared secret <c>Z_AB</c> (the x-coordinate of the
/// shared point) and the application context <c>SharedInfo</c>. The key-derivation function is a call-site choice
/// because the paper uses two different ones for the same <c>K</c>: Algorithms 16 and 17 derive
/// <c>K = HKDF(Z_AB, SharedInfo)</c>, bound to HKDF-SHA256 (the
/// library's <c>Sha256Hkdf.DeriveKey</c> method group converts directly), whereas the split form of
/// Algorithm 12 lets the HSM derive <c>K</c> with the PKCS#11 mechanism <c>CKM_ECDH1_DERIVE</c> and
/// <c>CKD_SHA256_KDF</c>, an ANSI X9.63 KDF over SHA-256. The two give different <c>K</c> for the same
/// <c>Z_AB</c>, so signer and verifier must bind the same function.
/// </summary>
/// <param name="salt">The extraction salt of a salted KDF such as HKDF (empty selects the RFC 5869 default); a KDF without a salt, such as X9.63, ignores it.</param>
/// <param name="sharedSecret">The 32-byte shared secret <c>Z_AB</c>; secret.</param>
/// <param name="sharedInfo">The context/application information <c>SharedInfo</c>; may be empty.</param>
/// <param name="macKey">Receives the derived key <c>K</c>; its length selects how much keying material is derived.</param>
public delegate void EcdhMacKeyDerivationDelegate(
    ReadOnlySpan<byte> salt,
    ReadOnlySpan<byte> sharedSecret,
    ReadOnlySpan<byte> sharedInfo,
    Span<byte> macKey);
