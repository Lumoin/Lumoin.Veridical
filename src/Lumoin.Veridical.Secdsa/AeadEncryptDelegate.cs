using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Authenticated encryption <c>(C, T) = ENC[K, P, A]</c> of ECIES step 4 (Verheul Annex A.4): encrypts the plaintext
/// and authenticates it together with the additional authenticated data. The library never implements the cipher;
/// the caller binds the platform's AEAD, for example AES-256-GCM.
/// </summary>
/// <param name="key">The AEAD key; secret.</param>
/// <param name="iv">The initialisation vector, as the parameter set sizes it.</param>
/// <param name="plaintext">The plaintext <c>P</c>; secret.</param>
/// <param name="associatedData">The additional authenticated data <c>A</c>; authenticated, not encrypted.</param>
/// <param name="ciphertext">Receives the ciphertext <c>C</c>, exactly as long as <paramref name="plaintext"/>.</param>
/// <param name="tag">Receives the authentication tag <c>T</c>, exactly the tag length of the parameter set.</param>
public delegate void AeadEncryptDelegate(
    ReadOnlySpan<byte> key,
    ReadOnlySpan<byte> iv,
    ReadOnlySpan<byte> plaintext,
    ReadOnlySpan<byte> associatedData,
    Span<byte> ciphertext,
    Span<byte> tag);
