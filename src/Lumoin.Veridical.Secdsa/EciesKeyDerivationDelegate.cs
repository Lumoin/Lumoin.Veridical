using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The key-derivation function <c>K = KDF(Z_AB, A)</c> of ECIES (Verheul Algorithms 18 and 19, steps 3 and 2):
/// turns the Diffie-Hellman shared secret and the shared data into the key material the authenticated encryption
/// uses. The key material comprises the AEAD key and the initialisation vector; how it is split is a property of
/// the <see cref="EciesParameterSet"/>, not of the delegate.
/// </summary>
/// <param name="sharedSecret">The shared secret <c>Z_AB</c>, the x-coordinate of the Diffie-Hellman point; secret.</param>
/// <param name="sharedData">The shared data the derivation binds: the additional authenticated data <c>A</c> when the parameter set says so, otherwise empty.</param>
/// <param name="keyMaterial">Receives exactly <c>keyMaterial.Length</c> bytes of derived key material; secret.</param>
public delegate void EciesKeyDerivationDelegate(
    ReadOnlySpan<byte> sharedSecret,
    ReadOnlySpan<byte> sharedData,
    Span<byte> keyMaterial);
