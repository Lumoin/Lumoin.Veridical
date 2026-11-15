using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The key derivation <c>K(Seed, D, L)</c> of the transferable proof (Verheul Annex A.5, before Algorithm 22): a
/// byte array of <c>L</c> bytes derived from the master key <c>Seed</c> and the derivation byte array <c>D</c>. The
/// paper deploys HKDF for it, outside the HSM; the caller binds the derivation, for example
/// HKDF-SHA-256 with the seed as input keying material and <c>D</c> as the info string.
/// </summary>
/// <param name="masterKey">The seed; secret.</param>
/// <param name="derivationInput">The derivation byte array <c>D</c>, produced by the layout profile.</param>
/// <param name="output">Receives exactly <c>output.Length</c> pseudorandom bytes; secret.</param>
/// <remarks>
/// The output feeds a reduction modulo <c>q − 1</c> with 8 more bytes than the group order is wide, as the BSI
/// specification the paper follows does, so the derived ephemeral keys are uniform up to a negligible bias. A
/// derivation that bounds the length of <paramref name="derivationInput"/> bounds the additional authenticated
/// data a challenge can carry; the delegate reports an unusable input with an <see cref="ArgumentException"/>.
/// </remarks>
public delegate void SeedKeyDerivationDelegate(
    ReadOnlySpan<byte> masterKey,
    ReadOnlySpan<byte> derivationInput,
    Span<byte> output);
