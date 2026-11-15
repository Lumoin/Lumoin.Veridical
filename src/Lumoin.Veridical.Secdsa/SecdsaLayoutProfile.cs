using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Encodes a typed value into a profile's byte layout by appending to a <see cref="LayoutWriter"/>.
/// </summary>
/// <typeparam name="TValue">The typed value.</typeparam>
/// <param name="value">The value to encode.</param>
/// <param name="writer">The writer the encoder appends to.</param>
public delegate void LayoutEncodeDelegate<in TValue>(TValue value, LayoutWriter writer);


/// <summary>
/// Decodes a profile's byte layout into a typed value. Layout bytes arrive from outside, so a structurally
/// malformed encoding is reported by the return value and never by an exception.
/// </summary>
/// <typeparam name="TValue">The typed value.</typeparam>
/// <param name="encoded">The bytes to decode; the whole span must be consumed.</param>
/// <param name="pool">The pool the decoded value is rented from.</param>
/// <param name="value">Receives the decoded value, owned by the caller, when the function returns <see langword="true"/>; otherwise <see langword="null"/>.</param>
/// <returns><see langword="true"/> when the bytes are a well-formed encoding of a value of the type.</returns>
public delegate bool LayoutDecodeDelegate<TValue>(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TValue? value)
    where TValue : class;


/// <summary>
/// Encodes the derivation byte array <c>D = [i] ‖ Ḡ ‖ D̄ ‖ AAD</c> from which the ephemeral private key
/// <c>eᵢ</c> is derived (Verheul Algorithm 22 step 4 and Algorithm 23 step 8).
/// </summary>
/// <param name="index">The index <c>i</c> of the key, zero-based.</param>
/// <param name="statement">The generators, public keys and additional authenticated data.</param>
/// <param name="writer">The writer the encoder appends to.</param>
public delegate void DerivationInputEncodeDelegate(int index, ProofStatement statement, LayoutWriter writer);


/// <summary>
/// Encodes the structure the challenger signs: <c>E ‖ Ḡ ‖ D̄ ‖ H2 ‖ AAD</c> (Verheul Algorithm 22 step 7, verified in
/// Algorithm 23 step 4 and Algorithm 24 step 4).
/// </summary>
/// <param name="ephemeralPublicKey">The ephemeral public key <c>E</c>.</param>
/// <param name="statement">The generators, public keys and additional authenticated data.</param>
/// <param name="secondaryDigest">The secondary hash <c>H2</c>.</param>
/// <param name="writer">The writer the encoder appends to.</param>
public delegate void ChallengeScopeEncodeDelegate(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, LayoutWriter writer);


/// <summary>
/// Encodes the structure the prover signs: <c>E ‖ Ḡ ‖ D̄ ‖ H2 ‖ AAD ‖ H1</c> (Verheul Algorithm 23 step 14, verified in
/// Algorithm 24 step 5).
/// </summary>
/// <param name="ephemeralPublicKey">The ephemeral public key <c>E</c>.</param>
/// <param name="statement">The generators, public keys and additional authenticated data.</param>
/// <param name="secondaryDigest">The secondary hash <c>H2</c>.</param>
/// <param name="primaryDigest">The primary hash <c>H1</c>.</param>
/// <param name="writer">The writer the encoder appends to.</param>
public delegate void ResponseScopeEncodeDelegate(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, ProofDigest primaryDigest, LayoutWriter writer);


/// <summary>
/// Encodes the ECIES plaintext <c>Seed ‖ ASD</c> of a transferable challenge (Verheul Algorithm 22 step 11).
/// </summary>
/// <param name="seed">The seed.</param>
/// <param name="additionalSecretData">The additional secret data <c>ASD</c>, which may be empty.</param>
/// <param name="writer">The writer the encoder appends to.</param>
public delegate void SeedPayloadEncodeDelegate(ProofSeed seed, AdditionalData additionalSecretData, LayoutWriter writer);


/// <summary>
/// Decodes the ECIES plaintext <c>Seed ‖ ASD</c> (Verheul Algorithm 23 step 7). The plaintext is released by an
/// authenticated decryption, but it was produced by the challenger and is still treated as wire data.
/// </summary>
/// <param name="encoded">The plaintext bytes.</param>
/// <param name="pool">The pool the decoded values are rented from.</param>
/// <param name="seed">Receives the seed, owned by the caller, when the function returns <see langword="true"/>.</param>
/// <param name="additionalSecretData">Receives the additional secret data, owned by the caller, when the function returns <see langword="true"/>.</param>
/// <returns><see langword="true"/> when the bytes are a well-formed payload.</returns>
public delegate bool SeedPayloadDecodeDelegate(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out ProofSeed? seed, out AdditionalData? additionalSecretData);


/// <summary>
/// Decodes the transport layout of an ECIES ciphertext. The parameter set fixes the tag length and is known to
/// the receiver from its configuration.
/// </summary>
/// <param name="encoded">The bytes to decode.</param>
/// <param name="parameters">The ECIES parameter set the ciphertext was made under.</param>
/// <param name="pool">The pool the decoded value is rented from.</param>
/// <param name="ciphertext">Receives the ciphertext, owned by the caller, when the function returns <see langword="true"/>.</param>
/// <returns><see langword="true"/> when the bytes are a well-formed encoding.</returns>
public delegate bool CiphertextDecodeDelegate(ReadOnlySpan<byte> encoded, EciesParameterSet parameters, BaseMemoryPool pool, out EciesCiphertext? ciphertext);


/// <summary>
/// A layout profile: a named set of encoder and decoder delegates that decide, in one place, every byte layout the
/// transferable proof needs. The paper leaves the "byte representation of the structure" that is hashed and signed
/// (<c>E ‖ Ḡ ‖ D̄ ‖ H2 ‖ AAD</c>, the response scope, the list of ephemeral keys, the index <c>[i]</c>, the derivation
/// input) and the container layouts of the typed values unspecified, and the choice is a deployment decision: a
/// deployment may need DER, CBOR or a fixed binary profile, and may use several at once.
/// </summary>
/// <remarks>
/// <para>
/// <b>The algorithms never concatenate fields.</b> Every place where several values become bytes goes through a
/// profile encoder, so a new profile touches no algorithm code. The typed values are canonical; converting between
/// two layouts is decoding with one profile and encoding with another, and is lossless.
/// </para>
/// <para>
/// <b>Recorded profile.</b> A value that was hashed or signed under a profile carries the profile's
/// <see cref="Id"/> in its tag. A verifier rebuilds the exact signed bytes from the typed value and the recorded
/// profile, even if the value arrived in another transport layout; a challenge and a response that disagree on
/// the profile are rejected. Container encoders must therefore carry the identifier so that a decoded value
/// regains it.
/// </para>
/// <para>
/// <b>Injectivity is the profile's duty.</b> The structures are signed, so an encoder must be injective: two
/// different typed values must never encode to the same bytes, and the three signed and derived structures
/// must be told apart (for example by a leading discriminator), or a signature on one could be replayed as a
/// signature on another. A profile that is not injective is a vulnerability, not a style choice.
/// </para>
/// <para>
/// <b>Secrets.</b> The scalar-vector, derivation-input and seed-payload encoders see secret values; the writer
/// they append to clears its buffer when disposed.
/// </para>
/// </remarks>
public sealed class SecdsaLayoutProfile
{
    /// <summary>The identifier recorded in the tag of every value hashed or signed under this profile.</summary>
    public required SecdsaLayoutProfileId Id { get; init; }

    /// <summary>Encodes a point vector, such as <c>Ḡ</c> or <c>D̄</c>.</summary>
    public required LayoutEncodeDelegate<P256PointVector> EncodePointVector { get; init; }

    /// <summary>Decodes a point vector.</summary>
    public required LayoutDecodeDelegate<P256PointVector> DecodePointVector { get; init; }

    /// <summary>Encodes the list of ephemeral private keys <c>e₀ ‖ … ‖ eₙ</c> that <c>H1</c> hashes.</summary>
    public required LayoutEncodeDelegate<P256ScalarVector> EncodeScalarVector { get; init; }

    /// <summary>Decodes a scalar vector.</summary>
    public required LayoutDecodeDelegate<P256ScalarVector> DecodeScalarVector { get; init; }

    /// <summary>Encodes the derivation byte array <c>D</c> of one ephemeral key.</summary>
    public required DerivationInputEncodeDelegate EncodeDerivationInput { get; init; }

    /// <summary>Encodes the structure the challenger signs.</summary>
    public required ChallengeScopeEncodeDelegate EncodeChallengeScope { get; init; }

    /// <summary>Encodes the structure the prover signs.</summary>
    public required ResponseScopeEncodeDelegate EncodeResponseScope { get; init; }

    /// <summary>Encodes the ECIES plaintext <c>Seed ‖ ASD</c>.</summary>
    public required SeedPayloadEncodeDelegate EncodeSeedPayload { get; init; }

    /// <summary>Decodes the ECIES plaintext <c>Seed ‖ ASD</c>.</summary>
    public required SeedPayloadDecodeDelegate DecodeSeedPayload { get; init; }

    /// <summary>Encodes an ECIES ciphertext for transport.</summary>
    public required LayoutEncodeDelegate<EciesCiphertext> EncodeCiphertext { get; init; }

    /// <summary>Decodes an ECIES ciphertext from transport.</summary>
    public required CiphertextDecodeDelegate DecodeCiphertext { get; init; }

    /// <summary>Encodes a challenge for transport, carrying the profile identifier.</summary>
    public required LayoutEncodeDelegate<TransferableChallenge> EncodeChallenge { get; init; }

    /// <summary>Decodes a challenge from transport, restoring the profile identifier in its tag.</summary>
    public required LayoutDecodeDelegate<TransferableChallenge> DecodeChallenge { get; init; }

    /// <summary>Encodes a response for transport, carrying the profile identifier.</summary>
    public required LayoutEncodeDelegate<TransferableResponse> EncodeResponse { get; init; }

    /// <summary>Decodes a response from transport, restoring the profile identifier in its tag.</summary>
    public required LayoutDecodeDelegate<TransferableResponse> DecodeResponse { get; init; }
}
