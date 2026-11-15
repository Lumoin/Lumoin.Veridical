using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using System;
using System.Security.Cryptography;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// ECDH-MAC device binding over NIST P-256, per Verheul's construction for an HSM-based EUDI wallet: instead of a
/// signature, the prover authenticates a message to one specific verifier by deriving a shared MAC key from an
/// ephemeral Diffie-Hellman exchange with that verifier's own ephemeral key. Split-ECDH-MAC (SECDH-MAC) composes
/// the same primitive from three key-share scalars — a wallet share, a WSCA share, and an HSM base key — none of
/// which ever combines into the full private scalar; the Diffie-Hellman associativity that makes this work is
/// exactly the composite-key identity split ECDSA relies on.
/// </summary>
/// <remarks>
/// <para>
/// <b>ISO/IEC 18013-5 §9.1.3.5 <c>EMacKey</c> mapping.</b> This class implements the cryptographic primitive
/// only; the ISO device-binding wiring — <c>salt = SHA-256(SessionTranscriptBytes)</c>, <c>info = "EMacKey"</c>,
/// <c>L = 32</c> — is a call-site concern the consumer supplies as the <c>salt</c> and <c>sharedInfo</c>
/// parameters below. The paper's plain form <c>K = HKDF(Z_AB, SharedInfo)</c> carries no salt; passing an empty
/// <c>salt</c> reproduces that plain form (HKDF's own empty-salt default applies).
/// </para>
/// <para>
/// <b>Phases.</b> When the private scalar lives in an HSM, a TPM, or a cloud KMS, the agreement is split into
/// pure phases around the external call. <see cref="PrepareKeyAgreement"/> validates the verifier's point and
/// yields the value for the key holder; the key holder returns either the shared secret <c>Z_AB</c>, completed
/// with <see cref="CompleteSign"/> or <see cref="CompleteVerify"/>, or the derived key <c>K</c> itself, completed
/// with the injected HMAC (signing) or <see cref="VerifyMac"/> (verification). The three-party split of
/// Algorithm 12 adds <see cref="ApplyKeyShare"/> for the wallet and WSCA steps. No phase keeps state.
/// </para>
/// <para>
/// <b>Which key derivation.</b> Algorithms 16 and 17 derive <c>K = HKDF(Z_AB, SharedInfo)</c>. Algorithm 12
/// leaves the derivation to the HSM and the accompanying text names the PKCS#11 mechanism
/// <c>CKM_ECDH1_DERIVE</c> with <c>CKD_SHA256_KDF</c>, an ANSI X9.63 KDF, which yields a different <c>K</c> than
/// HKDF for the same <c>Z_AB</c>. The library therefore takes the derivation as a named
/// <see cref="EcdhMacKeyDerivationDelegate"/> and never assumes one: a MAC verifies only if the verifier binds
/// the same derivation the key holder used. All-software signing and verification here bind HKDF-SHA256 at the
/// call site, as Algorithms 16 and 17 specify.
/// </para>
/// <para>
/// <b>Plausible deniability.</b> Unlike a signature, an ECDH-MAC authenticator is not non-repudiating: the
/// verifier holds the same shared key <c>K</c> the prover derived (both sides of a Diffie-Hellman exchange reach
/// the same <c>S_AB</c>), so the verifier could itself have forged a <c>MAC</c>-shaped output. This is
/// a deliberate design property of the primitive, not a defect — it is the reason ECDH-MAC, rather than a
/// signature, is used for device-presentation binding where the prover should not be able to prove to a third
/// party which verifier it presented to.
/// </para>
/// <para>
/// <b>Delegate-injected arithmetic.</b> Every scalar-field group operation, HKDF derivation, and HMAC computation
/// is supplied by the caller as a named delegate, so the package carries no concrete field/group/hash backend.
/// The choice of implementation — a BigInteger group reference, or a constant-time backend — is
/// entirely a call-site concern; this algorithm is byte-for-byte stable across either.
/// </para>
/// <para>
/// <b>Timing-hardening status.</b> The in-package secret-scalar checks — the <c>[1, n−1]</c> range validation on
/// each key/key-share — are <i>branchless</i>: they inspect every byte with no data-dependent early exit, so
/// they do not leak by an early return where a key and the order first differ. This is best-effort in managed
/// code, not a hard constant-time guarantee, and it is the cheap part: the dominant variable-time cost is the
/// <i>injected</i> group arithmetic (a BigInteger reference, or a constant-time scalar/group backend, entirely a
/// call-site choice), so genuine constant-time operation requires a constant-time backend, which this algorithm
/// is byte-for-byte stable across. Key-derived scratch (the shared point, the intermediate blinded points, the
/// MAC key) is cleared before return.
/// </para>
/// </remarks>
public static class EcdhMacAlgorithm
{
    /// <summary>The P-256 scalar octet length (a private key, a key share).</summary>
    public const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The P-256 SEC1 compressed point length (a public key, an ephemeral key).</summary>
    public const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    /// <summary>The length of the shared secret <c>Z_AB</c>, the P-256 x-coordinate of the Diffie-Hellman point.</summary>
    public const int SharedSecretSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    //The low byte of the scalar one, used to decode-validate a point by multiplying it by one.
    private const byte ScalarOneLowByte = 0x01;

    /// <summary>The HMAC-SHA256 output length: <c>MAC = HMAC(K, M)</c> is always 32 bytes.</summary>
    public const int MacSizeBytes = 32;

    /// <summary>
    /// The HKDF output length used to derive the MAC key <c>K</c> — the paper leaves this (RFC 5869's <c>L</c>)
    /// implicit; 32 bytes is the natural choice for an HMAC-SHA256 key. <see cref="DeriveMacKey"/> accepts any
    /// destination length; this constant is what <see cref="Sign"/>, <see cref="Verify"/>, and
    /// <see cref="SplitSign"/> use internally.
    /// </summary>
    public const int MacKeySizeBytes = 32;

    /// <summary>
    /// The NIST P-256 curve every group operation in this algorithm dispatches
    /// against.
    /// </summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;


    /// <summary>
    /// Derives the ECDH-MAC key <c>K</c> from an elliptic-curve Diffie-Hellman exchange between
    /// <paramref name="privateKey"/> and <paramref name="peerPublicPoint"/> — Algorithm 16 steps 1–4 (equally,
    /// realized against the composed key at the HSM, Algorithm 12 steps 6–8): this is the software equivalent of
    /// a PKCS#11 <c>CKM_ECDH1_DERIVE</c> mechanism followed by HKDF.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>E ∈ ⟨G⟩</c> (Algorithm 16 step 1).</b> Canonical SEC1 compressed decoding structurally prevents
    /// invalid-curve points: an <c>x</c>-coordinate for which <c>x³ − 3x + b</c> is not a quadratic residue has
    /// no corresponding point and the injected <paramref name="g1ScalarMultiply"/> backend throws decoding it.
    /// P-256 has cofactor 1, so on-curve and finite together already imply membership in the prime-order
    /// subgroup <c>⟨G⟩</c>. What this method checks explicitly is therefore the length of
    /// <paramref name="peerPublicPoint"/> and rejection of the encoded point at infinity; on-curve validation is
    /// the backend's decode contract, invoked when <paramref name="g1ScalarMultiply"/> runs.
    /// </para>
    /// <para>
    /// <c>Z_AB</c> is the shared point's <c>x</c>-coordinate — the compressed encoding's trailing 32 bytes,
    /// following this codebase's established x-coordinate-slice idiom.
    /// </para>
    /// </remarks>
    /// <param name="privateKey">The local private scalar, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="peerPublicPoint">The peer's public point <c>E</c>, SEC1 compressed (33 bytes); rejected if it encodes the point at infinity.</param>
    /// <param name="salt">The HKDF extraction salt; empty selects the paper's plain <c>K = HKDF(Z_AB, SharedInfo)</c> form (RFC 5869's default salt).</param>
    /// <param name="sharedInfo">
    /// The HKDF context/application information (<c>SharedInfo</c>); may be empty. The injected
    /// <paramref name="keyDerivation"/> implementation may bound its length (the library's <c>Sha256Hkdf</c> caps
    /// <c>info</c> at 1024 bytes) — a rejection surfaces as the delegate's own <see cref="ArgumentException"/>.
    /// </param>
    /// <param name="keyDerivation">The key-derivation delegate that turns <c>Z_AB</c> and <c>SharedInfo</c> into <c>K</c>: HKDF-SHA256 for Algorithms 16 and 17, see <see cref="EcdhMacKeyDerivationDelegate"/>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for the Diffie-Hellman product).</param>
    /// <param name="macKey">Receives the derived MAC key <c>K</c>; at least 1 byte (the delegate enforces HKDF's own upper bound).</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When a span has the wrong length, <paramref name="privateKey"/> is outside <c>[1, n−1]</c>,
    /// <paramref name="peerPublicPoint"/> encodes the point at infinity, or <paramref name="macKey"/> is empty.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// When <paramref name="peerPublicPoint"/> is not on the curve (the backend's decode contract), or the
    /// Diffie-Hellman product is degenerate (the point at infinity; impossible for valid inputs since <c>n</c>
    /// is prime, but checked defensively).
    /// </exception>
    public static void DeriveMacKey(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> peerPublicPoint,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        EcdhMacKeyDerivationDelegate keyDerivation,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> macKey)
    {
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(privateKey, ScalarSizeBytes, nameof(privateKey));
        RequireScalarInRange(privateKey, nameof(privateKey));
        if(macKey.Length < 1)
        {
            throw new ArgumentException("The MAC key destination must be at least 1 byte.", nameof(macKey));
        }

        //S_AB = privateKey·peerPoint is THE Diffie-Hellman secret; cleared in a finally so a throw mid-derivation
        //(a malformed HKDF call, an infinity result) cannot leave it on the stack.
        Span<byte> sharedPoint = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            ComputeSharedDiffieHellmanPoint(privateKey, peerPublicPoint, g1ScalarMultiply, sharedPoint);

            //Z_AB = the shared point's x-coordinate; K = KDF(Z_AB, SharedInfo) with the caller's salt.
            DeriveMacKeyFromSharedSecret(salt, sharedPoint[1..], sharedInfo, keyDerivation, macKey);
        }
        finally
        {
            sharedPoint.Clear();
        }
    }


    /// <summary>
    /// SECDSA Algorithm 16 (ECDH-MAC signature generation): authenticates <paramref name="message"/> to the
    /// holder of <paramref name="verifierEphemeralPublicKey"/> by deriving a shared MAC key with
    /// <see cref="DeriveMacKey"/> and computing <c>MAC = HMAC(K, M)</c>.
    /// </summary>
    /// <remarks>
    /// <paramref name="verifierEphemeralPublicKey"/> arrives from the counterparty, so a malformed value here is
    /// a live protocol condition, not only a programming error: per Algorithm 16 step 1 ("on error algorithm
    /// stops") this method throws, and a caller in a presentation flow should treat that throw as its rejection
    /// of the verifier's request.
    /// </remarks>
    /// <param name="privateKey">The prover's private key <c>d</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="verifierEphemeralPublicKey">The verifier's ephemeral public key <c>E = e·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="salt">The HKDF extraction salt; empty selects the paper's plain form.</param>
    /// <param name="sharedInfo">The HKDF context/application information (<c>SharedInfo</c>); may be empty.</param>
    /// <param name="message">The message <c>M</c> to authenticate; any length.</param>
    /// <param name="keyDerivation">The key-derivation delegate that turns <c>Z_AB</c> and <c>SharedInfo</c> into <c>K</c>: HKDF-SHA256 for Algorithms 16 and 17, see <see cref="EcdhMacKeyDerivationDelegate"/>.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for the Diffie-Hellman product).</param>
    /// <param name="mac">Receives the 32-byte MAC.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When a span has the wrong length, <paramref name="privateKey"/> is outside <c>[1, n−1]</c>, or
    /// <paramref name="verifierEphemeralPublicKey"/> encodes the point at infinity.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// When <paramref name="verifierEphemeralPublicKey"/> is not on the curve, or the Diffie-Hellman product is
    /// degenerate (see <see cref="DeriveMacKey"/>).
    /// </exception>
    public static void Sign(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> verifierEphemeralPublicKey,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> mac)
    {
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(hmac);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(privateKey, ScalarSizeBytes, nameof(privateKey));
        RequireScalarInRange(privateKey, nameof(privateKey));
        RequireLength(mac, MacSizeBytes, nameof(mac));

        //S_AB is THE Diffie-Hellman secret; cleared in a finally so a throw cannot leave it on the stack.
        Span<byte> sharedPoint = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            ComputeSharedDiffieHellmanPoint(privateKey, verifierEphemeralPublicKey, g1ScalarMultiply, sharedPoint);
            CompleteSign(salt, sharedPoint[1..], sharedInfo, message, keyDerivation, hmac, mac);
        }
        finally
        {
            sharedPoint.Clear();
        }
    }


    /// <summary>
    /// SECDSA Algorithm 17 (ECDH-MAC verification): accepts iff <paramref name="mac"/> equals the MAC recomputed
    /// from the verifier's own ephemeral private key <paramref name="verifierEphemeralPrivateKey"/> and the
    /// prover's public key <paramref name="proverPublicKey"/>. Relies on Diffie-Hellman symmetry
    /// <c>e·D = d·E</c> for <c>D = d·G</c>, <c>E = e·G</c>: this is exactly <see cref="DeriveMacKey"/> with the
    /// two sides' roles exchanged, so no separate group-arithmetic path exists for verification.
    /// </summary>
    /// <remarks>
    /// <paramref name="verifierEphemeralPrivateKey"/>, <paramref name="salt"/>, and
    /// <paramref name="sharedInfo"/> are the verifier's own material: a malformed or out-of-range value throws
    /// (including a <paramref name="salt"/>/<paramref name="sharedInfo"/> the injected <paramref name="keyDerivation"/>
    /// implementation rejects), since that is a caller configuration error a rejection must not mask. By
    /// contrast <paramref name="proverPublicKey"/> and <paramref name="mac"/> arrive from the (possibly
    /// adversarial) prover side of the exchange: a malformed point, an off-curve point, the point at infinity,
    /// or a wrong-length MAC all make this method return <see langword="false"/> rather than throw.
    /// </remarks>
    /// <param name="proverPublicKey">The prover's public key <c>D = d·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="verifierEphemeralPrivateKey">The verifier's own ephemeral private key <c>e</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="salt">The HKDF extraction salt; must match the value <see cref="Sign"/> used.</param>
    /// <param name="sharedInfo">The HKDF context/application information; must match the value <see cref="Sign"/> used.</param>
    /// <param name="message">The message <c>M</c> the MAC is claimed to authenticate.</param>
    /// <param name="mac">The claimed 32-byte MAC.</param>
    /// <param name="keyDerivation">The key-derivation delegate that turns <c>Z_AB</c> and <c>SharedInfo</c> into <c>K</c>: HKDF-SHA256 for Algorithms 16 and 17, see <see cref="EcdhMacKeyDerivationDelegate"/>.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for the Diffie-Hellman product).</param>
    /// <returns><see langword="true"/> iff the MAC is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="verifierEphemeralPrivateKey"/> has the wrong length or lies outside <c>[1, n−1]</c>,
    /// or the injected <paramref name="keyDerivation"/> rejects the caller's <paramref name="salt"/> or
    /// <paramref name="sharedInfo"/> (an implementation-bounded length, for example).
    /// </exception>
    public static bool Verify(
        ReadOnlySpan<byte> proverPublicKey,
        ReadOnlySpan<byte> verifierEphemeralPrivateKey,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> mac,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply)
    {
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(hmac);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(verifierEphemeralPrivateKey, ScalarSizeBytes, nameof(verifierEphemeralPrivateKey));
        RequireScalarInRange(verifierEphemeralPrivateKey, nameof(verifierEphemeralPrivateKey));

        if(mac.Length != MacSizeBytes)
        {
            return false;
        }

        Span<byte> sharedPoint = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            //Only the point-dependent step can be failed by the (possibly adversarial) prover: a wrong-length,
            //infinity, or off-curve proverPublicKey rejects as false here. The rejected-not-thrown handling is
            //scoped to exactly this call so a failure in the injected key derivation and hmac — which concerns the verifier's
            //OWN salt/sharedInfo/destination, e.g. an implementation-bounded info length — propagates as the
            //caller error it is instead of masquerading as an invalid MAC (the posture DlEqualityNizk.Verify
            //takes with its transcript-size cap).
            try
            {
                ComputeSharedDiffieHellmanPoint(verifierEphemeralPrivateKey, proverPublicKey, g1ScalarMultiply, sharedPoint);
            }
            catch(InvalidOperationException)
            {
                return false;
            }
            catch(ArgumentException)
            {
                return false;
            }

            //Z_AB = the shared point's x-coordinate; K = KDF(Z_AB, SharedInfo); MAC' = HMAC(K, M).
            return CompleteVerify(salt, sharedPoint[1..], sharedInfo, message, mac, keyDerivation, hmac);
        }
        finally
        {
            sharedPoint.Clear();
        }
    }


    /// <summary>
    /// SECDSA Algorithm 12 (Split-ECDH-MAC, SECDH-MAC): an all-software realization of the three-party MAC split
    /// across a wallet share <paramref name="walletKeyShare"/> (<c>zU</c>), a WSCA share
    /// <paramref name="wscaKeyShare"/> (<c>zW</c>), and an HSM base key <paramref name="baseKey"/> (<c>bU</c>) —
    /// analogous to how <see cref="SecdsaAlgorithm"/>'s <c>SplitSign</c> realizes Algorithm 2/11 with both
    /// factors as injected scalars. A real deployment splits the three group
    /// operations below across the three parties (wallet, WSCA, HSM) so no single party ever learns the
    /// composite scalar <c>p = zU·zW·bU</c>; this method performs all three multiplications in one process for
    /// callers that hold all three shares (tests, a single-process reference flow). It composes the same phases
    /// the parties run separately: <see cref="ApplyKeyShare"/> at the wallet (step 2) and at the WSCA (step 4),
    /// then the HSM's agreement and key derivation (steps 6–8) and the wallet's MAC (step 11) through
    /// <see cref="Sign"/> under the base key. A deployment whose parties are separate also runs
    /// <see cref="PrepareKeyAgreement"/> at the wallet (step 1) and at each party that receives a point.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Correctness.</b> Scalar multiplication over a group is associative and commutative in its scalar
    /// factor: <c>bU·(zW·(zU·E)) = (zU·zW·bU)·E</c>. So the MAC this method produces is identical to
    /// <see cref="Sign"/> under the composite private key <c>p = zU·zW·bU mod n</c>, and verifies with plain
    /// <see cref="Verify"/> against the composite public key <c>P = p·G</c> — nothing about verification is
    /// split-specific.
    /// </para>
    /// <para>
    /// <b><c>E ∈ ⟨G⟩</c> (Algorithm 12 step 1).</b> Checked once, up front, against the caller-supplied
    /// <paramref name="verifierEphemeralPublicKey"/> — see <see cref="DeriveMacKey"/>'s remarks for how the SEC1
    /// decode contract and P-256's cofactor of 1 together establish subgroup membership. On error, per the
    /// paper, the algorithm stops: this method throws rather than returning a sentinel. Since <c>E</c> arrives
    /// from the counterparty, a caller in a presentation flow should treat that throw as its rejection of the
    /// verifier's request, not only as a programming error.
    /// </para>
    /// <para>
    /// <b>Intermediate infinity.</b> Because <c>n</c> is prime, a nonzero scalar share cannot annihilate a point
    /// already known to lie in the prime-order subgroup <c>⟨G⟩</c> — so <c>E′ = zU·E</c> and
    /// <c>E″ = zW·E′</c> cannot be the point at infinity for valid (in-range, nonzero) shares and a valid
    /// <c>E</c>. The defensive checks after each multiplication below exist anyway, matching
    /// <see cref="DeriveMacKey"/>'s own defensive check on the final Diffie-Hellman product.
    /// </para>
    /// </remarks>
    /// <param name="walletKeyShare">The wallet's key-share scalar <c>zU</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="wscaKeyShare">The WSCA's key-share scalar <c>zW</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="baseKey">The HSM's base-key scalar <c>bU</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="verifierEphemeralPublicKey">The verifier's ephemeral public key <c>E = e·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="salt">The HKDF extraction salt; empty selects the paper's plain form.</param>
    /// <param name="sharedInfo">The HKDF context/application information (<c>SharedInfo</c>); may be empty.</param>
    /// <param name="message">The message <c>M</c> to authenticate; any length.</param>
    /// <param name="keyDerivation">The key-derivation delegate that turns <c>Z_AB</c> and <c>SharedInfo</c> into <c>K</c>: HKDF-SHA256 for Algorithms 16 and 17, see <see cref="EcdhMacKeyDerivationDelegate"/>.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication, invoked three times: <c>E′ = zU·E</c>, <c>E″ = zW·E′</c>, and <c>S_AB = bU·E″</c>.</param>
    /// <param name="mac">Receives the 32-byte MAC.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When a span has the wrong length, a key share is outside <c>[1, n−1]</c>, or
    /// <paramref name="verifierEphemeralPublicKey"/> encodes the point at infinity.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// When <paramref name="verifierEphemeralPublicKey"/> is not on the curve, or an intermediate/final
    /// Diffie-Hellman product is degenerate (the point at infinity; impossible for valid inputs, checked
    /// defensively).
    /// </exception>
    public static void SplitSign(
        ReadOnlySpan<byte> walletKeyShare,
        ReadOnlySpan<byte> wscaKeyShare,
        ReadOnlySpan<byte> baseKey,
        ReadOnlySpan<byte> verifierEphemeralPublicKey,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> mac)
    {
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(hmac);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(walletKeyShare, ScalarSizeBytes, nameof(walletKeyShare));
        RequireLength(wscaKeyShare, ScalarSizeBytes, nameof(wscaKeyShare));
        RequireLength(baseKey, ScalarSizeBytes, nameof(baseKey));
        RequireLength(verifierEphemeralPublicKey, CompressedPointSizeBytes, nameof(verifierEphemeralPublicKey));
        RequireLength(mac, MacSizeBytes, nameof(mac));
        RequireScalarInRange(walletKeyShare, nameof(walletKeyShare));
        RequireScalarInRange(wscaKeyShare, nameof(wscaKeyShare));
        RequireScalarInRange(baseKey, nameof(baseKey));
        RequireNotInfinity(verifierEphemeralPublicKey, nameof(verifierEphemeralPublicKey));

        //E' and E'' are share-blinded intermediate points; both are cleared in a finally so a throw partway
        //through the three-party chain cannot leave them on the stack.
        Span<byte> walletBlindedPoint = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> wscaBlindedPoint = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            //E' = zU·E (wallet), E'' = zW·E' (WSCA), then S_AB = bU·E'' (HSM), K, and the MAC.
            ApplyKeyShare(walletKeyShare, verifierEphemeralPublicKey, g1ScalarMultiply, walletBlindedPoint);
            ApplyKeyShare(wscaKeyShare, walletBlindedPoint, g1ScalarMultiply, wscaBlindedPoint);
            Sign(baseKey, wscaBlindedPoint, salt, sharedInfo, message, keyDerivation, hmac, g1ScalarMultiply, mac);
        }
        finally
        {
            walletBlindedPoint.Clear();
            wscaBlindedPoint.Clear();
        }
    }


    /// <summary>
    /// ECDH-MAC phase one (Algorithm 16 step 1, Algorithm 12 step 1), run by the party that will ask a key
    /// holder to perform the Diffie-Hellman agreement: validates the verifier's ephemeral public point
    /// <paramref name="peerPublicPoint"/> and writes the validated canonical encoding to
    /// <paramref name="keyHolderInput"/>, the value to send to the key holder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Checks.</b> The length must be 33 bytes, the encoding must not be the point at infinity, and the point
    /// must lie on the curve. Because P-256 has cofactor 1, on-curve and finite together are equivalent to
    /// <c>E ∈ ⟨G⟩</c>. On-curve membership is established through the injected
    /// <paramref name="g1ScalarMultiply"/>'s SEC1 decode contract: the point is multiplied by one, which
    /// decodes it (an off-curve point throws), and the re-encoded result must equal the input, so a
    /// non-canonical encoding is rejected rather than silently normalized. An HSM or TPM performing the
    /// agreement validates the point again on its side; this check protects the caller before anything leaves
    /// the process.
    /// </para>
    /// <para>
    /// <b>Boundary.</b> <paramref name="keyHolderInput"/> is public (it came from the counterparty) and is the
    /// only input the key holder needs for a raw ECDH that returns <c>Z_AB</c> (for example a TPM
    /// <c>ECDH_ZGen</c>) or for a derivation that returns <c>K</c> (for example PKCS#11
    /// <c>CKM_ECDH1_DERIVE</c>). Nothing secret is involved. The point arrives from a possibly adversarial
    /// counterparty, so a throw here is a rejection of the verifier's request, per "on error algorithm stops".
    /// </para>
    /// </remarks>
    /// <param name="peerPublicPoint">The verifier's ephemeral public key <c>E = e·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication, whose decode contract rejects off-curve points.</param>
    /// <param name="keyHolderInput">Receives the validated canonical 33-byte encoding of <c>E</c>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="g1ScalarMultiply"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, <paramref name="peerPublicPoint"/> encodes the point at infinity, or it is not the canonical encoding of its point.</exception>
    /// <exception cref="InvalidOperationException">When <paramref name="peerPublicPoint"/> is not on the curve (the backend's decode contract).</exception>
    public static void PrepareKeyAgreement(
        ReadOnlySpan<byte> peerPublicPoint,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> keyHolderInput)
    {
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(peerPublicPoint, CompressedPointSizeBytes, nameof(peerPublicPoint));
        RequireLength(keyHolderInput, CompressedPointSizeBytes, nameof(keyHolderInput));
        RequireNotInfinity(peerPublicPoint, nameof(peerPublicPoint));

        Span<byte> one = stackalloc byte[ScalarSizeBytes];
        one[^1] = ScalarOneLowByte;
        Span<byte> decoded = stackalloc byte[CompressedPointSizeBytes];
        g1ScalarMultiply(peerPublicPoint, one, decoded, Curve);
        if(decoded[0] == 0x00 || !CryptographicOperations.FixedTimeEquals(decoded, peerPublicPoint))
        {
            throw new ArgumentException("The point is not the canonical encoding of a finite point on the curve.", nameof(peerPublicPoint));
        }

        decoded.CopyTo(keyHolderInput);
    }


    /// <summary>
    /// Multiplies a point by a key-share scalar: <c>E′ = zU·E</c> at the wallet (Algorithm 12 step 2) and
    /// <c>E″ = zW·E′</c> at the WSCA (step 4) are this same primitive, each run by the party that holds the
    /// share. The point at infinity is rejected on input and on output.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Boundary.</b> <paramref name="keyShare"/> is secret and never leaves the party that holds it. The
    /// output is a share-blinded point; it is sent to the next party (the WSCA, then the HSM) and, since
    /// the next party also holds a secret factor, it reveals nothing about <paramref name="keyShare"/> beyond
    /// what the Diffie-Hellman assumption already hides. The input point must first have been validated by
    /// <see cref="PrepareKeyAgreement"/> at the first party; each later party should validate what it received
    /// by calling that method before this one, because a blinded point from an untrusted party is peer input.
    /// </para>
    /// <para>
    /// <b>Infinity.</b> Because <c>n</c> is prime, a nonzero in-range share cannot annihilate a point of the
    /// prime-order group, so the output check never fires for valid inputs; it is a defensive check that stops
    /// a degenerate chain from reaching the key holder.
    /// </para>
    /// </remarks>
    /// <param name="keyShare">The key-share scalar, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="point">The point to multiply, SEC1 compressed (33 bytes); rejected if it encodes the point at infinity.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="result">Receives the 33-byte SEC1 compressed product; cleared when the call throws.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="g1ScalarMultiply"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, <paramref name="keyShare"/> is outside <c>[1, n−1]</c>, or <paramref name="point"/> encodes the point at infinity.</exception>
    /// <exception cref="InvalidOperationException">When <paramref name="point"/> is not on the curve, or the product is the point at infinity.</exception>
    public static void ApplyKeyShare(
        ReadOnlySpan<byte> keyShare,
        ReadOnlySpan<byte> point,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> result)
    {
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(keyShare, ScalarSizeBytes, nameof(keyShare));
        RequireLength(point, CompressedPointSizeBytes, nameof(point));
        RequireLength(result, CompressedPointSizeBytes, nameof(result));
        RequireScalarInRange(keyShare, nameof(keyShare));
        RequireNotInfinity(point, nameof(point));

        g1ScalarMultiply(point, keyShare, result, Curve);
        if(result[0] == 0x00)
        {
            result.Clear();

            throw new InvalidOperationException("The key-share product is the point at infinity; the key share or the input point is degenerate.");
        }
    }


    /// <summary>
    /// ECDH-MAC derivation from a key holder's shared secret (Algorithm 16 steps 3–4, Algorithm 17 steps 2–3):
    /// derives <c>K = KDF(Z_AB, SharedInfo)</c> from the 32-byte x-coordinate <c>Z_AB</c> that a key holder's
    /// raw ECDH returned.
    /// </summary>
    /// <remarks>
    /// <paramref name="sharedSecret"/> and <paramref name="macKey"/> are secret; the caller clears both. The
    /// key holder is trusted with the private scalar, so an incorrect <c>Z_AB</c> cannot be detected here: it
    /// yields a wrong <c>K</c>, which a verifier rejects as an invalid MAC. The KDF is the caller's choice and
    /// must match the verifier's, see <see cref="EcdhMacKeyDerivationDelegate"/>.
    /// </remarks>
    /// <param name="salt">The KDF salt; empty selects the paper's plain form.</param>
    /// <param name="sharedSecret">The shared secret <c>Z_AB</c>, 32 bytes.</param>
    /// <param name="sharedInfo">The context/application information (<c>SharedInfo</c>); may be empty.</param>
    /// <param name="keyDerivation">The key-derivation delegate.</param>
    /// <param name="macKey">Receives the derived MAC key <c>K</c>; at least 1 byte.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="keyDerivation"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="sharedSecret"/> is not 32 bytes or <paramref name="macKey"/> is empty.</exception>
    public static void DeriveMacKeyFromSharedSecret(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> sharedInfo,
        EcdhMacKeyDerivationDelegate keyDerivation,
        Span<byte> macKey)
    {
        ArgumentNullException.ThrowIfNull(keyDerivation);
        RequireLength(sharedSecret, SharedSecretSizeBytes, nameof(sharedSecret));
        if(macKey.Length < 1)
        {
            throw new ArgumentException("The MAC key destination must be at least 1 byte.", nameof(macKey));
        }

        keyDerivation(salt, sharedSecret, sharedInfo, macKey);
    }


    /// <summary>
    /// ECDH-MAC phase two for signing from a shared secret (Algorithm 16 steps 4–5): derives
    /// <c>K = KDF(Z_AB, SharedInfo)</c> from the <c>Z_AB</c> a key holder's raw ECDH returned and computes
    /// <c>MAC = HMAC(K, M)</c>. The derived key is cleared before return.
    /// </summary>
    /// <remarks>
    /// <paramref name="sharedSecret"/> is secret and stays with the caller; <paramref name="mac"/> is the
    /// value sent to the verifier. When the key holder derives <c>K</c> itself and returns it, no library step
    /// is needed beyond the injected HMAC: <c>hmac(K, M, mac)</c> is the whole phase. Use
    /// <see cref="VerifyMac"/> for the matching verification with a key-holder-derived key.
    /// </remarks>
    /// <param name="salt">The KDF salt; empty selects the paper's plain form.</param>
    /// <param name="sharedSecret">The shared secret <c>Z_AB</c>, 32 bytes.</param>
    /// <param name="sharedInfo">The context/application information (<c>SharedInfo</c>); may be empty.</param>
    /// <param name="message">The message <c>M</c> to authenticate; any length.</param>
    /// <param name="keyDerivation">The key-derivation delegate.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <param name="mac">Receives the 32-byte MAC.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    public static void CompleteSign(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        Span<byte> mac)
    {
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(hmac);
        RequireLength(mac, MacSizeBytes, nameof(mac));

        //The MAC key K is key-derived material; cleared in a finally so a throwing delegate cannot leave it on
        //the stack.
        Span<byte> macKey = stackalloc byte[MacKeySizeBytes];
        try
        {
            DeriveMacKeyFromSharedSecret(salt, sharedSecret, sharedInfo, keyDerivation, macKey);
            hmac(macKey, message, mac);
        }
        finally
        {
            macKey.Clear();
        }
    }


    /// <summary>
    /// ECDH-MAC phase two for verification from a shared secret (Algorithm 17 steps 3–5): derives
    /// <c>K = KDF(Z_AB, SharedInfo)</c> from the <c>Z_AB</c> the verifier's key holder returned, recomputes
    /// <c>MAC′ = HMAC(K, M)</c>, and compares it with <paramref name="mac"/> in constant time.
    /// </summary>
    /// <remarks>
    /// <paramref name="mac"/> arrives from the (possibly adversarial) prover, so a wrong-length MAC returns
    /// <see langword="false"/> rather than throwing. The salt, shared info, and shared secret are the verifier's
    /// own material: a failure in the injected delegates propagates as the caller error it is. The key is
    /// cleared before return.
    /// </remarks>
    /// <param name="salt">The KDF salt; must match the signer's.</param>
    /// <param name="sharedSecret">The shared secret <c>Z_AB</c>, 32 bytes.</param>
    /// <param name="sharedInfo">The context/application information; must match the signer's.</param>
    /// <param name="message">The message <c>M</c> the MAC is claimed to authenticate.</param>
    /// <param name="mac">The claimed 32-byte MAC.</param>
    /// <param name="keyDerivation">The key-derivation delegate.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <returns><see langword="true"/> iff the MAC is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="sharedSecret"/> is not 32 bytes.</exception>
    public static bool CompleteVerify(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> mac,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac)
    {
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(hmac);
        RequireLength(sharedSecret, SharedSecretSizeBytes, nameof(sharedSecret));

        if(mac.Length != MacSizeBytes)
        {
            return false;
        }

        Span<byte> macKey = stackalloc byte[MacKeySizeBytes];
        try
        {
            DeriveMacKeyFromSharedSecret(salt, sharedSecret, sharedInfo, keyDerivation, macKey);

            return VerifyMac(macKey, message, mac, hmac);
        }
        finally
        {
            macKey.Clear();
        }
    }


    /// <summary>
    /// Verifies a MAC under a key a key holder derived itself (Algorithm 17 step 5 with <c>K</c> supplied):
    /// recomputes <c>MAC′ = HMAC(K, M)</c> and compares it with <paramref name="mac"/> in constant time. A
    /// wrong-length MAC returns <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// This is the one step of the key-holder-derived-key path the library owns beyond the injected HMAC:
    /// signing under such a key is <c>hmac(K, M, mac)</c> directly, whereas verification must compare in
    /// constant time. <paramref name="macKey"/> is secret and the caller clears it.
    /// </remarks>
    /// <param name="macKey">The MAC key <c>K</c> the key holder derived.</param>
    /// <param name="message">The message <c>M</c> the MAC is claimed to authenticate.</param>
    /// <param name="mac">The claimed 32-byte MAC.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <returns><see langword="true"/> iff the MAC is valid.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hmac"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="macKey"/> is empty.</exception>
    public static bool VerifyMac(
        ReadOnlySpan<byte> macKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> mac,
        HmacSha256Delegate hmac)
    {
        ArgumentNullException.ThrowIfNull(hmac);
        if(macKey.Length < 1)
        {
            throw new ArgumentException("The MAC key must be at least 1 byte.", nameof(macKey));
        }

        if(mac.Length != MacSizeBytes)
        {
            return false;
        }

        Span<byte> computedMac = stackalloc byte[MacSizeBytes];
        try
        {
            hmac(macKey, message, computedMac);

            return CryptographicOperations.FixedTimeEquals(computedMac, mac);
        }
        finally
        {
            computedMac.Clear();
        }
    }


    /// <summary>
    /// Realizes <c>E ∈ ⟨G⟩</c>: rejects the encoded point at infinity here, and relies on the injected
    /// <see cref="G1ScalarMultiplyDelegate"/>'s SEC1-decode contract to reject a syntactically
    /// well-formed but off-curve point (P-256's cofactor of 1 then makes on-curve-and-finite
    /// equivalent to subgroup membership).
    /// </summary>
    private static void RequireNotInfinity(ReadOnlySpan<byte> compressedPoint, string name)
    {
        if(compressedPoint[0] == 0x00)
        {
            throw new ArgumentException("The point encodes the point at infinity, which is not a member of the prime-order subgroup <G>.", name);
        }
    }


    /// <summary>
    /// The point-dependent core every entry point shares: validates the peer point (length, infinity,
    /// and — via the delegate's decode contract — on-curve membership) and computes <c>S_AB =
    /// privateScalar·peerPoint</c>. This is the ONLY step a counterparty's malformed input can fail,
    /// which is what lets <see cref="Verify"/> scope its rejected-not-thrown handling to exactly this
    /// call while HKDF/HMAC failures propagate as caller errors. Callers validate their own scalar
    /// before calling; the result buffer receives the full compressed <c>S_AB</c>.
    /// </summary>
    private static void ComputeSharedDiffieHellmanPoint(
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> peerPublicPoint,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> sharedPoint)
    {
        RequireLength(peerPublicPoint, CompressedPointSizeBytes, nameof(peerPublicPoint));
        RequireNotInfinity(peerPublicPoint, nameof(peerPublicPoint));

        g1ScalarMultiply(peerPublicPoint, privateScalar, sharedPoint, Curve);
        if(sharedPoint[0] == 0x00)
        {
            throw new InvalidOperationException("The Diffie-Hellman shared point is the point at infinity; the private key or peer point is degenerate.");
        }
    }
}
