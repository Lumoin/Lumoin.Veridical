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
/// The choice of implementation — the BigInteger group reference today, a constant-time backend later — is
/// entirely a call-site concern; this algorithm is byte-for-byte stable across it.
/// </para>
/// <para>
/// <b>Timing-hardening status.</b> The in-package secret-scalar checks — the <c>[1, n−1]</c> range validation on
/// each key/key-share — are <i>branchless</i>: they inspect every byte with no data-dependent early exit, so
/// they do not leak by an early return where a key and the order first differ. This is best-effort in managed
/// code, not a hard constant-time guarantee, and it is the cheap part: the dominant variable-time cost is the
/// <i>injected</i> group arithmetic (the BigInteger reference today; a constant-time scalar/group backend is a
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

    /// <summary>The HMAC-SHA256 output length: <c>MAC = HMAC(K, M)</c> is always 32 bytes.</summary>
    public const int MacSizeBytes = 32;

    /// <summary>
    /// The HKDF output length used to derive the MAC key <c>K</c> — the paper leaves this (RFC 5869's <c>L</c>)
    /// implicit; 32 bytes is the natural choice for an HMAC-SHA256 key. <see cref="DeriveMacKey"/> accepts any
    /// destination length; this constant is what <see cref="Sign"/>, <see cref="Verify"/>, and
    /// <see cref="SplitSign"/> use internally.
    /// </summary>
    public const int MacKeySizeBytes = 32;

    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;


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
    /// <paramref name="hkdf"/> implementation may bound its length (the library's <c>Sha256Hkdf</c> caps
    /// <c>info</c> at 1024 bytes) — a rejection surfaces as the delegate's own <see cref="ArgumentException"/>.
    /// </param>
    /// <param name="hkdf">The HKDF-SHA256 derivation delegate.</param>
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
        HkdfSha256Delegate hkdf,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> macKey)
    {
        ArgumentNullException.ThrowIfNull(hkdf);
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

            //Z_AB = the shared point's x-coordinate; K = HKDF(Z_AB, SharedInfo) with the caller's salt.
            hkdf(salt, sharedPoint[1..], sharedInfo, macKey);
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
    /// <param name="hkdf">The HKDF-SHA256 derivation delegate.</param>
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
        HkdfSha256Delegate hkdf,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> mac)
    {
        ArgumentNullException.ThrowIfNull(hkdf);
        ArgumentNullException.ThrowIfNull(hmac);
        RequireLength(mac, MacSizeBytes, nameof(mac));

        //The MAC key K is key-derived material; cleared in a finally so a throwing hmac call cannot leave it on
        //the stack.
        Span<byte> macKey = stackalloc byte[MacKeySizeBytes];
        try
        {
            DeriveMacKey(privateKey, verifierEphemeralPublicKey, salt, sharedInfo, hkdf, g1ScalarMultiply, macKey);
            hmac(macKey, message, mac);
        }
        finally
        {
            macKey.Clear();
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
    /// (including a <paramref name="salt"/>/<paramref name="sharedInfo"/> the injected <paramref name="hkdf"/>
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
    /// <param name="hkdf">The HKDF-SHA256 derivation delegate.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for the Diffie-Hellman product).</param>
    /// <returns><see langword="true"/> iff the MAC is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="verifierEphemeralPrivateKey"/> has the wrong length or lies outside <c>[1, n−1]</c>,
    /// or the injected <paramref name="hkdf"/> rejects the caller's <paramref name="salt"/> or
    /// <paramref name="sharedInfo"/> (an implementation-bounded length, for example).
    /// </exception>
    public static bool Verify(
        ReadOnlySpan<byte> proverPublicKey,
        ReadOnlySpan<byte> verifierEphemeralPrivateKey,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> mac,
        HkdfSha256Delegate hkdf,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply)
    {
        ArgumentNullException.ThrowIfNull(hkdf);
        ArgumentNullException.ThrowIfNull(hmac);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(verifierEphemeralPrivateKey, ScalarSizeBytes, nameof(verifierEphemeralPrivateKey));
        RequireScalarInRange(verifierEphemeralPrivateKey, nameof(verifierEphemeralPrivateKey));

        if(mac.Length != MacSizeBytes)
        {
            return false;
        }

        Span<byte> sharedPoint = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> macKey = stackalloc byte[MacKeySizeBytes];
        Span<byte> computedMac = stackalloc byte[MacSizeBytes];
        try
        {
            //Only the point-dependent step can be failed by the (possibly adversarial) prover: a wrong-length,
            //infinity, or off-curve proverPublicKey rejects as false here. The rejected-not-thrown handling is
            //scoped to exactly this call so a failure in the injected hkdf/hmac — which concerns the verifier's
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

            //Z_AB = the shared point's x-coordinate; K = HKDF(Z_AB, SharedInfo); MAC' = HMAC(K, M).
            hkdf(salt, sharedPoint[1..], sharedInfo, macKey);
            hmac(macKey, message, computedMac);

            return CryptographicOperations.FixedTimeEquals(computedMac, mac);
        }
        finally
        {
            sharedPoint.Clear();
            macKey.Clear();
            computedMac.Clear();
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
    /// callers that hold all three shares (tests, a single-process reference flow).
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
    /// <param name="hkdf">The HKDF-SHA256 derivation delegate.</param>
    /// <param name="hmac">The HMAC-SHA256 delegate.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication, invoked three times: <c>E′ = zU·E</c>, <c>E″ = zW·E′</c>, and (inside <see cref="DeriveMacKey"/>) <c>S_AB = bU·E″</c>.</param>
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
        HkdfSha256Delegate hkdf,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> mac)
    {
        ArgumentNullException.ThrowIfNull(hkdf);
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

        //E' and E'' are share-blinded intermediate points; K is the final MAC key. All three are cleared in a
        //finally so a throw partway through the three-party chain cannot leave them on the stack.
        Span<byte> walletBlindedPoint = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> wscaBlindedPoint = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> macKey = stackalloc byte[MacKeySizeBytes];
        try
        {
            //E' = zU·E (wallet).
            g1ScalarMultiply(verifierEphemeralPublicKey, walletKeyShare, walletBlindedPoint, Curve);
            if(walletBlindedPoint[0] == 0x00)
            {
                throw new InvalidOperationException("The wallet-share Diffie-Hellman point E' is the point at infinity; the wallet key share or the verifier's ephemeral public key is degenerate.");
            }

            //E'' = zW·E' (WSCA).
            g1ScalarMultiply(walletBlindedPoint, wscaKeyShare, wscaBlindedPoint, Curve);
            if(wscaBlindedPoint[0] == 0x00)
            {
                throw new InvalidOperationException("The WSCA-share Diffie-Hellman point E'' is the point at infinity; the WSCA key share is degenerate.");
            }

            //S_AB = bU·E'' (HSM); K = HKDF(Z_AB, SharedInfo); MAC = HMAC(K, M).
            DeriveMacKey(baseKey, wscaBlindedPoint, salt, sharedInfo, hkdf, g1ScalarMultiply, macKey);
            hmac(macKey, message, mac);
        }
        finally
        {
            walletBlindedPoint.Clear();
            wscaBlindedPoint.Clear();
            macKey.Clear();
        }
    }


    //E ∈ ⟨G⟩ is realized as: reject the encoded point at infinity here, and rely on the injected
    //G1ScalarMultiplyDelegate's SEC1-decode contract to reject a syntactically well-formed but off-curve point
    //(P-256's cofactor of 1 then makes on-curve-and-finite equivalent to subgroup membership).
    private static void RequireNotInfinity(ReadOnlySpan<byte> compressedPoint, string name)
    {
        if(compressedPoint[0] == 0x00)
        {
            throw new ArgumentException("The point encodes the point at infinity, which is not a member of the prime-order subgroup <G>.", name);
        }
    }


    //The point-dependent core every entry point shares: validates the peer point (length, infinity, and — via
    //the delegate's decode contract — on-curve membership) and computes S_AB = privateScalar·peerPoint. This is
    //the ONLY step a counterparty's malformed input can fail, which is what lets Verify scope its
    //rejected-not-thrown handling to exactly this call while HKDF/HMAC failures propagate as caller errors.
    //Callers validate their own scalar before calling; the result buffer receives the full compressed S_AB.
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
