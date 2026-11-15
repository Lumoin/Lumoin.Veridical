using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Security.Cryptography;
using static Lumoin.Veridical.Core.Cryptography.ConstantTimeComparison;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Split-ECDSA (SECDSA) over NIST P-256, per Verheul's construction for an HSM-based EUDI wallet: a standard
/// ECDSA signature <c>(r, s)</c> under the composite private key <c>d = P·u</c> is produced from a PIN-key
/// <c>P</c> and a hardware key <c>u</c> without ever materialising <c>P·u</c>. The output is an ordinary ECDSA
/// signature — it verifies under the public key <c>Y = (P·u)·G</c> with any standard verifier.
/// </summary>
/// <remarks>
/// <para>
/// <b>Algorithm 2 (split sign).</b> Given the hash <c>e = H(M)</c>: blind it as <c>e' = P⁻¹·e mod n</c>,
/// raw-ECDSA-sign <c>e'</c> under the hardware key <c>u</c> with nonce <c>k</c> to get <c>(r, s₀)</c>, then
/// mask the output as <c>s = P·s₀ mod n</c>. The result is a standard ECDSA <c>(r, s)</c> on <c>M</c> under
/// <c>d = P·u</c>, because
/// <c>s = P·k⁻¹(P⁻¹·e + r·u) = k⁻¹(e + r·(P·u)) mod n</c> — the blind and the mask cancel around the raw
/// signature, leaving exactly the <c>s</c> a direct signer under <c>d</c> would compute with the same
/// <c>k</c>. Split-sign security reduces to raw ECDSA security (Verheul, Proposition 3.2).
/// </para>
/// <para>
/// <b>Phases.</b> When the hardware key <c>u</c> lives in a TPM, an HSM, or a cloud KMS, split sign is exposed
/// as two pure phases around the external call: <see cref="PrepareSplitSign"/> returns the blinded
/// representative <c>e'</c> to send to the key holder's raw ECDSA sign, and <see cref="CompleteSplitSign"/>
/// consumes the key holder's <c>(r, s₀)</c>, masks it, and verifies the finished signature before releasing it.
/// The caller performs the external call however it likes, asynchronously or minutes later; neither phase
/// keeps state. The synchronous <c>SplitSign</c> overloads compose the same two phases.
/// </para>
/// <para>
/// <b>Delegate-injected arithmetic.</b> Every scalar (mod <c>n</c>) and group operation is supplied by the
/// caller as a named delegate, so the package carries no concrete field/group backend. The choice of mod-<c>n</c>
/// implementation — a BigInteger reference, a constant-time backend, or any other — is entirely a call-site
/// concern; this algorithm is byte-for-byte stable across it.
/// </para>
/// <para>
/// <b>Timing-hardening status.</b> The in-package secret-scalar checks — the <c>[1, n−1]</c> range validation
/// and the zero tests on <c>P</c>, <c>u</c>, and the derived intermediates — are <i>branchless</i>: they
/// inspect every byte with no data-dependent early exit, so they do not leak by an early return where a key
/// and the order first differ. This is best-effort in managed code, not a hard constant-time guarantee, and it
/// is the cheap part: the dominant variable-time cost is the <i>injected</i> mod-<c>n</c> arithmetic (a
/// BigInteger reference is variable-time; a constant-time scalar backend is a call-site choice) and the RFC 6979 nonce
/// derivation (see <see cref="Core.Cryptography.Rfc6979DeterministicNonce"/>) — so genuine constant-time
/// signing requires a constant-time scalar backend, which this algorithm is byte-for-byte stable across.
/// Key-derived scratch is cleared before return.
/// </para>
/// </remarks>
public static class SecdsaAlgorithm
{
    /// <summary>The P-256 scalar octet length (a signature component, a key, a hash representative).</summary>
    public const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The P-256 SEC1 compressed point length (the public key and the intermediate <c>R = k·G</c>).</summary>
    public const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    /// <summary>The NIST P-256 curve tag every delegate call in this algorithm routes over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;


    /// <summary>
    /// Produces a raw ECDSA-P-256 signature <c>(r, s)</c> over <paramref name="messageHash"/> under
    /// <paramref name="privateKey"/> with the caller-supplied nonce <paramref name="nonce"/>:
    /// <c>r = (k·G).x mod n</c>, <c>s = k⁻¹(e + r·d) mod n</c>. This is the unblinded ECDSA primitive split
    /// sign builds on, and the verification target a matched-nonce equivalence check compares against.
    /// </summary>
    /// <param name="privateKey">The signing scalar <c>d</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The message representative, 32-byte big-endian (reduced mod <c>n</c> internally).</param>
    /// <param name="nonce">The per-signature nonce <c>k</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for <c>k·G</c>).</param>
    /// <param name="r">Receives the 32-byte component <c>r</c>.</param>
    /// <param name="s">Receives the 32-byte component <c>s</c>.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields <c>r = 0</c>, <c>s = 0</c>, or <c>k·G = O</c> (retry with a fresh nonce; probability ~<c>1/n</c>).</exception>
    public static void Sign(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> nonce,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> r,
        Span<byte> s)
    {
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(privateKey, ScalarSizeBytes, nameof(privateKey));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(nonce, ScalarSizeBytes, nameof(nonce));
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(s, ScalarSizeBytes, nameof(s));

        //R = k·G; r = R.x mod n. The x-coordinate lives mod p and can exceed n, so the reduction mod n is
        //load-bearing (a verifier reduces R.x the same way).
        Span<byte> generator = stackalloc byte[CompressedPointSizeBytes];
        WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
        Span<byte> point = stackalloc byte[CompressedPointSizeBytes];
        g1ScalarMultiply(generator, nonce, point, Curve);
        if(point[0] == 0x00)
        {
            throw new InvalidOperationException("The nonce produced the point at infinity; retry with a fresh nonce.");
        }

        scalarReduce(point[1..], r, Curve);
        if(IsZero(r))
        {
            throw new InvalidOperationException("The nonce produced r = 0; retry with a fresh nonce.");
        }

        //s = k⁻¹·(e + r·d) mod n. The intermediates rd = r·d, eRd = e + r·d, and kInverse = k⁻¹ are
        //key/nonce-derived, so they are cleared in a finally — an injected delegate that throws mid-computation
        //must not leave that material on the stack.
        Span<byte> e = stackalloc byte[ScalarSizeBytes];
        Span<byte> rd = stackalloc byte[ScalarSizeBytes];
        Span<byte> eRd = stackalloc byte[ScalarSizeBytes];
        Span<byte> kInverse = stackalloc byte[ScalarSizeBytes];
        try
        {
            scalarReduce(messageHash, e, Curve);
            scalarMultiply(r, privateKey, rd, Curve);
            scalarAdd(e, rd, eRd, Curve);
            scalarInvert(nonce, kInverse, Curve);
            scalarMultiply(kInverse, eRd, s, Curve);
        }
        finally
        {
            e.Clear();
            rd.Clear();
            eRd.Clear();
            kInverse.Clear();
        }

        if(IsZero(s))
        {
            throw new InvalidOperationException("The nonce produced s = 0; retry with a fresh nonce.");
        }
    }


    /// <summary>
    /// SECDSA Algorithm 2 (split sign), phase one, run by the party that holds the PIN-key
    /// <paramref name="pinKey"/>: validates <c>P</c> and computes the blinded representative
    /// <c>e' = P⁻¹·e mod n</c> (Algorithm 2 step 3), the value the key holder raw-ECDSA-signs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What crosses the boundary.</b> <paramref name="blindedHash"/> is the only output and the only thing
    /// the key holder (a TPM, a PKCS#11 token, a cloud KMS, or another party) needs: it is sent to a raw
    /// <c>CKM_ECDSA</c>-style sign under the hardware key <c>u</c>. Because <c>P</c> is uniform and secret,
    /// <c>e'</c> on its own is a uniformly random scalar and reveals neither <c>P</c> nor <c>e</c> (Verheul,
    /// Proposition 3.2 reduces the security of the composition to raw ECDSA).
    /// </para>
    /// <para>
    /// <b>What must never be paired.</b> The message hash <c>e</c> is usually public, and <c>e' = P⁻¹·e</c>, so
    /// anyone who sees both <c>e</c> and <c>e'</c> computes <c>P = e·e'⁻¹</c>. The key holder must therefore be
    /// given only <c>e'</c>, never <c>e</c> or the message, and <c>e'</c> must travel to it over a channel that
    /// an observer of <c>e</c> cannot also read. The same holds for the key holder's answer, see
    /// <see cref="CompleteSplitSign"/>.
    /// </para>
    /// <para>
    /// <b>Secret.</b> <paramref name="pinKey"/> never leaves this party; <paramref name="blindedHash"/> is
    /// derived from it and should be treated as sensitive until the signature is released. The phase is a pure
    /// function of its inputs and keeps no state: the caller carries <c>P</c> and <c>e</c> to
    /// <see cref="CompleteSplitSign"/>, however long the key holder takes.
    /// </para>
    /// <para>
    /// <b>Algorithm 11 (key shares).</b> The two-party split of Algorithm 11 is this same phase applied once
    /// per party: the wallet runs it with <c>zU</c> on <c>e</c> (step 2), the WSCA runs it with <c>zW</c> on the
    /// wallet's output (step 4), and the HSM raw-signs the result (step 6). The completion runs in the opposite
    /// order, see <see cref="CompleteSplitSign"/>.
    /// </para>
    /// </remarks>
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The hash <c>e = H(M)</c>, 32-byte big-endian.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="blindedHash">Receives the 32-byte blinded representative <c>e'</c>.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c> is outside <c>[1, n−1]</c>.</exception>
    public static void PrepareSplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        Span<byte> blindedHash)
    {
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        RequireLength(pinKey, ScalarSizeBytes, nameof(pinKey));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(blindedHash, ScalarSizeBytes, nameof(blindedHash));
        RequireScalarInRange(pinKey, nameof(pinKey));

        //The digest is reduced to a canonical e first so the multiply operands are canonical for any mod-n
        //backend (reduction is a ring homomorphism, so this is byte-identical to multiplying the raw digest).
        Span<byte> e = stackalloc byte[ScalarSizeBytes];
        Span<byte> pinInverse = stackalloc byte[ScalarSizeBytes];
        try
        {
            scalarReduce(messageHash, e, Curve);
            scalarInvert(pinKey, pinInverse, Curve);
            scalarMultiply(pinInverse, e, blindedHash, Curve);
        }
        finally
        {
            e.Clear();
            pinInverse.Clear();
        }
    }


    /// <summary>
    /// SECDSA Algorithm 2 (split sign), phase two, run by the party that holds the PIN-key
    /// <paramref name="pinKey"/>: takes the key holder's raw signature <c>(r, s₀)</c> on <c>e'</c>, masks it as
    /// <c>s = P·s₀ mod n</c> (Algorithm 2 step 8), and releases <c>s</c> only after the finished ECDSA signature
    /// <c>(r, s)</c> verifies on <paramref name="messageHash"/> under the composite public key
    /// <paramref name="publicKeyCompressed"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Verify-before-release.</b> The key holder is outside this party's trust boundary and may be faulty,
    /// substituted, or malicious: a wrong <c>s₀</c>, an <c>(r, s₀)</c> for a different message or key, or a
    /// glitched computation would otherwise turn into a signature the caller emits. Completion therefore
    /// rejects zero or out-of-range <c>r</c> and <c>s₀</c> and then runs the ordinary ECDSA verification
    /// (<see cref="Verify"/>) of <c>(r, s)</c> against <c>e</c> and <c>Y</c>. This one check also authenticates
    /// that <c>(r, s₀)</c> came from the intended key holder, because only a signer holding <c>u</c> with
    /// <c>Y = (P·u)·G</c> can produce a pair that verifies; no separate authentication of the answer is needed.
    /// The public key is a required parameter and the check is not optional. <c>Y</c> is public; the caller is
    /// responsible for obtaining it from a source it trusts (for example <see cref="DeriveSplitPublicKey"/> at
    /// enrolment, or the certificate the signature will be verified against).
    /// </para>
    /// <para>
    /// <b>Secret and exposed.</b> <paramref name="pinKey"/> is secret and stays with this party. The raw
    /// components <paramref name="r"/> and <paramref name="rawS"/> are what the key holder returned: <c>r</c> is
    /// part of the final signature and public. <c>s₀</c> is secret in the same way <c>e'</c> is: the released
    /// <c>s = P·s₀</c> is public, so anyone who also sees <c>s₀</c> computes <c>P = s·s₀⁻¹</c>. Neither
    /// <c>s₀</c> nor <c>e'</c> may be published or logged. The output <paramref name="s"/> is public once released; on
    /// any failure it is cleared and an exception is thrown, so a rejected completion releases nothing.
    /// </para>
    /// <para>
    /// <b>Algorithm 11 (key shares).</b> The completion mirrors the preparation order: the WSCA masks with
    /// <c>zW</c> (step 8) against the intermediate public key <c>zW·BU</c> and the intermediate hash <c>e'</c>,
    /// then the wallet masks with <c>zU</c> (step 10) against the final key <c>zU·zW·BU</c> and <c>e</c>. Each
    /// party can therefore apply this method with its own share as <paramref name="pinKey"/>, and neither
    /// forms <c>zU·zW</c>.
    /// </para>
    /// </remarks>
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The hash <c>e = H(M)</c> that was passed to <see cref="PrepareSplitSign"/>, 32-byte big-endian.</param>
    /// <param name="publicKeyCompressed">The composite public key <c>Y = (P·u)·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="r">The key holder's component <c>r</c>, 32-byte big-endian.</param>
    /// <param name="rawS">The key holder's raw component <c>s₀</c>, 32-byte big-endian; must not alias <paramref name="s"/>.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for the verification).</param>
    /// <param name="g1Add">G1 addition (for the verification).</param>
    /// <param name="s">Receives the 32-byte component <c>s = P·s₀ mod n</c>; cleared when the call throws.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When <c>r</c> or <c>s₀</c> is zero or outside <c>[1, n−1]</c>, or the finished signature does not verify under <paramref name="publicKeyCompressed"/>.</exception>
    public static void CompleteSplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> rawS,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> s)
    {
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        RequireLength(pinKey, ScalarSizeBytes, nameof(pinKey));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(publicKeyCompressed, CompressedPointSizeBytes, nameof(publicKeyCompressed));
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(rawS, ScalarSizeBytes, nameof(rawS));
        RequireLength(s, ScalarSizeBytes, nameof(s));
        RequireScalarInRange(pinKey, nameof(pinKey));

        bool released = false;
        try
        {
            //The key holder's answer is untrusted input: a zero or non-canonical component is a defective
            //answer, not a caller programming error.
            if(IsZero(r) || !IsLess(r, OrderBytes) || IsZero(rawS) || !IsLess(rawS, OrderBytes))
            {
                throw new InvalidOperationException("The key holder returned a raw signature with r or s0 outside [1, n-1].");
            }

            //Mask: s = P·s₀ mod n. P ≠ 0 and n is prime, so s = 0 only if s₀ = 0, already rejected.
            scalarMultiply(pinKey, rawS, s, Curve);
            if(IsZero(s))
            {
                throw new InvalidOperationException("The masked signature component s is zero.");
            }

            //Verify before release: (r, s) must be a valid ECDSA signature on e under Y.
            if(!Verify(publicKeyCompressed, messageHash, r, s, scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add))
            {
                throw new InvalidOperationException("The completed signature does not verify under the composite public key; the key holder's response is rejected.");
            }

            released = true;
        }
        finally
        {
            if(!released)
            {
                s.Clear();
            }
        }
    }


    /// <summary>
    /// SECDSA Algorithm 2 (split sign): produces a standard ECDSA <c>(r, s)</c> on <paramref name="messageHash"/>
    /// under the composite key <c>d = P·u</c> from the PIN-key <paramref name="pinKey"/> and the hardware key
    /// <paramref name="hardwareKey"/>, with the nonce drawn through <paramref name="nonceSource"/> over
    /// <c>(u, e')</c>. <c>P·u</c> is never formed for signing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This runs <see cref="PrepareSplitSign"/>, the raw signature under <c>u</c> (<see cref="Sign"/>), and
    /// <see cref="CompleteSplitSign"/> back to back, so it is one implementation with the phased path. It also
    /// verifies before release, as every entry point does: the public key <c>Y = (P·u)·G</c> is derived with
    /// <see cref="DeriveSplitPublicKey"/> and the finished signature is checked against it, which catches a
    /// computational fault in the in-process arithmetic before a bad signature leaves the call.
    /// </para>
    /// <para>
    /// This also realizes Verheul's Algorithm 11 (split-key signature generation), which equals Algorithm 2 with
    /// <c>P = zU·zW</c> as the PIN-key and the base key <c>bU</c> as the hardware key: the signature is under
    /// <c>Y = (zU·zW·bU)·G</c>. Algorithm 11 applies the shares one after the other, the wallet's <c>zU</c> and
    /// then the WSCA's <c>zW</c>, so the product is never formed in one place; a caller that holds both shares
    /// supplies their product as <paramref name="pinKey"/>. A caller that keeps the shares apart runs
    /// <see cref="PrepareSplitSign"/> and <see cref="CompleteSplitSign"/> once per party instead. With the key
    /// share kept only in the wallet application (the paper's Option I) <c>zW = 1</c> and
    /// <paramref name="pinKey"/> is <c>zU</c> alone.
    /// </para>
    /// </remarks>
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="hardwareKey">The hardware-key scalar <c>u</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The hash <c>e = H(M)</c>, 32-byte big-endian.</param>
    /// <param name="nonceSource">The nonce source, invoked as <c>(P256, u, e')</c>; production binds RFC 6979.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for <c>k·G</c> and the verification).</param>
    /// <param name="g1Add">G1 addition (for the verification).</param>
    /// <param name="r">Receives the 32-byte component <c>r</c>.</param>
    /// <param name="s">Receives the 32-byte component <c>s</c>.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c>/<c>u</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields a degenerate raw signature (retry; probability ~<c>1/n</c>), or the finished signature fails verification.</exception>
    public static void SplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> hardwareKey,
        ReadOnlySpan<byte> messageHash,
        SecdsaNonceSource nonceSource,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> r,
        Span<byte> s)
    {
        ArgumentNullException.ThrowIfNull(nonceSource);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        RequireLength(pinKey, ScalarSizeBytes, nameof(pinKey));
        RequireLength(hardwareKey, ScalarSizeBytes, nameof(hardwareKey));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(s, ScalarSizeBytes, nameof(s));

        //u must be a valid scalar in [1, n−1] (P is validated by the prepare phase): u = 0 makes the signature
        //forgeable and u ≥ n silently folds to a different key. The check is variable-time against the public
        //order — constant-time key validation is the later hardening step.
        RequireScalarInRange(hardwareKey, nameof(hardwareKey));

        //blindedHash, nonce, and rawS are key/nonce-derived; cleared in a finally so a throw in the
        //nonce/sign/mask sequence cannot leave secret material on the stack.
        Span<byte> blindedHash = stackalloc byte[ScalarSizeBytes];
        Span<byte> nonce = stackalloc byte[ScalarSizeBytes];
        Span<byte> rawS = stackalloc byte[ScalarSizeBytes];
        Span<byte> publicKey = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            DeriveSplitPublicKey(pinKey, hardwareKey, scalarMultiply, g1ScalarMultiply, publicKey);
            PrepareSplitSign(pinKey, messageHash, scalarMultiply, scalarInvert, scalarReduce, blindedHash);

            //Nonce over (u, e') — the exact (key, message) the raw signature consumes.
            nonceSource(Curve, hardwareKey, blindedHash, nonce);

            //Raw ECDSA-sign e' under u with k → (r, s₀). r is final; s₀ feeds the mask.
            Sign(hardwareKey, blindedHash, nonce, scalarMultiply, scalarAdd, scalarInvert, scalarReduce, g1ScalarMultiply, r, rawS);

            CompleteSplitSign(pinKey, messageHash, publicKey, r, rawS, scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add, s);
        }
        finally
        {
            blindedHash.Clear();
            nonce.Clear();
            rawS.Clear();
        }
    }


    /// <summary>
    /// SECDSA Algorithm 2 (split sign) over a hardware raw-sign seam: the device computes the blind
    /// <c>e' = P⁻¹·e</c> and the mask <c>s = P·s₀</c> here, and delegates the raw ECDSA signature of <c>e'</c>
    /// to <paramref name="rawSign"/> — a TPM <c>TPM2_Sign</c> / PKCS#11 call, or
    /// <see cref="SecdsaSoftwareRawSigner"/> — so the hardware key <c>u</c> is never seen by this package. The
    /// output <c>(r, s)</c> is a standard ECDSA signature under <c>d = P·u</c>.
    /// </summary>
    /// <remarks>
    /// This is <see cref="PrepareSplitSign"/>, the synchronous <paramref name="rawSign"/> call, and
    /// <see cref="CompleteSplitSign"/> in sequence; a key holder that cannot be called synchronously (a remote
    /// KMS, an asynchronous token API) uses the two phases directly. Because the raw signer is a seam to an
    /// external key holder, the composite public key <paramref name="publicKeyCompressed"/> is required and the
    /// result is verified against it before release, exactly as in <see cref="CompleteSplitSign"/>; a failure
    /// clears <paramref name="r"/> and <paramref name="s"/> and throws.
    /// </remarks>
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The hash <c>e = H(M)</c>, 32-byte big-endian.</param>
    /// <param name="publicKeyCompressed">The composite public key <c>Y = (P·u)·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="rawSign">The hardware/software raw signer: signs <c>e'</c> under <c>u</c> → <c>(r, s₀)</c>.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c> (the blind, the mask, and the verification).</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c> (<c>P⁻¹</c> and the verification).</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c> (the digest to a canonical <c>e</c>).</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for the verification).</param>
    /// <param name="g1Add">G1 addition (for the verification).</param>
    /// <param name="r">Receives the 32-byte component <c>r</c>.</param>
    /// <param name="s">Receives the 32-byte component <c>s</c>.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the raw signature is degenerate or the finished signature does not verify under <paramref name="publicKeyCompressed"/>.</exception>
    public static void SplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> publicKeyCompressed,
        SecdsaRawEcdsaSign rawSign,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> r,
        Span<byte> s)
    {
        ArgumentNullException.ThrowIfNull(rawSign);
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(s, ScalarSizeBytes, nameof(s));

        //blindedHash and rawS are key-derived; cleared in a finally. r and s are public outputs, cleared
        //on failure so a rejected key-holder answer leaves nothing that looks like a signature.
        Span<byte> blindedHash = stackalloc byte[ScalarSizeBytes];
        Span<byte> rawS = stackalloc byte[ScalarSizeBytes];
        bool released = false;
        try
        {
            PrepareSplitSign(pinKey, messageHash, scalarMultiply, scalarInvert, scalarReduce, blindedHash);

            //Hardware/software raw-ECDSA-signs e' under u → (r, s₀); u never crosses into this package.
            rawSign(blindedHash, r, rawS);

            CompleteSplitSign(pinKey, messageHash, publicKeyCompressed, r, rawS, scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add, s);
            released = true;
        }
        finally
        {
            blindedHash.Clear();
            rawS.Clear();
            if(!released)
            {
                r.Clear();
                s.Clear();
            }
        }
    }


    /// <summary>
    /// SECDSA Algorithm 2 (split sign) returning a pool-backed <see cref="SecdsaSignature"/>.
    /// </summary>
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="hardwareKey">The hardware-key scalar <c>u</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The hash <c>e = H(M)</c>, 32-byte big-endian.</param>
    /// <param name="nonceSource">The nonce source, invoked as <c>(P256, u, e')</c>; production binds RFC 6979.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for <c>k·G</c> and the verification).</param>
    /// <param name="g1Add">G1 addition (for the verification).</param>
    /// <param name="pool">The pool to rent the 64-byte signature buffer from.</param>
    /// <returns>A signature wrapping a pool-rented <c>r || s</c> buffer.</returns>
    /// <exception cref="ArgumentNullException">When a delegate or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c>/<c>u</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields a degenerate raw signature (retry; probability ~<c>1/n</c>).</exception>
    public static SecdsaSignature SplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> hardwareKey,
        ReadOnlySpan<byte> messageHash,
        SecdsaNonceSource nonceSource,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(SecdsaSignature.SizeBytes);
        try
        {
            Span<byte> signature = owner.Memory.Span[..SecdsaSignature.SizeBytes];
            SplitSign(
                pinKey, hardwareKey, messageHash, nonceSource,
                scalarMultiply, scalarAdd, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add,
                signature.Slice(SecdsaSignature.ROffset, SecdsaSignature.RSizeBytes),
                signature.Slice(SecdsaSignature.SOffset, SecdsaSignature.SSizeBytes));
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        return new SecdsaSignature(owner, SecdsaSignature.AlgebraicTag);
    }


    /// <summary>
    /// Verifies a standard ECDSA-P-256 signature <c>(r, s)</c> over <paramref name="messageHash"/> under the
    /// public key <paramref name="publicKeyCompressed"/>. For SECDSA the verification key is
    /// <c>Y = (P·u)·G</c>, but verification is plain ECDSA — there is nothing split-specific.
    /// </summary>
    /// <param name="publicKeyCompressed">The public key <c>Y</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="messageHash">The message representative, 32-byte big-endian.</param>
    /// <param name="r">The component <c>r</c>, 32-byte big-endian.</param>
    /// <param name="s">The component <c>s</c>, 32-byte big-endian.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <returns><see langword="true"/> iff the signature is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    public static bool Verify(
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add)
    {
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        RequireLength(publicKeyCompressed, CompressedPointSizeBytes, nameof(publicKeyCompressed));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(s, ScalarSizeBytes, nameof(s));

        //Adversarial inputs (an out-of-range scalar, a non-point public key) must reject, not throw: the
        //group delegate throws on a malformed point, and an inversion may reject a degenerate value.
        try
        {
            Span<byte> noncePoint = stackalloc byte[CompressedPointSizeBytes];
            if(!TryRecoverNoncePoint(
                publicKeyCompressed, messageHash, r, s,
                scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add,
                noncePoint))
            {
                return false;
            }

            //Accept iff R.x ≡ r (mod n).
            Span<byte> rPrime = stackalloc byte[ScalarSizeBytes];
            scalarReduce(noncePoint[1..], rPrime, Curve);

            return CryptographicOperations.FixedTimeEquals(rPrime, r);
        }
        catch(InvalidOperationException)
        {
            return false;
        }
        catch(ArgumentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Recovers the full nonce point <c>R = k·G</c> from a standard ECDSA signature <c>(r, s)</c> — the
    /// conversion to the full representation <c>(R, s)</c> of Verheul's Annex A.2 (Algorithm 3 Step 4). A plain
    /// signature carries only <c>r = R.x mod n</c>; blind SECDSA (and any flow that re-randomises the signature)
    /// needs the full point <c>R</c>. Recovery uses <c>R = (e·s⁻¹)·G + (r·s⁻¹)·Y</c>, as in Step 5 of
    /// Algorithm 14, which reconstructs the same <c>R</c> the signer formed from its nonce <c>k</c>.
    /// </summary>
    /// <param name="publicKeyCompressed">The public key <c>Y</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="messageHash">The message representative, 32-byte big-endian.</param>
    /// <param name="r">The component <c>r</c>, 32-byte big-endian.</param>
    /// <param name="s">The component <c>s</c>, 32-byte big-endian.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="noncePointCompressed">Receives the recovered <c>R</c>, SEC1 compressed (33 bytes).</param>
    /// <returns><see langword="true"/> iff a finite <c>R</c> was recovered; <see langword="false"/> when
    /// <c>(r, s)</c> is out of range, the public key is malformed, or <c>R</c> is the point at infinity (the
    /// contents of <paramref name="noncePointCompressed"/> are then unspecified).</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    public static bool RecoverNoncePoint(
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> noncePointCompressed)
    {
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        RequireLength(publicKeyCompressed, CompressedPointSizeBytes, nameof(publicKeyCompressed));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(s, ScalarSizeBytes, nameof(s));
        RequireLength(noncePointCompressed, CompressedPointSizeBytes, nameof(noncePointCompressed));

        try
        {
            return TryRecoverNoncePoint(
                publicKeyCompressed, messageHash, r, s,
                scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add,
                noncePointCompressed);
        }
        catch(InvalidOperationException)
        {
            return false;
        }
        catch(ArgumentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Verifies a "full-format" SECDSA signature <c>(R, s)</c> that carries the full nonce point — Verheul's
    /// Algorithm 15 (alternative ECDSA signature verification). Equivalent to standard <see cref="Verify"/> with <c>r = R.x mod n</c>: it derives <c>r</c> from
    /// the supplied point and runs the ordinary ECDSA check (which re-recovers <c>R</c> and confirms <c>R.x ≡ r</c>).
    /// </summary>
    /// <param name="publicKeyCompressed">The public key <c>Y</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="messageHash">The message representative, 32-byte big-endian.</param>
    /// <param name="noncePointCompressed">The nonce point <c>R</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="s">The component <c>s</c>, 32-byte big-endian.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <returns><see langword="true"/> iff the full-format signature is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    public static bool VerifyFull(
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> noncePointCompressed,
        ReadOnlySpan<byte> s,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add)
    {
        ArgumentNullException.ThrowIfNull(scalarReduce);
        RequireLength(noncePointCompressed, CompressedPointSizeBytes, nameof(noncePointCompressed));

        //r = R.x mod n. An infinity point (0x00 prefix) carries x = 0, which reduces to r = 0 and Verify rejects
        //as out of range; otherwise Verify re-recovers R and confirms R.x ≡ r, so the carried point is consistent.
        Span<byte> r = stackalloc byte[ScalarSizeBytes];
        try
        {
            scalarReduce(noncePointCompressed[1..], r, Curve);
        }
        catch(ArgumentException)
        {
            return false;
        }

        return Verify(
            publicKeyCompressed, messageHash, r, s,
            scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add);
    }


    /// <summary>
    /// Recovers <c>R = (e·s⁻¹)·G + (r·s⁻¹)·Y</c> for a standard ECDSA (r, s). Returns
    /// <see langword="false"/> when (r, s) is out of [1, n−1] or R is the point at infinity; may
    /// throw (a malformed public key, a degenerate inversion) for the public callers to translate
    /// into a rejection. Shared by <see cref="Verify"/> and <see cref="RecoverNoncePoint"/> so both
    /// agree bit-for-bit.
    /// </summary>
    private static bool TryRecoverNoncePoint(
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> noncePointCompressed)
    {
        //Reject r, s outside [1, n−1].
        if(IsZero(r) || IsZero(s) || !IsLess(r, OrderBytes) || !IsLess(s, OrderBytes))
        {
            return false;
        }

        Span<byte> e = stackalloc byte[ScalarSizeBytes];
        scalarReduce(messageHash, e, Curve);

        //w = s⁻¹; u1 = e·w; u2 = r·w (mod n).
        Span<byte> w = stackalloc byte[ScalarSizeBytes];
        scalarInvert(s, w, Curve);
        Span<byte> u1 = stackalloc byte[ScalarSizeBytes];
        Span<byte> u2 = stackalloc byte[ScalarSizeBytes];
        scalarMultiply(e, w, u1, Curve);
        scalarMultiply(r, w, u2, Curve);

        //R = u1·G + u2·Q.
        Span<byte> generator = stackalloc byte[CompressedPointSizeBytes];
        WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
        Span<byte> u1G = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> u2Q = stackalloc byte[CompressedPointSizeBytes];
        g1ScalarMultiply(generator, u1, u1G, Curve);
        g1ScalarMultiply(publicKeyCompressed, u2, u2Q, Curve);
        g1Add(u1G, u2Q, noncePointCompressed, Curve);

        //R must not be the point at infinity (0x00 prefix).
        return noncePointCompressed[0] != 0x00;
    }


    /// <summary>
    /// Derives the SECDSA public key <c>Y = (P·u)·G</c> from the PIN-key <paramref name="pinKey"/> and the
    /// hardware key <paramref name="hardwareKey"/>, writing it SEC1 compressed (33 bytes). The composite scalar
    /// <c>P·u</c> is formed locally only to scalar-multiply the generator, and cleared before return.
    /// </summary>
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="hardwareKey">The hardware-key scalar <c>u</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="publicKeyCompressed">Receives the 33-byte SEC1 compressed public key.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c>/<c>u</c> is outside <c>[1, n−1]</c>.</exception>
    public static void DeriveSplitPublicKey(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> hardwareKey,
        ScalarMultiplyDelegate scalarMultiply,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> publicKeyCompressed)
    {
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(pinKey, ScalarSizeBytes, nameof(pinKey));
        RequireLength(hardwareKey, ScalarSizeBytes, nameof(hardwareKey));
        RequireLength(publicKeyCompressed, CompressedPointSizeBytes, nameof(publicKeyCompressed));
        RequireScalarInRange(pinKey, nameof(pinKey));
        RequireScalarInRange(hardwareKey, nameof(hardwareKey));

        //composite = P·u IS the full composite private key d; it is cleared in a finally so a throw in the
        //group multiply cannot leave the private key on the stack.
        Span<byte> composite = stackalloc byte[ScalarSizeBytes];
        try
        {
            scalarMultiply(pinKey, hardwareKey, composite, Curve);

            Span<byte> generator = stackalloc byte[CompressedPointSizeBytes];
            WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
            g1ScalarMultiply(generator, composite, publicKeyCompressed, Curve);
        }
        finally
        {
            composite.Clear();
        }
    }
}
