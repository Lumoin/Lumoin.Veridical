using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

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
/// <b>Delegate-injected arithmetic.</b> Every scalar (mod <c>n</c>) and group operation is supplied by the
/// caller as a named delegate, so the package carries no concrete field/group backend. The choice of mod-<c>n</c>
/// implementation — the BigInteger reference today, a constant-time backend later — is entirely a call-site
/// concern; this algorithm is byte-for-byte stable across it.
/// </para>
/// <para>
/// <b>Not constant-time yet.</b> The wired BigInteger arithmetic, the RFC 6979 nonce derivation, and the
/// public-order range checks here are all variable-time in their secret inputs. Constant-time secret-scalar
/// handling for <c>u</c>, <c>P</c>, and the derived intermediates is a separate, later hardening step; this is
/// flagged exactly as <see cref="Core.Cryptography.Rfc6979DeterministicNonce"/> flags its own candidate
/// comparison. Key-derived scratch is nonetheless cleared before return.
/// </para>
/// </remarks>
public static class SecdsaAlgorithm
{
    /// <summary>The P-256 scalar octet length (a signature component, a key, a hash representative).</summary>
    public const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The P-256 SEC1 compressed point length (the public key and the intermediate <c>R = k·G</c>).</summary>
    public const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;


    //The order n as a 32-byte big-endian scalar, used only for the public-order range checks. n is curve
    //definition data, not a secret.
    private static byte[] OrderBytes { get; } = BuildOrderBytes();


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
    /// SECDSA Algorithm 2 (split sign): produces a standard ECDSA <c>(r, s)</c> on <paramref name="messageHash"/>
    /// under the composite key <c>d = P·u</c> from the PIN-key <paramref name="pinKey"/> and the hardware key
    /// <paramref name="hardwareKey"/>, with the nonce drawn through <paramref name="nonceSource"/> over
    /// <c>(u, e')</c>. <c>P·u</c> is never formed.
    /// </summary>
    /// <remarks>
    /// This also realizes Verheul's Algorithm 11 (split-key / key-share sign): it is algebraically identical with
    /// the key share <c>zU</c> passed as <paramref name="pinKey"/> and the base key <c>bU</c> as
    /// <paramref name="hardwareKey"/>, signing under <c>Y = (zU·bU)·G</c>. No separate key-share entry point is
    /// needed — the two algorithms differ only in which factor is the long-lived hardware key and which is the
    /// per-operation share, and the split sign treats both as injected scalars.
    /// </remarks>
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="hardwareKey">The hardware-key scalar <c>u</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The hash <c>e = H(M)</c>, 32-byte big-endian.</param>
    /// <param name="nonceSource">The nonce source, invoked as <c>(P256, u, e')</c>; production binds RFC 6979.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for <c>k·G</c>).</param>
    /// <param name="r">Receives the 32-byte component <c>r</c>.</param>
    /// <param name="s">Receives the 32-byte component <c>s</c>.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c>/<c>u</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields a degenerate raw signature (retry; probability ~<c>1/n</c>).</exception>
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
        Span<byte> r,
        Span<byte> s)
    {
        ArgumentNullException.ThrowIfNull(nonceSource);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(pinKey, ScalarSizeBytes, nameof(pinKey));
        RequireLength(hardwareKey, ScalarSizeBytes, nameof(hardwareKey));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(s, ScalarSizeBytes, nameof(s));

        //u must be a valid scalar in [1, n−1] (P is validated inside BlindHash): u = 0 makes the signature
        //forgeable and u ≥ n silently folds to a different key. The check is variable-time against the public
        //order — constant-time key validation is the later hardening step.
        RequireScalarInRange(hardwareKey, nameof(hardwareKey));

        //blindedHash, nonce, and rawS are key/nonce-derived; cleared in a finally so a throw in the
        //nonce/sign/mask sequence cannot leave secret material on the stack.
        Span<byte> blindedHash = stackalloc byte[ScalarSizeBytes];
        Span<byte> nonce = stackalloc byte[ScalarSizeBytes];
        Span<byte> rawS = stackalloc byte[ScalarSizeBytes];
        try
        {
            //Blind: e' = P⁻¹·e mod n (validates P and clears its own scratch).
            BlindHash(pinKey, messageHash, scalarMultiply, scalarInvert, scalarReduce, blindedHash);

            //Nonce over (u, e') — the exact (key, message) the raw signature consumes.
            nonceSource(Curve, hardwareKey, blindedHash, nonce);

            //Raw ECDSA-sign e' under u with k → (r, s₀). r is final; s₀ feeds the mask.
            Sign(hardwareKey, blindedHash, nonce, scalarMultiply, scalarAdd, scalarInvert, scalarReduce, g1ScalarMultiply, r, rawS);

            //Mask: s = P·s₀ mod n. P ≠ 0, so s = 0 iff s₀ = 0, already rejected by Sign.
            scalarMultiply(pinKey, rawS, s, Curve);
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
    /// <param name="pinKey">The PIN-key scalar <c>P</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="messageHash">The hash <c>e = H(M)</c>, 32-byte big-endian.</param>
    /// <param name="rawSign">The hardware/software raw signer: signs <c>e'</c> under <c>u</c> → <c>(r, s₀)</c>.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c> (the blind and the mask).</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c> (<c>P⁻¹</c>).</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c> (the digest to a canonical <c>e</c>).</param>
    /// <param name="r">Receives the 32-byte component <c>r</c>.</param>
    /// <param name="s">Receives the 32-byte component <c>s</c>.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, or <c>P</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the raw signature is degenerate (<c>r = 0</c> or <c>s = 0</c>; retry).</exception>
    public static void SplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        SecdsaRawEcdsaSign rawSign,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        Span<byte> r,
        Span<byte> s)
    {
        ArgumentNullException.ThrowIfNull(rawSign);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        RequireLength(pinKey, ScalarSizeBytes, nameof(pinKey));
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));
        RequireLength(r, ScalarSizeBytes, nameof(r));
        RequireLength(s, ScalarSizeBytes, nameof(s));

        //blindedHash and rawS are key-derived; cleared in a finally. r and s are public outputs.
        Span<byte> blindedHash = stackalloc byte[ScalarSizeBytes];
        Span<byte> rawS = stackalloc byte[ScalarSizeBytes];
        try
        {
            //Blind: e' = P⁻¹·e mod n (validates P and clears its own scratch).
            BlindHash(pinKey, messageHash, scalarMultiply, scalarInvert, scalarReduce, blindedHash);

            //Hardware/software raw-ECDSA-signs e' under u → (r, s₀); u never crosses into this package.
            rawSign(blindedHash, r, rawS);

            //Mask: s = P·s₀ mod n.
            scalarMultiply(pinKey, rawS, s, Curve);

            //Defensive: a correct raw signer never returns r = 0 / s₀ = 0 (P ≠ 0 ⇒ s = 0 iff s₀ = 0), but a
            //degenerate result must not be emitted as a valid-looking signature.
            if(IsZero(r) || IsZero(s))
            {
                throw new InvalidOperationException("The raw signature was degenerate (r = 0 or s = 0); retry.");
            }
        }
        finally
        {
            blindedHash.Clear();
            rawS.Clear();
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
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for <c>k·G</c>).</param>
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
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(SecdsaSignature.SizeBytes);
        try
        {
            Span<byte> signature = owner.Memory.Span[..SecdsaSignature.SizeBytes];
            SplitSign(
                pinKey, hardwareKey, messageHash, nonceSource,
                scalarMultiply, scalarAdd, scalarInvert, scalarReduce, g1ScalarMultiply,
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

            return rPrime.SequenceEqual(r);
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
    /// Recovers the full nonce point <c>R = k·G</c> from a standard ECDSA signature <c>(r, s)</c> — Verheul's
    /// "full-format" conversion (ToFullFormat). A plain signature carries only <c>r = R.x mod n</c>; blind SECDSA
    /// (and any flow that re-randomises the signature) needs the full point <c>R</c>. Recovery uses the
    /// verification relation <c>R = (e·s⁻¹)·G + (r·s⁻¹)·Y</c>, which reconstructs the same <c>R</c> the signer
    /// formed from its nonce <c>k</c>.
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
    /// VerifyFull. Equivalent to standard <see cref="Verify"/> with <c>r = R.x mod n</c>: it derives <c>r</c> from
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


    //Recovers R = (e·s⁻¹)·G + (r·s⁻¹)·Y for a standard ECDSA (r, s). Returns false when (r, s) is out of
    //[1, n−1] or R is the point at infinity; may throw (a malformed public key, a degenerate inversion) for the
    //public callers to translate into a rejection. Shared by Verify and RecoverNoncePoint so both agree bit-for-bit.
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


    private static byte[] BuildOrderBytes()
    {
        BigInteger n = WellKnownCurves.GetScalarFieldOrder(Curve);
        byte[] big = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] order = new byte[ScalarSizeBytes];
        big.CopyTo(order.AsSpan(ScalarSizeBytes - big.Length));

        return order;
    }


    //Blind: writes e' = P⁻¹·e mod n into blindedHash. Validates P in [1, n−1]; reduces the digest to a
    //canonical e first so the multiply operands are canonical for any mod-n backend (reduction is a ring
    //homomorphism, so this is byte-identical to multiplying the raw digest). Clears its own key-derived scratch.
    private static void BlindHash(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        Span<byte> blindedHash)
    {
        RequireScalarInRange(pinKey, nameof(pinKey));

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


    private static void RequireScalarInRange(ReadOnlySpan<byte> scalar, string name)
    {
        if(IsZero(scalar) || !IsLess(scalar, OrderBytes))
        {
            throw new ArgumentException($"The scalar must be in [1, n-1] for the P-256 group order.", name);
        }
    }


    private static void RequireLength(ReadOnlySpan<byte> span, int expected, string name)
    {
        if(span.Length != expected)
        {
            throw new ArgumentException($"Expected {expected} bytes; received {span.Length}.", name);
        }
    }


    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;


    //Big-endian unsigned comparison: a < b. Equal-length operands (both 32-byte scalars).
    private static bool IsLess(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for(int i = 0; i < a.Length; i++)
        {
            if(a[i] != b[i])
            {
                return a[i] < b[i];
            }
        }

        return false;
    }
}
