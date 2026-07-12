using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference ECDSA over NIST P-256 (FIPS 186-4 §6, SEC 1 v2.0 §4.1), built on
/// the P-256 scalar field (<see cref="P256BigIntegerScalarReference"/>, mod
/// <c>n</c>) and group (<see cref="P256BigIntegerG1Reference"/>). This is the
/// cleartext verification spec the in-circuit zero-knowledge proof is gated
/// against, and the primitive Verifiable's split-key ECDSA (SECDSA) is meant
/// to sit on once promoted.
/// </summary>
/// <remarks>
/// <para>
/// The message hash enters already reduced from the application's hash
/// function (SHA-256 for the standard P-256 ciphersuite): the caller passes
/// the 32-byte digest, which this treats as the integer <c>e</c> — P-256's
/// order is 256 bits, so no leftmost-bits truncation is needed, only the
/// implicit reduction mod <c>n</c> the verify equation applies. Keeping the
/// hash outside this type leaves the digest a backend choice, matching the
/// rest of the library.
/// </para>
/// <para>
/// Verify: reject <c>r, s</c> outside <c>[1, n−1]</c>; <c>w = s⁻¹</c>,
/// <c>u₁ = e·w</c>, <c>u₂ = r·w</c> (all mod <c>n</c>); recover
/// <c>R = u₁·G + u₂·Q</c>; accept iff <c>R ≠ O</c> and <c>R.x ≡ r (mod n)</c>.
/// Sign: <c>R = k·G</c>, <c>r = R.x mod n</c>, <c>s = k⁻¹(e + r·d) mod n</c>,
/// with the caller supplying the per-signature nonce <c>k</c> (this reference
/// does not derive it; a deterministic RFC 6979 nonce is a separate concern).
/// </para>
/// </remarks>
internal static class P256EcdsaReference
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;
    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;

    private static readonly ScalarMultiplyDelegate ScalarMul = P256BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarAddDelegate ScalarAdd = P256BigIntegerScalarReference.GetAdd();
    private static readonly ScalarInvertDelegate ScalarInvert = P256BigIntegerScalarReference.GetInvert();
    private static readonly ScalarReduceDelegate ScalarReduce = P256BigIntegerScalarReference.GetReduce();
    //Constant-time secret-scalar multiply (byte-identical to the reference): hardens the k·G in Sign. The
    //verify-side u1·G / u2·Q multiplies run on public scalars but share the same delegate.
    private static readonly G1ScalarMultiplyDelegate PointMul = P256ConstantTimeG1Backend.GetScalarMultiply();
    private static readonly G1AddDelegate PointAdd = P256BigIntegerG1Reference.GetAdd();

    private static BigInteger Order { get; } = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);


    /// <summary>
    /// Verifies an ECDSA-P-256 signature.
    /// </summary>
    /// <param name="publicKeyCompressed">The signer's public key <c>Q</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="messageHash">The message digest as the integer <c>e</c>, canonical big-endian (32 bytes).</param>
    /// <param name="r">The signature component <c>r</c>, canonical big-endian (32 bytes).</param>
    /// <param name="s">The signature component <c>s</c>, canonical big-endian (32 bytes).</param>
    /// <returns><see langword="true"/> iff the signature is valid.</returns>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    public static bool Verify(
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s)
    {
        RequireLength(publicKeyCompressed, CompressedSize, nameof(publicKeyCompressed));
        RequireLength(messageHash, ScalarSize, nameof(messageHash));
        RequireLength(r, ScalarSize, nameof(r));
        RequireLength(s, ScalarSize, nameof(s));

        //Adversarial inputs (a non-point public key, an out-of-range scalar)
        //must reject, not throw.
        try
        {
            BigInteger rValue = new(r, isUnsigned: true, isBigEndian: true);
            BigInteger sValue = new(s, isUnsigned: true, isBigEndian: true);
            if(rValue < BigInteger.One || rValue >= Order || sValue < BigInteger.One || sValue >= Order)
            {
                return false;
            }

            Span<byte> e = stackalloc byte[ScalarSize];
            ScalarReduce(messageHash, e, Curve);

            //w = s⁻¹; u1 = e·w; u2 = r·w (mod n).
            Span<byte> w = stackalloc byte[ScalarSize];
            ScalarInvert(s, w, Curve);
            Span<byte> u1 = stackalloc byte[ScalarSize];
            Span<byte> u2 = stackalloc byte[ScalarSize];
            ScalarMul(e, w, u1, Curve);
            ScalarMul(r, w, u2, Curve);

            //R = u1·G + u2·Q.
            Span<byte> generator = stackalloc byte[CompressedSize];
            WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
            Span<byte> u1G = stackalloc byte[CompressedSize];
            Span<byte> u2Q = stackalloc byte[CompressedSize];
            PointMul(generator, u1, u1G, Curve);
            PointMul(publicKeyCompressed, u2, u2Q, Curve);
            Span<byte> point = stackalloc byte[CompressedSize];
            PointAdd(u1G, u2Q, point, Curve);

            //R must not be the point at infinity (0x00 prefix).
            if(point[0] == 0x00)
            {
                return false;
            }

            //Accept iff R.x ≡ r (mod n). R.x is the compressed encoding's
            //coordinate field; reduce it mod n before the comparison.
            Span<byte> rPrime = stackalloc byte[ScalarSize];
            ScalarReduce(point[1..], rPrime, Curve);

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
    /// Produces an ECDSA-P-256 signature with the caller-supplied nonce.
    /// </summary>
    /// <param name="privateKey">The signer's private scalar <c>d</c>, canonical big-endian (32 bytes).</param>
    /// <param name="messageHash">The message digest as the integer <c>e</c>, canonical big-endian (32 bytes).</param>
    /// <param name="nonce">The per-signature nonce <c>k</c> in <c>[1, n−1]</c>, canonical big-endian (32 bytes).</param>
    /// <param name="r">Receives the signature component <c>r</c> (32 bytes).</param>
    /// <param name="s">Receives the signature component <c>s</c> (32 bytes).</param>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields <c>r = 0</c> or <c>s = 0</c> (caller must retry with a fresh nonce; probability ~<c>1/n</c>).</exception>
    public static void Sign(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> nonce,
        Span<byte> r,
        Span<byte> s)
    {
        RequireLength(privateKey, ScalarSize, nameof(privateKey));
        RequireLength(messageHash, ScalarSize, nameof(messageHash));
        RequireLength(nonce, ScalarSize, nameof(nonce));
        RequireLength(r, ScalarSize, nameof(r));
        RequireLength(s, ScalarSize, nameof(s));

        //R = k·G; r = R.x mod n.
        Span<byte> generator = stackalloc byte[CompressedSize];
        WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
        Span<byte> point = stackalloc byte[CompressedSize];
        PointMul(generator, nonce, point, Curve);
        if(point[0] == 0x00)
        {
            throw new InvalidOperationException("The nonce produced the point at infinity; retry with a fresh nonce.");
        }

        ScalarReduce(point[1..], r, Curve);
        if(IsZero(r))
        {
            throw new InvalidOperationException("The nonce produced r = 0; retry with a fresh nonce.");
        }

        //s = k⁻¹·(e + r·d) mod n.
        Span<byte> e = stackalloc byte[ScalarSize];
        ScalarReduce(messageHash, e, Curve);
        Span<byte> rd = stackalloc byte[ScalarSize];
        ScalarMul(r, privateKey, rd, Curve);
        Span<byte> eRd = stackalloc byte[ScalarSize];
        ScalarAdd(e, rd, eRd, Curve);
        Span<byte> kInverse = stackalloc byte[ScalarSize];
        ScalarInvert(nonce, kInverse, Curve);
        ScalarMul(kInverse, eRd, s, Curve);
        if(IsZero(s))
        {
            throw new InvalidOperationException("The nonce produced s = 0; retry with a fresh nonce.");
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
}
