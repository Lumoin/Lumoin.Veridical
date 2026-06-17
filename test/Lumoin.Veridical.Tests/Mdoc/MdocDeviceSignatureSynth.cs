using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The SYNTHESIZED device half of the mdoc SIG circuit (coordinator decision OQ1): a self-consistent
/// P-256/SHA-256 ECDSA verification tuple <c>(dpkx, dpky, e2, r2, s2)</c> standing in for the credential's
/// real device-key signature. The SIG circuit only checks the internal consistency of each
/// <c>VerifyWitness3</c> column (it does not bind the device key to any public value, see
/// <c>tempdocs/longfellow-zk-reference/lib/circuits/mdoc/mdoc_zk.cc</c>), so the device tuple needs only to
/// be a genuine ECDSA verification: <c>e2</c> is the device/transcript message hash (the PUBLIC wire 3,
/// OQ6 — distinct from the issuer MSO hash <c>e_</c>), <c>(dpkx, dpky)</c> is the device public key, and
/// <c>(r2, s2)</c> is a signature over <c>e2</c> under that key such that the recovered nonce point
/// <c>R2 = (e2/s2)·G + (r2/s2)·Q2</c> has <c>R2.x mod n == r2</c>.
/// </summary>
/// <remarks>
/// <para>
/// A fixed device private key <c>d2</c> (distinct from the issuer-test key so the two halves are visibly
/// independent) gives <c>Q2 = d2·G</c> via <see cref="EcdsaNonceRecovery.ScalarMultiply"/>; the device hash is
/// <c>e2 = SHA256(deviceMessage)</c>; and the signature is a DETERMINISTIC ECDSA over a fixed nonce <c>k</c> —
/// <c>r2 = (k·G).x mod n</c>, <c>s2 = k⁻¹·(e2 + r2·d2) mod n</c> — NOT <see cref="ECDsa.SignData"/>, whose
/// random nonce made the synthesized signature (and therefore the witness column and the whole proof envelope)
/// vary run-to-run. A fixed <c>k</c> is sound for this fixture (one fixed message under one fixed key, so no
/// nonce reuse across messages). The tuple is a genuine ECDSA verification (<c>R2.x mod n == r2</c>), confirmed
/// by <see cref="Verify"/> through .NET's own <see cref="ECDsa.VerifyData"/>.
/// </para>
/// <para>
/// The fixed device message stands in for the full <c>compute_transcript_hash</c> CBOR construction
/// (mdoc_witness.h:437-490); the only circuit precondition on <c>e2</c> is <c>e2 != 0</c>
/// (mdoc_zk.cc:196-201), trivially satisfied by a SHA-256 digest. Byte-exact transcript fidelity is the
/// deferred Docker reverse-gate concern.
/// </para>
/// </remarks>
internal sealed class MdocDeviceSignatureSynth
{
    private const int ScalarSize = 32;

    //A deterministic P-256 device private key d2, well below n, distinct from the issuer-test key
    //(EcdsaSignatureWitnessTests.PrivateKeyHex) so the synthesized device half is visibly independent.
    private const string DevicePrivateKeyHex = "0fedcba9876543210123456789abcdeffedcba98765432100f1e2d3c4b5a6978";

    //A fixed device message standing in for the transcript-derived DeviceAuthenticationBytes. e2 is its
    //SHA-256, which is non-zero with overwhelming probability (the only circuit precondition on e2).
    private static ReadOnlySpan<byte> DeviceMessage => "Lumoin.Veridical synthesized mdoc device authentication."u8;

    //A fixed ECDSA nonce k for the DETERMINISTIC device signature (well below n, distinct from d2). A fixed k
    //is sound here because the device signs exactly one fixed message under one fixed key — no nonce reuse
    //across distinct messages. This replaces .NET's random-nonce SignData so the synthesized signature (and so
    //the witness column and the proof envelope) is reproducible run-to-run.
    private const string DeviceNonceHex = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff";


    private MdocDeviceSignatureSynth(BigInteger dpkx, BigInteger dpky, BigInteger e2, BigInteger r2, BigInteger s2, byte[] message)
    {
        DeviceKeyX = dpkx;
        DeviceKeyY = dpky;
        DeviceHash = e2;
        SignatureR = r2;
        SignatureS = s2;
        Message = message;
    }


    /// <summary>The device public key X coordinate <c>dpkx</c> (the synthesized <c>Q2.X</c>).</summary>
    public BigInteger DeviceKeyX { get; }

    /// <summary>The device public key Y coordinate <c>dpky</c> (the synthesized <c>Q2.Y</c>).</summary>
    public BigInteger DeviceKeyY { get; }

    /// <summary>The device/transcript hash <c>e2</c> (PUBLIC wire 3) — <c>SHA256(deviceMessage)</c>.</summary>
    public BigInteger DeviceHash { get; }

    /// <summary>The device signature component <c>r2</c>.</summary>
    public BigInteger SignatureR { get; }

    /// <summary>The device signature component <c>s2</c>.</summary>
    public BigInteger SignatureS { get; }

    /// <summary>The fixed device message <c>(r2, s2)</c> sign and whose SHA-256 is <c>e2</c>.</summary>
    public byte[] Message { get; }


    /// <summary>
    /// Synthesizes the device tuple deterministically from the fixed device key and message. The returned
    /// tuple is a genuine .NET ECDSA verification (confirmed by <see cref="Verify"/>), so its
    /// <c>VerifyWitness3</c> column terminates at the point at infinity.
    /// </summary>
    public static MdocDeviceSignatureSynth Create()
    {
        //Q2 = d2·G, derived through the reference so the device key is self-contained and matches CreateKey.
        BigInteger d2 = EcdsaNonceRecovery.ToInteger(Convert.FromHexString(DevicePrivateKeyHex));
        (BigInteger dpkx, BigInteger dpky) = EcdsaNonceRecovery.ScalarMultiply(d2, EcdsaNonceRecovery.G);

        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(DeviceMessage, digest);
        BigInteger e2 = EcdsaNonceRecovery.ToInteger(digest);

        //Deterministic ECDSA over the fixed nonce k: r2 = (k·G).x mod n; s2 = k⁻¹·(e2 + r2·d2) mod n. No
        //random nonce, so (r2, s2) — and therefore the witness column and the proof envelope — are stable.
        BigInteger deviceNonce = EcdsaNonceRecovery.ToInteger(Convert.FromHexString(DeviceNonceHex));
        (BigInteger noncePointX, BigInteger _) = EcdsaNonceRecovery.ScalarMultiply(deviceNonce, EcdsaNonceRecovery.G);
        BigInteger r2 = EcdsaNonceRecovery.ModN(noncePointX);
        BigInteger s2 = EcdsaNonceRecovery.ModN(EcdsaNonceRecovery.ModInvN(deviceNonce) * (e2 + (r2 * d2)));

        return new MdocDeviceSignatureSynth(dpkx, dpky, e2, r2, s2, DeviceMessage.ToArray());
    }


    /// <summary>
    /// The independent .NET oracle confirming the synthesized tuple is a genuine nonce point: .NET's
    /// verifier recomputes <c>R2 = (e2/s2)·G + (r2/s2)·Q2</c> and checks <c>R2.x mod n == r2</c>, exactly
    /// the property <c>VerifyWitness3</c> relies on (mirrors
    /// <c>RecoveredNoncePointMatchesTheDotNetSignature</c>).
    /// </summary>
    public bool Verify()
    {
        using ECDsa ecdsa = CreateKey();
        Span<byte> signature = stackalloc byte[2 * ScalarSize];
        EcdsaNonceRecovery.Bytes(SignatureR).CopyTo(signature[..ScalarSize]);
        EcdsaNonceRecovery.Bytes(SignatureS).CopyTo(signature[ScalarSize..]);

        return ecdsa.VerifyData(Message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }


    //Import the device key from the fixed scalar d2, deriving Q2 = d2·G through the reference so the
    //imported key is complete and deterministic (the established EcdsaSignatureWitnessTests.CreateKey pattern).
    private static ECDsa CreateKey()
    {
        byte[] d = Convert.FromHexString(DevicePrivateKeyHex);
        (BigInteger X, BigInteger Y) q = EcdsaNonceRecovery.ScalarMultiply(EcdsaNonceRecovery.ToInteger(d), EcdsaNonceRecovery.G);
        ECParameters parameters = new()
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
            Q = new ECPoint
            {
                X = EcdsaNonceRecovery.Bytes(q.X),
                Y = EcdsaNonceRecovery.Bytes(q.Y),
            },
        };

        return ECDsa.Create(parameters);
    }


    private static BigInteger ToInteger(byte[] bytes) => new(bytes, isUnsigned: true, isBigEndian: true);
}
