using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The REAL device half of the mdoc SIG circuit extracted from a credential's DeviceResponse (coordinator
/// decision 2026-06-14: the fully-real path). It reads the device public key <c>(dpkx, dpky)</c> from the
/// MSO <c>deviceKeyInfo</c> — the very bytes <see cref="MdocHashWitnessState"/> reads — and the device
/// signature <c>(r2, s2)</c> from <c>documents[0].deviceSigned.deviceAuth.deviceSignature</c> (the
/// COSE_Sign1 array's 64-byte signature bstr). The device-auth message hash <c>e2</c> (the PUBLIC wire 3,
/// the reference's <c>ne2 = to_montgomery(compute_transcript_hash)</c> in canonical form) is supplied by the
/// caller, since the byte-exact transcript-hash CBOR construction is the reference's, captured in the crown
/// gate's <c>sig_template[3]</c> fixture (reversed from little-endian to canonical big-endian per the spike).
/// </summary>
/// <remarks>
/// <para>
/// The spike (2026-06-14) validated this tuple over mdoc-00: our <see cref="EcdsaNonceRecovery"/> recovered
/// <c>R2 = (e2/s2)G + (r2/s2)Q2</c> with <c>Q2 = (dpkx, dpky)</c> and <c>R.x mod n == r2</c> exactly, and
/// .NET's <c>ECDsa.VerifyHash</c> (nistP256, <c>e2</c> as the 32-byte big-endian pre-hashed digest, 64-byte
/// <c>r||s</c>) passed. The SIG circuit's device <c>VerifyWitness3</c> column then terminates at the point at
/// infinity, so the real tuple is in-circuit valid.
/// </para>
/// <para>
/// Byte conventions (the spike's gotchas): <c>dpkx</c>/<c>dpky</c> are the RAW big-endian coordinate bytes
/// (the ECDSA integer <c>Q2</c> path uses them un-reversed; <see cref="MdocHashWitnessState"/> reverses them
/// only to form the little-endian MAC-message bytes, so the common values still match after the shared
/// convention). <c>r2</c>/<c>s2</c> are the big-endian halves of the 64-byte signature. <c>e2</c> is the
/// canonical big-endian <c>ne2</c> (the caller reverses the little-endian template element).
/// </para>
/// </remarks>
internal sealed class MdocDeviceSignature
{
    private MdocDeviceSignature(BigInteger dpkx, BigInteger dpky, BigInteger e2, BigInteger r2, BigInteger s2)
    {
        DeviceKeyX = dpkx;
        DeviceKeyY = dpky;
        DeviceHash = e2;
        SignatureR = r2;
        SignatureS = s2;
    }


    /// <summary>The device public key X coordinate <c>dpkx</c> (the real <c>Q2.X</c>, big-endian integer).</summary>
    public BigInteger DeviceKeyX { get; }

    /// <summary>The device public key Y coordinate <c>dpky</c> (the real <c>Q2.Y</c>, big-endian integer).</summary>
    public BigInteger DeviceKeyY { get; }

    /// <summary>The device-auth message hash <c>e2</c> (PUBLIC wire 3) — the canonical big-endian <c>ne2</c>.</summary>
    public BigInteger DeviceHash { get; }

    /// <summary>The device signature component <c>r2</c> (big-endian integer).</summary>
    public BigInteger SignatureR { get; }

    /// <summary>The device signature component <c>s2</c> (big-endian integer).</summary>
    public BigInteger SignatureS { get; }


    /// <summary>
    /// Extracts the real device tuple from <paramref name="mdoc"/> (the raw DeviceResponse bytes), taking the
    /// device-auth hash <paramref name="deviceHash"/> as the caller-supplied canonical big-endian <c>ne2</c>.
    /// </summary>
    public static MdocDeviceSignature Extract(byte[] mdoc, BigInteger deviceHash)
    {
        ArgumentNullException.ThrowIfNull(mdoc);

        MdocParsedDocument parsed = MdocParsedDocument.Parse(mdoc);

        //The device public key is the same bytes the hash side reads: document[TaggedMsoContentPos + 5 +
        //DeviceKeyPkxPos, 32] (and DeviceKeyPkyPos), the RAW big-endian coordinates (do NOT reverse).
        ReadOnlySpan<byte> document = parsed.Document;
        int msoBody = parsed.TaggedMsoContentPos + 5;
        BigInteger dpkx = EcdsaNonceRecovery.ToInteger(document.Slice(msoBody + parsed.DeviceKeyPkxPos, 32));
        BigInteger dpky = EcdsaNonceRecovery.ToInteger(document.Slice(msoBody + parsed.DeviceKeyPkyPos, 32));

        //The device signature: documents[0].deviceSigned.deviceAuth.deviceSignature is a COSE_Sign1 array
        //whose element [3] is the 64-byte signature bstr (r2 || s2, big-endian). Mirror the issuer walk in
        //MdocParsedDocument.Parse, but follow the deviceSigned branch.
        var walker = new MdocCborWalker(mdoc);
        MdocCborItem root = walker.Decode(0);
        MdocCborItem documents = RequireLookup(root, "documents");
        MdocCborItem firstDocument = documents.ArrayRef(0);
        MdocCborItem deviceSigned = RequireLookup(firstDocument, "deviceSigned");
        MdocCborItem deviceAuth = RequireLookup(deviceSigned, "deviceAuth");
        MdocCborItem deviceSignature = RequireLookup(deviceAuth, "deviceSignature");
        MdocCborItem signatureBstr = deviceSignature.ArrayRef(3);

        BigInteger r2 = EcdsaNonceRecovery.ToInteger(document.Slice(signatureBstr.Position, 32));
        BigInteger s2 = EcdsaNonceRecovery.ToInteger(document.Slice(signatureBstr.Position + 32, 32));

        return new MdocDeviceSignature(dpkx, dpky, deviceHash, r2, s2);
    }


    /// <summary>
    /// The independent oracle the spike used: recover <c>R2 = (e2/s2)G + (r2/s2)Q2</c> and check
    /// <c>R2.x mod n == r2</c> — the property the device <c>VerifyWitness3</c> column relies on. A fast sanity
    /// gate that the extracted tuple is a genuine nonce point before the full prove.
    /// </summary>
    public bool RecoveredNoncePointMatches()
    {
        (BigInteger X, BigInteger _) = EcdsaNonceRecovery.RecoverNoncePoint(DeviceKeyX, DeviceKeyY, DeviceHash, SignatureR, SignatureS);

        return EcdsaNonceRecovery.ModN(X) == EcdsaNonceRecovery.ModN(SignatureR);
    }


    private static MdocCborItem RequireLookup(MdocCborItem map, string key)
    {
        if(!map.TryLookup(key, out _, out MdocCborItem value))
        {
            throw new FormatException($"The map has no '{key}' entry.");
        }

        return value;
    }
}
