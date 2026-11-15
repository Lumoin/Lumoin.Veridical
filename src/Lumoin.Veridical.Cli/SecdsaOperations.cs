using Lumoin.Base;
using Lumoin.Veridical.Secdsa;
using System;
using System.Buffers;
using System.Globalization;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The SECDSA operations behind the <c>secdsa-*</c> subcommands and their MCP tools, each mapping one-to-one
/// onto a primitive of <c>Lumoin.Veridical.Secdsa</c>. Scalars are 32-byte big-endian hex, points are SEC1
/// compressed 33-byte hex, signatures and proofs are the 64-byte <c>r || s</c> hex, and the byte strings the
/// library takes (salt, shared info, challenge, record context, message) are hex. Secret scalars arrive as hex
/// the caller read from a file and are cleared after use; none is echoed.
/// </summary>
internal static class SecdsaOperations
{
    private const int ScalarBytes = SecdsaAlgorithm.ScalarSizeBytes;

    private const int PointBytes = SecdsaAlgorithm.CompressedPointSizeBytes;


    /// <summary>SECDSA split sign over a software key pair: the pin key and the hardware key produce a standard ECDSA signature.</summary>
    /// <param name="pinKeyHex">The PIN-key scalar as hex (secret).</param>
    /// <param name="hardwareKeyHex">The hardware-key scalar as hex (secret).</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <returns>The signature <c>r || s</c> as hex.</returns>
    public static string SplitSign(string pinKeyHex, string hardwareKeyHex, string messageHashHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> pinKey = stackalloc byte[ScalarBytes];
        Span<byte> hardwareKey = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(pinKeyHex, pinKey, "pin key");
            HexInput.DecodeExact(hardwareKeyHex, hardwareKey, "hardware key");
            byte[] messageHash = HexInput.Decode(messageHashHex, "message hash");
            using SecdsaSignature signature = SecdsaAlgorithm.SplitSign(
                pinKey, hardwareKey, messageHash, composition.NonceSource,
                composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarInvert, composition.ScalarReduce,
                composition.G1ScalarMultiply, composition.G1Add, BaseMemoryPool.Shared);

            return Convert.ToHexStringLower(signature.AsReadOnlySpan());
        }
        catch(InvalidOperationException error)
        {
            throw new ArgumentException(error.Message, nameof(pinKeyHex), error);
        }
        finally
        {
            pinKey.Clear();
            hardwareKey.Clear();
        }
    }


    /// <summary>Derives the split public key <c>(P·u)·G</c>.</summary>
    /// <param name="pinKeyHex">The PIN-key scalar as hex (secret).</param>
    /// <param name="hardwareKeyHex">The hardware-key scalar as hex (secret).</param>
    /// <returns>The compressed public key as hex.</returns>
    public static string DerivePublicKey(string pinKeyHex, string hardwareKeyHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> pinKey = stackalloc byte[ScalarBytes];
        Span<byte> hardwareKey = stackalloc byte[ScalarBytes];
        Span<byte> publicKey = stackalloc byte[PointBytes];
        try
        {
            HexInput.DecodeExact(pinKeyHex, pinKey, "pin key");
            HexInput.DecodeExact(hardwareKeyHex, hardwareKey, "hardware key");
            SecdsaAlgorithm.DeriveSplitPublicKey(pinKey, hardwareKey, composition.ScalarMultiply, composition.G1ScalarMultiply, publicKey);

            return Convert.ToHexStringLower(publicKey);
        }
        finally
        {
            pinKey.Clear();
            hardwareKey.Clear();
        }
    }


    /// <summary>Verifies an ECDSA signature <c>(r, s)</c> under a public key.</summary>
    /// <param name="publicKeyHex">The compressed public key as hex.</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <param name="signatureHex">The signature <c>r || s</c> as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult Verify(string publicKeyHex, string messageHashHex, string signatureHex)
    {
        try
        {
            using var composition = new SecdsaPlatformComposition();
            byte[] publicKey = HexInput.Decode(publicKeyHex, "public key");
            byte[] messageHash = HexInput.Decode(messageHashHex, "message hash");
            byte[] signature = HexInput.Decode(signatureHex, "signature");
            if(signature.Length != 2 * ScalarBytes)
            {
                throw new ArgumentException($"The signature is r || s, {2 * ScalarBytes} bytes; received {signature.Length.ToString(CultureInfo.InvariantCulture)}.", nameof(signatureHex));
            }

            bool valid = SecdsaAlgorithm.Verify(
                publicKey, messageHash, signature.AsSpan(0, ScalarBytes), signature.AsSpan(ScalarBytes, ScalarBytes),
                composition.ScalarMultiply, composition.ScalarInvert, composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add);
            string statement = $"an ECDSA signature under public key {publicKeyHex.Trim()}";

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>Recovers the nonce point <c>R</c> from a signature.</summary>
    /// <param name="publicKeyHex">The compressed public key as hex.</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <param name="signatureHex">The signature <c>r || s</c> as hex.</param>
    /// <returns>The compressed nonce point as hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid or no nonce point is recoverable.</exception>
    public static string RecoverNoncePoint(string publicKeyHex, string messageHashHex, string signatureHex)
    {
        using var composition = new SecdsaPlatformComposition();
        byte[] publicKey = HexInput.Decode(publicKeyHex, "public key");
        byte[] messageHash = HexInput.Decode(messageHashHex, "message hash");
        byte[] signature = HexInput.Decode(signatureHex, "signature");
        if(signature.Length != 2 * ScalarBytes)
        {
            throw new ArgumentException($"The signature is r || s, {2 * ScalarBytes} bytes; received {signature.Length.ToString(CultureInfo.InvariantCulture)}.", nameof(signatureHex));
        }

        Span<byte> noncePoint = stackalloc byte[PointBytes];
        if(!SecdsaAlgorithm.RecoverNoncePoint(
            publicKey, messageHash, signature.AsSpan(0, ScalarBytes), signature.AsSpan(ScalarBytes, ScalarBytes),
            composition.ScalarMultiply, composition.ScalarInvert, composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add, noncePoint))
        {
            throw new ArgumentException("No nonce point is recoverable from the signature.", nameof(signatureHex));
        }

        return Convert.ToHexStringLower(noncePoint);
    }


    /// <summary>Verifies a signature given as its nonce point <c>R</c> and <c>s</c>.</summary>
    /// <param name="publicKeyHex">The compressed public key as hex.</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <param name="noncePointHex">The compressed nonce point as hex.</param>
    /// <param name="sHex">The component <c>s</c> as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult VerifyFull(string publicKeyHex, string messageHashHex, string noncePointHex, string sHex)
    {
        try
        {
            using var composition = new SecdsaPlatformComposition();
            byte[] publicKey = HexInput.Decode(publicKeyHex, "public key");
            byte[] messageHash = HexInput.Decode(messageHashHex, "message hash");
            byte[] noncePoint = HexInput.Decode(noncePointHex, "nonce point");
            byte[] s = HexInput.Decode(sHex, "s");
            bool valid = SecdsaAlgorithm.VerifyFull(
                publicKey, messageHash, noncePoint, s,
                composition.ScalarMultiply, composition.ScalarInvert, composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add);
            string statement = $"an ECDSA signature with nonce point {noncePointHex.Trim()} under public key {publicKeyHex.Trim()}";

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>Proves that every pair <c>(G_i, D_i)</c> shares one private key <c>d</c> (<c>D_i = d·G_i</c>).</summary>
    /// <param name="witnessHex">The private key <c>d</c> as hex (secret).</param>
    /// <param name="generatorsHex">The concatenated compressed generators as hex.</param>
    /// <param name="publicKeysHex">The concatenated compressed public keys as hex, pairwise with the generators.</param>
    /// <param name="challengeHex">The challenge byte string as hex; may be empty.</param>
    /// <returns>The proof <c>r || s</c> as hex.</returns>
    public static string DlEqualityProve(string witnessHex, string generatorsHex, string publicKeysHex, string challengeHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> witness = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(witnessHex, witness, "witness");
            using DlEqualityProof proof = DlEqualityNizk.Prove(
                witness, HexInput.Decode(generatorsHex, "generators"), HexInput.Decode(publicKeysHex, "public keys"), HexInput.Decode(challengeHex, "challenge"),
                composition.NonceSource, composition.Hash, composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarReduce, composition.G1ScalarMultiply,
                BaseMemoryPool.Shared);

            return Convert.ToHexStringLower(proof.AsReadOnlySpan());
        }
        finally
        {
            witness.Clear();
        }
    }


    /// <summary>Verifies a DL-equality proof.</summary>
    /// <param name="generatorsHex">The concatenated compressed generators as hex.</param>
    /// <param name="publicKeysHex">The concatenated compressed public keys as hex.</param>
    /// <param name="challengeHex">The challenge byte string as hex; may be empty.</param>
    /// <param name="proofHex">The proof <c>r || s</c> as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult DlEqualityVerify(string generatorsHex, string publicKeysHex, string challengeHex, string proofHex)
    {
        try
        {
            using var composition = new SecdsaPlatformComposition();
            byte[] proof = HexInput.Decode(proofHex, "proof");
            if(proof.Length != DlEqualityProof.SizeBytes)
            {
                throw new ArgumentException($"The proof is r || s, {DlEqualityProof.SizeBytes} bytes; received {proof.Length.ToString(CultureInfo.InvariantCulture)}.", nameof(proofHex));
            }

            bool valid = DlEqualityNizk.Verify(
                HexInput.Decode(generatorsHex, "generators"), HexInput.Decode(publicKeysHex, "public keys"), HexInput.Decode(challengeHex, "challenge"),
                proof.AsSpan(0, ScalarBytes), proof.AsSpan(ScalarBytes, ScalarBytes),
                composition.Hash, composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add, composition.G1Negate);
            string statement = "that every generator/public-key pair shares one private key";

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>Proves the blinding relation <c>ZKP[(G,G''),(Y',Y'')]</c>.</summary>
    /// <param name="gHex">The standard base point <c>G</c> as hex.</param>
    /// <param name="gDoublePrimeHex">The point <c>G''</c> as hex.</param>
    /// <param name="yPrimeHex">The point <c>Y'</c> as hex.</param>
    /// <param name="yDoublePrimeHex">The point <c>Y''</c> as hex.</param>
    /// <param name="blindingWitnessHex">The blinding witness as hex (secret).</param>
    /// <returns>The proof <c>r || s</c> as hex.</returns>
    public static string BlindingRelationProve(string gHex, string gDoublePrimeHex, string yPrimeHex, string yDoublePrimeHex, string blindingWitnessHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> witness = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(blindingWitnessHex, witness, "blinding witness");
            using DlEqualityProof proof = SecdsaEvidence.ProveBlindingRelation(
                HexInput.Decode(gHex, "G"), HexInput.Decode(gDoublePrimeHex, "G''"), HexInput.Decode(yPrimeHex, "Y'"), HexInput.Decode(yDoublePrimeHex, "Y''"),
                witness, composition.NonceSource, composition.Hash, composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarReduce, composition.G1ScalarMultiply,
                BaseMemoryPool.Shared);

            return Convert.ToHexStringLower(proof.AsReadOnlySpan());
        }
        finally
        {
            witness.Clear();
        }
    }


    /// <summary>Verifies the blinding relation.</summary>
    /// <param name="gHex">The standard base point <c>G</c> as hex.</param>
    /// <param name="gDoublePrimeHex">The point <c>G''</c> as hex.</param>
    /// <param name="yPrimeHex">The point <c>Y'</c> as hex.</param>
    /// <param name="yDoublePrimeHex">The point <c>Y''</c> as hex.</param>
    /// <param name="proofHex">The proof <c>r || s</c> as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult BlindingRelationVerify(string gHex, string gDoublePrimeHex, string yPrimeHex, string yDoublePrimeHex, string proofHex)
    {
        try
        {
            using var composition = new SecdsaPlatformComposition();
            byte[] proof = RequireProof(proofHex);
            bool valid = SecdsaEvidence.VerifyBlindingRelation(
                HexInput.Decode(gHex, "G"), HexInput.Decode(gDoublePrimeHex, "G''"), HexInput.Decode(yPrimeHex, "Y'"), HexInput.Decode(yDoublePrimeHex, "Y''"),
                proof.AsSpan(0, ScalarBytes), proof.AsSpan(ScalarBytes, ScalarBytes),
                composition.Hash, composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add, composition.G1Negate);
            string statement = "the blinding relation ZKP[(G,G''),(Y',Y'')]";

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>Proves the control relation <c>ZKP[(H,H'),(W,W'),H(T_I)]</c>.</summary>
    /// <param name="hHex">The point <c>H</c> as hex.</param>
    /// <param name="wHex">The point <c>W</c> as hex.</param>
    /// <param name="hPrimeHex">The point <c>H'</c> as hex.</param>
    /// <param name="wPrimeHex">The point <c>W'</c> as hex.</param>
    /// <param name="controlWitnessHex">The control witness as hex (secret).</param>
    /// <param name="recordContextHex">The record context <c>T_I</c> as hex.</param>
    /// <returns>The proof <c>r || s</c> as hex.</returns>
    public static string ControlRelationProve(string hHex, string wHex, string hPrimeHex, string wPrimeHex, string controlWitnessHex, string recordContextHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> witness = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(controlWitnessHex, witness, "control witness");
            using DlEqualityProof proof = SecdsaEvidence.ProveControlRelation(
                HexInput.Decode(hHex, "H"), HexInput.Decode(wHex, "W"), HexInput.Decode(hPrimeHex, "H'"), HexInput.Decode(wPrimeHex, "W'"),
                witness, HexInput.Decode(recordContextHex, "record context"),
                composition.NonceSource, composition.Hash, composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarReduce, composition.G1ScalarMultiply,
                BaseMemoryPool.Shared);

            return Convert.ToHexStringLower(proof.AsReadOnlySpan());
        }
        finally
        {
            witness.Clear();
        }
    }


    /// <summary>Verifies the control relation.</summary>
    /// <param name="hHex">The point <c>H</c> as hex.</param>
    /// <param name="wHex">The point <c>W</c> as hex.</param>
    /// <param name="hPrimeHex">The point <c>H'</c> as hex.</param>
    /// <param name="wPrimeHex">The point <c>W'</c> as hex.</param>
    /// <param name="recordContextHex">The record context <c>T_I</c> as hex.</param>
    /// <param name="proofHex">The proof <c>r || s</c> as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult ControlRelationVerify(string hHex, string wHex, string hPrimeHex, string wPrimeHex, string recordContextHex, string proofHex)
    {
        try
        {
            using var composition = new SecdsaPlatformComposition();
            byte[] proof = RequireProof(proofHex);
            bool valid = SecdsaEvidence.VerifyControlRelation(
                HexInput.Decode(hHex, "H"), HexInput.Decode(wHex, "W"), HexInput.Decode(hPrimeHex, "H'"), HexInput.Decode(wPrimeHex, "W'"),
                HexInput.Decode(recordContextHex, "record context"),
                proof.AsSpan(0, ScalarBytes), proof.AsSpan(ScalarBytes, ScalarBytes),
                composition.Hash, composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add, composition.G1Negate);
            string statement = "the control relation ZKP[(H,H'),(W,W'),H(T_I)]";

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>Derives the ECDH-MAC key shared with a peer public point.</summary>
    /// <param name="privateKeyHex">The private scalar as hex (secret).</param>
    /// <param name="peerPublicPointHex">The peer's compressed public point as hex.</param>
    /// <param name="saltHex">The HKDF salt as hex.</param>
    /// <param name="sharedInfoHex">The HKDF info as hex.</param>
    /// <returns>The MAC key as hex (secret).</returns>
    public static string EcdhMacDeriveKey(string privateKeyHex, string peerPublicPointHex, string saltHex, string sharedInfoHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> privateKey = stackalloc byte[ScalarBytes];
        Span<byte> macKey = stackalloc byte[EcdhMacAlgorithm.MacKeySizeBytes];
        try
        {
            HexInput.DecodeExact(privateKeyHex, privateKey, "private key");
            EcdhMacAlgorithm.DeriveMacKey(
                privateKey, HexInput.Decode(peerPublicPointHex, "peer public point"), HexInput.Decode(saltHex, "salt"), HexInput.Decode(sharedInfoHex, "shared info"),
                composition.Hkdf, composition.G1ScalarMultiply, macKey);

            return Convert.ToHexStringLower(macKey);
        }
        finally
        {
            privateKey.Clear();
            macKey.Clear();
        }
    }


    /// <summary>Computes the ECDH-MAC of a message under a prover key and the verifier's ephemeral public key.</summary>
    /// <param name="privateKeyHex">The prover's private scalar as hex (secret).</param>
    /// <param name="verifierEphemeralPublicKeyHex">The verifier's ephemeral compressed public key as hex.</param>
    /// <param name="saltHex">The HKDF salt as hex.</param>
    /// <param name="sharedInfoHex">The HKDF info as hex.</param>
    /// <param name="messageHex">The message as hex.</param>
    /// <returns>The MAC as hex.</returns>
    public static string EcdhMacSign(string privateKeyHex, string verifierEphemeralPublicKeyHex, string saltHex, string sharedInfoHex, string messageHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> privateKey = stackalloc byte[ScalarBytes];
        Span<byte> mac = stackalloc byte[EcdhMacAlgorithm.MacSizeBytes];
        try
        {
            HexInput.DecodeExact(privateKeyHex, privateKey, "private key");
            EcdhMacAlgorithm.Sign(
                privateKey, HexInput.Decode(verifierEphemeralPublicKeyHex, "verifier ephemeral public key"), HexInput.Decode(saltHex, "salt"),
                HexInput.Decode(sharedInfoHex, "shared info"), HexInput.Decode(messageHex, "message"),
                composition.Hkdf, composition.Hmac, composition.G1ScalarMultiply, mac);

            return Convert.ToHexStringLower(mac);
        }
        finally
        {
            privateKey.Clear();
        }
    }


    /// <summary>Verifies an ECDH-MAC with the verifier's ephemeral private key.</summary>
    /// <param name="proverPublicKeyHex">The prover's compressed public key as hex.</param>
    /// <param name="verifierEphemeralPrivateKeyHex">The verifier's ephemeral private scalar as hex (secret).</param>
    /// <param name="saltHex">The HKDF salt as hex.</param>
    /// <param name="sharedInfoHex">The HKDF info as hex.</param>
    /// <param name="messageHex">The message as hex.</param>
    /// <param name="macHex">The MAC as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult EcdhMacVerify(string proverPublicKeyHex, string verifierEphemeralPrivateKeyHex, string saltHex, string sharedInfoHex, string messageHex, string macHex)
    {
        Span<byte> privateKey = stackalloc byte[ScalarBytes];
        try
        {
            using var composition = new SecdsaPlatformComposition();
            HexInput.DecodeExact(verifierEphemeralPrivateKeyHex, privateKey, "verifier ephemeral private key");
            bool valid = EcdhMacAlgorithm.Verify(
                HexInput.Decode(proverPublicKeyHex, "prover public key"), privateKey, HexInput.Decode(saltHex, "salt"), HexInput.Decode(sharedInfoHex, "shared info"),
                HexInput.Decode(messageHex, "message"), HexInput.Decode(macHex, "mac"),
                composition.Hkdf, composition.Hmac, composition.G1ScalarMultiply);
            string statement = $"an ECDH-MAC under prover public key {proverPublicKeyHex.Trim()}";

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
        finally
        {
            privateKey.Clear();
        }
    }


    /// <summary>Computes the ECDH-MAC from the wallet and WSCA key shares and the base key, as the split signer does.</summary>
    /// <param name="walletKeyShareHex">The wallet key share as hex (secret).</param>
    /// <param name="wscaKeyShareHex">The WSCA key share as hex (secret).</param>
    /// <param name="baseKeyHex">The base key as hex (secret).</param>
    /// <param name="verifierEphemeralPublicKeyHex">The verifier's ephemeral compressed public key as hex.</param>
    /// <param name="saltHex">The HKDF salt as hex.</param>
    /// <param name="sharedInfoHex">The HKDF info as hex.</param>
    /// <param name="messageHex">The message as hex.</param>
    /// <returns>The MAC as hex.</returns>
    public static string EcdhMacSplitSign(string walletKeyShareHex, string wscaKeyShareHex, string baseKeyHex, string verifierEphemeralPublicKeyHex, string saltHex, string sharedInfoHex, string messageHex)
    {
        using var composition = new SecdsaPlatformComposition();
        Span<byte> walletShare = stackalloc byte[ScalarBytes];
        Span<byte> wscaShare = stackalloc byte[ScalarBytes];
        Span<byte> baseKey = stackalloc byte[ScalarBytes];
        Span<byte> mac = stackalloc byte[EcdhMacAlgorithm.MacSizeBytes];
        try
        {
            HexInput.DecodeExact(walletKeyShareHex, walletShare, "wallet key share");
            HexInput.DecodeExact(wscaKeyShareHex, wscaShare, "WSCA key share");
            HexInput.DecodeExact(baseKeyHex, baseKey, "base key");
            EcdhMacAlgorithm.SplitSign(
                walletShare, wscaShare, baseKey, HexInput.Decode(verifierEphemeralPublicKeyHex, "verifier ephemeral public key"), HexInput.Decode(saltHex, "salt"),
                HexInput.Decode(sharedInfoHex, "shared info"), HexInput.Decode(messageHex, "message"),
                composition.Hkdf, composition.Hmac, composition.G1ScalarMultiply, mac);

            return Convert.ToHexStringLower(mac);
        }
        finally
        {
            walletShare.Clear();
            wscaShare.Clear();
            baseKey.Clear();
        }
    }


    private static byte[] RequireProof(string proofHex)
    {
        byte[] proof = HexInput.Decode(proofHex, "proof");
        if(proof.Length != DlEqualityProof.SizeBytes)
        {
            throw new ArgumentException($"The proof is r || s, {DlEqualityProof.SizeBytes} bytes; received {proof.Length.ToString(CultureInfo.InvariantCulture)}.", nameof(proofHex));
        }

        return proof;
    }
}
