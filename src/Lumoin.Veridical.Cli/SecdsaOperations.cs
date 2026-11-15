using Lumoin.Base;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> pinBytes = stackalloc byte[ScalarBytes];
        Span<byte> hardwareBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(pinKeyHex, pinBytes, "pin key");
            HexInput.DecodeExact(hardwareKeyHex, hardwareBytes, "hardware key");
            using PinKey pinKey = PinKey.FromCanonical(pinBytes, pool);
            using PrivateScalar hardwareKey = PrivateScalar.FromCanonical(hardwareBytes, pool);
            using MessageHash messageHash = MessageHash.FromCanonical(HexInput.Decode(messageHashHex, "message hash"), pool);
            using SecdsaSignature signature = SecdsaAlgorithm.SplitSign(
                pinKey, hardwareKey, messageHash, composition.NonceSource,
                composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarInvert, composition.ScalarReduce,
                composition.G1ScalarMultiply, composition.G1Add, pool);

            return Convert.ToHexStringLower(signature.AsReadOnlySpan());
        }
        catch(InvalidOperationException error)
        {
            throw new ArgumentException(error.Message, nameof(pinKeyHex), error);
        }
        finally
        {
            pinBytes.Clear();
            hardwareBytes.Clear();
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> witnessBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(witnessHex, witnessBytes, "witness");
            using PrivateScalar witness = PrivateScalar.FromCanonical(witnessBytes, pool);
            using P256PointVector generators = P256PointVector.FromCanonical(HexInput.Decode(generatorsHex, "generators"), pool);
            using P256PointVector publicKeys = P256PointVector.FromCanonical(HexInput.Decode(publicKeysHex, "public keys"), pool);
            using AdditionalData challenge = AdditionalData.FromCanonical(HexInput.Decode(challengeHex, "challenge"), AdditionalDataRole.Authenticated, pool);
            using DlEqualityProof proof = DlEqualityNizk.Prove(
                witness, generators, publicKeys, challenge,
                composition.NonceSource, composition.Hash, composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarReduce, composition.G1ScalarMultiply,
                pool);

            return Convert.ToHexStringLower(proof.AsReadOnlySpan());
        }
        finally
        {
            witnessBytes.Clear();
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
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            using DlEqualityProof proof = DlEqualityProof.FromCanonical(RequireProof(proofHex), pool);
            using P256PointVector generators = P256PointVector.FromCanonical(HexInput.Decode(generatorsHex, "generators"), pool);
            using P256PointVector publicKeys = P256PointVector.FromCanonical(HexInput.Decode(publicKeysHex, "public keys"), pool);
            using AdditionalData challenge = AdditionalData.FromCanonical(HexInput.Decode(challengeHex, "challenge"), AdditionalDataRole.Authenticated, pool);
            bool valid = DlEqualityNizk.Verify(
                generators, publicKeys, challenge, proof,
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> witnessBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(blindingWitnessHex, witnessBytes, "blinding witness");
            using PrivateScalar witness = PrivateScalar.FromCanonical(witnessBytes, pool);
            using G1Point g = G1Point.FromCanonical(HexInput.Decode(gHex, "G"), CurveParameterSet.P256, pool);
            using G1Point gDoublePrime = G1Point.FromCanonical(HexInput.Decode(gDoublePrimeHex, "G''"), CurveParameterSet.P256, pool);
            using G1Point yPrime = G1Point.FromCanonical(HexInput.Decode(yPrimeHex, "Y'"), CurveParameterSet.P256, pool);
            using G1Point yDoublePrime = G1Point.FromCanonical(HexInput.Decode(yDoublePrimeHex, "Y''"), CurveParameterSet.P256, pool);
            using DlEqualityProof proof = SecdsaEvidence.ProveBlindingRelation(
                g, gDoublePrime, yPrime, yDoublePrime,
                witness, composition.NonceSource, composition.Hash, composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarReduce, composition.G1ScalarMultiply,
                pool);

            return Convert.ToHexStringLower(proof.AsReadOnlySpan());
        }
        finally
        {
            witnessBytes.Clear();
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
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            using DlEqualityProof proof = DlEqualityProof.FromCanonical(RequireProof(proofHex), pool);
            using G1Point g = G1Point.FromCanonical(HexInput.Decode(gHex, "G"), CurveParameterSet.P256, pool);
            using G1Point gDoublePrime = G1Point.FromCanonical(HexInput.Decode(gDoublePrimeHex, "G''"), CurveParameterSet.P256, pool);
            using G1Point yPrime = G1Point.FromCanonical(HexInput.Decode(yPrimeHex, "Y'"), CurveParameterSet.P256, pool);
            using G1Point yDoublePrime = G1Point.FromCanonical(HexInput.Decode(yDoublePrimeHex, "Y''"), CurveParameterSet.P256, pool);
            bool valid = SecdsaEvidence.VerifyBlindingRelation(
                g, gDoublePrime, yPrime, yDoublePrime, proof,
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> witnessBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(controlWitnessHex, witnessBytes, "control witness");
            using PrivateScalar witness = PrivateScalar.FromCanonical(witnessBytes, pool);
            using G1Point h = G1Point.FromCanonical(HexInput.Decode(hHex, "H"), CurveParameterSet.P256, pool);
            using G1Point w = G1Point.FromCanonical(HexInput.Decode(wHex, "W"), CurveParameterSet.P256, pool);
            using G1Point hPrime = G1Point.FromCanonical(HexInput.Decode(hPrimeHex, "H'"), CurveParameterSet.P256, pool);
            using G1Point wPrime = G1Point.FromCanonical(HexInput.Decode(wPrimeHex, "W'"), CurveParameterSet.P256, pool);
            using AdditionalData recordContext = AdditionalData.FromCanonical(HexInput.Decode(recordContextHex, "record context"), AdditionalDataRole.Authenticated, pool);
            using DlEqualityProof proof = SecdsaEvidence.ProveControlRelation(
                h, w, hPrime, wPrime, witness, recordContext,
                composition.NonceSource, composition.Hash, composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarReduce, composition.G1ScalarMultiply,
                pool);

            return Convert.ToHexStringLower(proof.AsReadOnlySpan());
        }
        finally
        {
            witnessBytes.Clear();
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
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            using DlEqualityProof proof = DlEqualityProof.FromCanonical(RequireProof(proofHex), pool);
            using G1Point h = G1Point.FromCanonical(HexInput.Decode(hHex, "H"), CurveParameterSet.P256, pool);
            using G1Point w = G1Point.FromCanonical(HexInput.Decode(wHex, "W"), CurveParameterSet.P256, pool);
            using G1Point hPrime = G1Point.FromCanonical(HexInput.Decode(hPrimeHex, "H'"), CurveParameterSet.P256, pool);
            using G1Point wPrime = G1Point.FromCanonical(HexInput.Decode(wPrimeHex, "W'"), CurveParameterSet.P256, pool);
            using AdditionalData recordContext = AdditionalData.FromCanonical(HexInput.Decode(recordContextHex, "record context"), AdditionalDataRole.Authenticated, pool);
            bool valid = SecdsaEvidence.VerifyControlRelation(
                h, w, hPrime, wPrime, recordContext, proof,
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> privateBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(privateKeyHex, privateBytes, "private key");
            using PrivateScalar privateKey = PrivateScalar.FromCanonical(privateBytes, pool);
            using G1Point peerPublicPoint = G1Point.FromCanonical(HexInput.Decode(peerPublicPointHex, "peer public point"), CurveParameterSet.P256, pool);
            using MacSalt salt = MacSalt.FromCanonical(HexInput.Decode(saltHex, "salt"), pool);
            using SharedInfo sharedInfo = SharedInfo.FromCanonical(HexInput.Decode(sharedInfoHex, "shared info"), pool);
            using MacKey macKey = EcdhMacAlgorithm.DeriveMacKey(
                privateKey, peerPublicPoint, salt, sharedInfo, composition.Hkdf, composition.G1ScalarMultiply, EcdhMacAlgorithm.MacKeySizeBytes, pool);

            return Convert.ToHexStringLower(macKey.AsReadOnlySpan());
        }
        finally
        {
            privateBytes.Clear();
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> privateBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(privateKeyHex, privateBytes, "private key");
            using PrivateScalar privateKey = PrivateScalar.FromCanonical(privateBytes, pool);
            using G1Point verifierEphemeralPublicKey = G1Point.FromCanonical(HexInput.Decode(verifierEphemeralPublicKeyHex, "verifier ephemeral public key"), CurveParameterSet.P256, pool);
            using MacSalt salt = MacSalt.FromCanonical(HexInput.Decode(saltHex, "salt"), pool);
            using SharedInfo sharedInfo = SharedInfo.FromCanonical(HexInput.Decode(sharedInfoHex, "shared info"), pool);
            using MacTag mac = EcdhMacAlgorithm.Sign(
                privateKey, verifierEphemeralPublicKey, salt, sharedInfo, HexInput.Decode(messageHex, "message"),
                composition.Hkdf, composition.Hmac, composition.G1ScalarMultiply, pool);

            return Convert.ToHexStringLower(mac.AsReadOnlySpan());
        }
        finally
        {
            privateBytes.Clear();
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
        Span<byte> privateBytes = stackalloc byte[ScalarBytes];
        try
        {
            using var composition = new SecdsaPlatformComposition();
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            HexInput.DecodeExact(verifierEphemeralPrivateKeyHex, privateBytes, "verifier ephemeral private key");
            using PrivateScalar privateKey = PrivateScalar.FromCanonical(privateBytes, pool);
            using G1Point proverPublicKey = G1Point.FromCanonical(HexInput.Decode(proverPublicKeyHex, "prover public key"), CurveParameterSet.P256, pool);
            using MacSalt salt = MacSalt.FromCanonical(HexInput.Decode(saltHex, "salt"), pool);
            using SharedInfo sharedInfo = SharedInfo.FromCanonical(HexInput.Decode(sharedInfoHex, "shared info"), pool);
            using MacTag mac = MacTag.FromCanonical(HexInput.Decode(macHex, "mac"), pool);
            bool valid = EcdhMacAlgorithm.Verify(
                proverPublicKey, privateKey, salt, sharedInfo, HexInput.Decode(messageHex, "message"), mac,
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
            privateBytes.Clear();
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> walletBytes = stackalloc byte[ScalarBytes];
        Span<byte> wscaBytes = stackalloc byte[ScalarBytes];
        Span<byte> baseBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(walletKeyShareHex, walletBytes, "wallet key share");
            HexInput.DecodeExact(wscaKeyShareHex, wscaBytes, "WSCA key share");
            HexInput.DecodeExact(baseKeyHex, baseBytes, "base key");
            using PrivateScalar walletShare = PrivateScalar.FromCanonical(walletBytes, pool);
            using PrivateScalar wscaShare = PrivateScalar.FromCanonical(wscaBytes, pool);
            using PrivateScalar baseKey = PrivateScalar.FromCanonical(baseBytes, pool);
            using G1Point verifierEphemeralPublicKey = G1Point.FromCanonical(HexInput.Decode(verifierEphemeralPublicKeyHex, "verifier ephemeral public key"), CurveParameterSet.P256, pool);
            using MacSalt salt = MacSalt.FromCanonical(HexInput.Decode(saltHex, "salt"), pool);
            using SharedInfo sharedInfo = SharedInfo.FromCanonical(HexInput.Decode(sharedInfoHex, "shared info"), pool);
            using MacTag mac = EcdhMacAlgorithm.SplitSign(
                walletShare, wscaShare, baseKey, verifierEphemeralPublicKey, salt, sharedInfo, HexInput.Decode(messageHex, "message"),
                composition.Hkdf, composition.Hmac, composition.G1ScalarMultiply, pool);

            return Convert.ToHexStringLower(mac.AsReadOnlySpan());
        }
        finally
        {
            walletBytes.Clear();
            wscaBytes.Clear();
            baseBytes.Clear();
        }
    }


    /// <summary>
    /// SECDSA split sign, prepare phase (Algorithm 2 step 3): computes the blinded representative
    /// <c>e' = P⁻¹·e</c> that is sent to the key holder's raw ECDSA sign.
    /// </summary>
    /// <param name="pinKeyHex">The PIN-key scalar as hex (secret).</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <returns>The blinded representative as hex; sensitive, because <c>e'</c> together with <c>e</c> reveals <c>P</c>.</returns>
    /// <exception cref="ArgumentException">An input is invalid.</exception>
    public static string SplitSignPrepare(string pinKeyHex, string messageHashHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> pinBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(pinKeyHex, pinBytes, "pin key");
            using PinKey pinKey = PinKey.FromCanonical(pinBytes, pool);
            using MessageHash messageHash = MessageHash.FromCanonical(HexInput.Decode(messageHashHex, "message hash"), pool);
            using BlindedHash blinded = SecdsaAlgorithm.PrepareSplitSign(
                pinKey, messageHash, composition.ScalarMultiply, composition.ScalarInvert, composition.ScalarReduce, pool);

            return Convert.ToHexStringLower(blinded.AsReadOnlySpan());
        }
        finally
        {
            pinBytes.Clear();
        }
    }


    /// <summary>
    /// SECDSA split sign, complete phase (Algorithm 2 step 8): masks the key holder's raw signature
    /// <c>(r, s₀)</c> with the PIN key and releases the signature only if it verifies under the public key.
    /// </summary>
    /// <param name="pinKeyHex">The PIN-key scalar as hex (secret).</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <param name="publicKeyHex">The composite public key as hex.</param>
    /// <param name="rawSignatureHex">The key holder's raw signature <c>r || s₀</c> as hex (<c>s₀</c> is secret).</param>
    /// <returns>The signature <c>r || s</c> as hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid, or the key holder's answer is rejected.</exception>
    public static string SplitSignComplete(string pinKeyHex, string messageHashHex, string publicKeyHex, string rawSignatureHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> pinBytes = stackalloc byte[ScalarBytes];
        Span<byte> rawBytes = stackalloc byte[2 * ScalarBytes];
        try
        {
            HexInput.DecodeExact(pinKeyHex, pinBytes, "pin key");
            HexInput.DecodeExact(rawSignatureHex, rawBytes, "raw signature");
            using PinKey pinKey = PinKey.FromCanonical(pinBytes, pool);
            using MessageHash messageHash = MessageHash.FromCanonical(HexInput.Decode(messageHashHex, "message hash"), pool);
            using G1Point publicKey = G1Point.FromCanonical(HexInput.Decode(publicKeyHex, "public key"), CurveParameterSet.P256, pool);
            using RawSignature rawSignature = RawSignature.FromCanonical(rawBytes, pool);
            using SecdsaSignature signature = SecdsaAlgorithm.CompleteSplitSign(
                pinKey, messageHash, publicKey, rawSignature,
                composition.ScalarMultiply, composition.ScalarInvert, composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add, pool);

            return Convert.ToHexStringLower(signature.AsReadOnlySpan());
        }
        catch(InvalidOperationException error)
        {
            throw new ArgumentException(error.Message, nameof(rawSignatureHex), error);
        }
        finally
        {
            pinBytes.Clear();
            rawBytes.Clear();
        }
    }


    /// <summary>ECDH-MAC prepare phase (Algorithm 16 step 1): validates the verifier's ephemeral public key and returns the canonical point to send to the key holder.</summary>
    /// <param name="peerPublicKeyHex">The verifier's ephemeral compressed public key as hex.</param>
    /// <returns>The validated compressed point as hex.</returns>
    /// <exception cref="ArgumentException">The point is malformed, the point at infinity, or not on the curve.</exception>
    public static string EcdhMacPrepare(string peerPublicKeyHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        try
        {
            using G1Point peerPublicPoint = G1Point.FromCanonical(HexInput.Decode(peerPublicKeyHex, "peer public key"), CurveParameterSet.P256, pool);
            using G1Point keyHolderInput = EcdhMacAlgorithm.PrepareKeyAgreement(peerPublicPoint, composition.G1ScalarMultiply, pool);

            return Convert.ToHexStringLower(keyHolderInput.AsReadOnlySpan());
        }
        catch(InvalidOperationException error)
        {
            throw new ArgumentException(error.Message, nameof(peerPublicKeyHex), error);
        }
    }


    /// <summary>Multiplies a point by a key share, the wallet and WSCA steps of the split ECDH-MAC (Algorithm 12 steps 2 and 4).</summary>
    /// <param name="keyShareHex">The key-share scalar as hex (secret).</param>
    /// <param name="pointHex">The compressed point as hex.</param>
    /// <returns>The product as a compressed point in hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid, or the point is not on the curve.</exception>
    public static string EcdhMacApplyKeyShare(string keyShareHex, string pointHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> shareBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(keyShareHex, shareBytes, "key share");
            using PrivateScalar keyShare = PrivateScalar.FromCanonical(shareBytes, pool);
            using G1Point point = G1Point.FromCanonical(HexInput.Decode(pointHex, "point"), CurveParameterSet.P256, pool);
            using G1Point product = EcdhMacAlgorithm.ApplyKeyShare(keyShare, point, composition.G1ScalarMultiply, pool);

            return Convert.ToHexStringLower(product.AsReadOnlySpan());
        }
        catch(InvalidOperationException error)
        {
            throw new ArgumentException(error.Message, nameof(pointHex), error);
        }
        finally
        {
            shareBytes.Clear();
        }
    }


    /// <summary>ECDH-MAC complete phase for signing (Algorithm 16 steps 4 and 5): derives the key from the key holder's shared secret and computes the MAC.</summary>
    /// <param name="sharedSecretHex">The 32-byte shared secret <c>Z_AB</c> as hex (secret).</param>
    /// <param name="saltHex">The HKDF salt as hex.</param>
    /// <param name="sharedInfoHex">The HKDF info as hex.</param>
    /// <param name="messageHex">The message as hex.</param>
    /// <returns>The MAC as hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid.</exception>
    public static string EcdhMacCompleteSign(string sharedSecretHex, string saltHex, string sharedInfoHex, string messageHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> secretBytes = stackalloc byte[EcdhMacAlgorithm.SharedSecretSizeBytes];
        try
        {
            HexInput.DecodeExact(sharedSecretHex, secretBytes, "shared secret");
            using SharedSecret sharedSecret = SharedSecret.FromCanonical(secretBytes, pool);
            using MacSalt salt = MacSalt.FromCanonical(HexInput.Decode(saltHex, "salt"), pool);
            using SharedInfo sharedInfo = SharedInfo.FromCanonical(HexInput.Decode(sharedInfoHex, "shared info"), pool);
            using MacTag mac = EcdhMacAlgorithm.CompleteSign(
                salt, sharedSecret, sharedInfo, HexInput.Decode(messageHex, "message"), composition.Hkdf, composition.Hmac, pool);

            return Convert.ToHexStringLower(mac.AsReadOnlySpan());
        }
        finally
        {
            secretBytes.Clear();
        }
    }


    /// <summary>ECDH-MAC complete phase for verification (Algorithm 17 steps 3 to 5): derives the key from the verifier's key holder's shared secret and compares the MAC in constant time.</summary>
    /// <param name="sharedSecretHex">The 32-byte shared secret <c>Z_AB</c> as hex (secret).</param>
    /// <param name="saltHex">The HKDF salt as hex.</param>
    /// <param name="sharedInfoHex">The HKDF info as hex.</param>
    /// <param name="messageHex">The message as hex.</param>
    /// <param name="macHex">The MAC as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult EcdhMacCompleteVerify(string sharedSecretHex, string saltHex, string sharedInfoHex, string messageHex, string macHex)
    {
        const string statement = "an ECDH-MAC under the supplied shared secret";
        Span<byte> secretBytes = stackalloc byte[EcdhMacAlgorithm.SharedSecretSizeBytes];
        try
        {
            using var composition = new SecdsaPlatformComposition();
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            HexInput.DecodeExact(sharedSecretHex, secretBytes, "shared secret");
            using SharedSecret sharedSecret = SharedSecret.FromCanonical(secretBytes, pool);
            using MacSalt salt = MacSalt.FromCanonical(HexInput.Decode(saltHex, "salt"), pool);
            using SharedInfo sharedInfo = SharedInfo.FromCanonical(HexInput.Decode(sharedInfoHex, "shared info"), pool);
            using MacTag mac = MacTag.FromCanonical(HexInput.Decode(macHex, "mac"), pool);
            bool valid = EcdhMacAlgorithm.CompleteVerify(
                salt, sharedSecret, sharedInfo, HexInput.Decode(messageHex, "message"), mac, composition.Hkdf, composition.Hmac);

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
        finally
        {
            secretBytes.Clear();
        }
    }


    /// <summary>Verifies an ECDH-MAC under a MAC key the key holder derived itself, comparing in constant time.</summary>
    /// <param name="macKeyHex">The MAC key as hex (secret).</param>
    /// <param name="messageHex">The message as hex.</param>
    /// <param name="macHex">The MAC as hex.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult EcdhMacVerifyMac(string macKeyHex, string messageHex, string macHex)
    {
        const string statement = "an ECDH-MAC under the supplied MAC key";
        try
        {
            using var composition = new SecdsaPlatformComposition();
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            using MacKey macKey = MacKey.FromCanonical(HexInput.Decode(macKeyHex, "MAC key"), pool);
            using MacTag mac = MacTag.FromCanonical(HexInput.Decode(macHex, "mac"), pool);
            bool valid = EcdhMacAlgorithm.VerifyMac(macKey, HexInput.Decode(messageHex, "message"), mac, composition.Hmac);

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
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
