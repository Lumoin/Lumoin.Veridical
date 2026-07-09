using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The public dual-field mdoc facade: a curated, serialization-free surface over the byte-conformant
/// google/longfellow-zk prover and verifier. <see cref="Prove"/> drives one shared Fiat-Shamir transcript
/// across the GF(2^128) hash circuit and the P-256 base-field signature circuit — committing both, binding
/// them with the cross-field MAC key, and proving both — into a pooled <see cref="LongfellowMdocProof"/>;
/// <see cref="Verify"/> replays that ceremony to a <see cref="LongfellowMdocVerdict"/>.
/// </summary>
/// <remarks>
/// The caller supplies the mdoc-derived witness columns and public-input templates (the CBOR/COSE walk and
/// the device-authentication hash stay caller-side per the serialization-ban architecture); the facade owns
/// the circuit provisioning, the field bundles, the canonical-to-Montgomery lift of the signature material,
/// the shared transcript, and the proof envelope. The swappable primitives — the Merkle and leaf hashes, the
/// transcript block cipher and incremental hash, and the prover entropy — ride in the
/// <see cref="LongfellowMdocCryptoSuite"/>; <see cref="LongfellowMdocCryptoSuite.Default"/> is the production
/// bundle. Circuits are re-parsed and bundles rebuilt per call; caching them across calls is a later
/// performance refinement behind the <see cref="LongfellowMdocCircuitSource"/> seam.
/// </remarks>
public static class LongfellowMdoc
{
    /// <summary>
    /// Produces a dual-field mdoc zero-knowledge proof over the caller-assembled witness.
    /// </summary>
    /// <param name="witness">The two field witness columns (the signature column canonical), the three common values, and the six MAC keys.</param>
    /// <param name="circuits">The concatenated signature-then-hash circuit-definition bytes.</param>
    /// <param name="spec">The proof specification the circuits were generated for.</param>
    /// <param name="transcriptSeed">The session seed the transcript is constructed from.</param>
    /// <param name="pool">The pool the working buffers and the returned proof rent from.</param>
    /// <param name="suite">The cryptographic-primitive bundle; <see langword="null"/> selects <see cref="LongfellowMdocCryptoSuite.Default"/>.</param>
    /// <returns>A pooled proof wrapping the <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c> envelope.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit bytes do not parse, do not match the specification, or a witness region length does not match the circuit.</exception>
    public static LongfellowMdocProof Prove(
        LongfellowMdocWitness witness,
        LongfellowMdocCircuitSource circuits,
        LongfellowMdocZkSpec spec,
        ReadOnlySpan<byte> transcriptSeed,
        BaseMemoryPool pool,
        LongfellowMdocCryptoSuite? suite = null)
    {
        ArgumentNullException.ThrowIfNull(witness);
        ArgumentNullException.ThrowIfNull(circuits);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(pool);
        LongfellowMdocCryptoSuite cryptoSuite = suite ?? LongfellowMdocCryptoSuite.Default;

        ParseCircuits(circuits, spec, out LongfellowSumcheckCircuit signatureCircuit, out LongfellowSumcheckCircuit hashCircuit);

        //The hash side runs over GF(2^128); its circuit is committed as parsed (no coefficient lift). The FFT
        //and the GF codec own pooled state and must outlive the driver call, so they are using-declared.
        using Lch14AdditiveFft hashFft = LongfellowMdocBundles.NewGfFft(pool);
        LongfellowFieldProfile hashProfile = LongfellowMdocBundles.NewGfProfile(hashFft);
        using LongfellowSubfieldRunCodec hashCodec = LongfellowMdocBundles.NewGfCodec(hashProfile, hashFft, pool);
        LongfellowMdocFieldProver hashBundle = LongfellowMdocBundles.BuildHashProver(spec, hashCircuit, hashProfile, hashFft, hashCodec, pool);

        //The sig side runs over the P-256 base field in the Montgomery working domain. The real-FFT owns no
        //pooled state (it is not disposable); the Fp256 codec owns nothing but is still disposable.
        LongfellowFieldProfile signatureProfile = LongfellowMdocBundles.NewMontgomerySigProfile();
        Fp256RealFft signatureFft = LongfellowMdocBundles.NewFp256Fft(signatureProfile, pool);
        using LongfellowSubfieldRunCodec signatureCodec = LongfellowMdocBundles.NewSigCodec(signatureProfile);
        LongfellowMdocFieldProver signatureBundle = LongfellowMdocBundles.BuildSigProver(spec, signatureCircuit, signatureProfile, signatureFft, signatureCodec, pool);

        //Lift the caller's canonical signature column to the Montgomery working domain into a pooled buffer the
        //facade owns and clears (it carries the secret signature wires).
        int signatureColumnBytes = witness.SignatureColumn.Length;
        using IMemoryOwner<byte> signatureColumnOwner = pool.Rent(signatureColumnBytes);
        Span<byte> montgomerySignatureColumn = signatureColumnOwner.Memory.Span[..signatureColumnBytes];
        LongfellowMdocBundles.LiftColumnToMontgomery(witness.SignatureColumn.Span, montgomerySignatureColumn);

        //A fresh transcript from the session seed (the ctor absorbs it immediately). The crypto suite's public
        //primitive delegates are wrapped to the driver's internal seam delegates here.
        LongfellowTranscriptBlockCipher blockCipher = (key, input, output) => cryptoSuite.BlockCipher(key, input, output);
        LongfellowRandomByteSource hashRandom = destination => cryptoSuite.HashRandom(destination);
        LongfellowRandomByteSource signatureRandom = destination => cryptoSuite.SignatureRandom(destination);

        using LongfellowTranscript transcript = new(
            transcriptSeed, spec.ProofSpecVersion, LongfellowMdocBundles.TranscriptElementBytes,
            blockCipher, pool, cryptoSuite.IncrementalHashFactory);

        byte[] envelope = LongfellowMdocProver.Prove(
            hashBundle, signatureBundle, witness.HashColumn.Span, montgomerySignatureColumn,
            hashRandom, signatureRandom, witness.CommonValues.Span, witness.ApKeys.Span,
            spec.HashMacIndex, LongfellowMdocZkSpec.SignatureMacIndex, transcript,
            cryptoSuite.MerkleHash, cryptoSuite.LeafHash, WellKnownHashAlgorithms.Sha256, pool);

        LongfellowMdocProof proof = LongfellowMdocProof.FromCanonical(envelope, pool);

        //The envelope is public proof material; zero the transient copy and the lifted secret column.
        CryptographicOperations.ZeroMemory(envelope);
        montgomerySignatureColumn.Clear();

        return proof;
    }


    /// <summary>
    /// Verifies a dual-field mdoc proof against the caller-assembled public statement.
    /// </summary>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="statement">The two field public-input templates (the signature template canonical) and the proof specification they were assembled for.</param>
    /// <param name="circuits">The concatenated signature-then-hash circuit-definition bytes.</param>
    /// <param name="transcriptSeed">The session seed the prover used.</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="suite">The cryptographic-primitive bundle; <see langword="null"/> selects <see cref="LongfellowMdocCryptoSuite.Default"/>.</param>
    /// <returns>The verdict; <see cref="LongfellowMdocVerdict.Accepted"/> when both proofs verify.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit bytes do not parse or do not match the statement's specification.</exception>
    public static LongfellowMdocVerdict Verify(
        LongfellowMdocProof proof,
        LongfellowMdocStatement statement,
        LongfellowMdocCircuitSource circuits,
        ReadOnlySpan<byte> transcriptSeed,
        BaseMemoryPool pool,
        LongfellowMdocCryptoSuite? suite = null)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(circuits);
        ArgumentNullException.ThrowIfNull(pool);
        LongfellowMdocCryptoSuite cryptoSuite = suite ?? LongfellowMdocCryptoSuite.Default;
        LongfellowMdocZkSpec spec = statement.Spec;

        ParseCircuits(circuits, spec, out LongfellowSumcheckCircuit signatureCircuit, out LongfellowSumcheckCircuit hashCircuit);

        using Lch14AdditiveFft hashFft = LongfellowMdocBundles.NewGfFft(pool);
        LongfellowFieldProfile hashProfile = LongfellowMdocBundles.NewGfProfile(hashFft);
        using LongfellowSubfieldRunCodec hashCodec = LongfellowMdocBundles.NewGfCodec(hashProfile, hashFft, pool);
        LongfellowMdocFieldVerifier hashBundle = LongfellowMdocBundles.BuildHashVerifier(spec, hashCircuit, hashProfile, hashFft, hashCodec, pool);

        LongfellowFieldProfile signatureProfile = LongfellowMdocBundles.NewMontgomerySigProfile();
        Fp256RealFft signatureFft = LongfellowMdocBundles.NewFp256Fft(signatureProfile, pool);
        using LongfellowSubfieldRunCodec signatureCodec = LongfellowMdocBundles.NewSigCodec(signatureProfile);
        LongfellowMdocFieldVerifier signatureBundle = LongfellowMdocBundles.BuildSigVerifier(spec, signatureCircuit, signatureProfile, signatureFft, signatureCodec, pool);

        //Frame the canonical signature template into the little-endian wire form the verifier's splice consumes
        //(the hash template is already in GF wire framing and passes through as supplied).
        int signatureTemplateBytes = statement.SignatureTemplateCanonical.Length;
        using IMemoryOwner<byte> signatureTemplateOwner = pool.Rent(signatureTemplateBytes);
        Span<byte> framedSignatureTemplate = signatureTemplateOwner.Memory.Span[..signatureTemplateBytes];
        LongfellowMdocBundles.FrameSigTemplateMontgomery(signatureProfile, statement.SignatureTemplateCanonical.Span, framedSignatureTemplate);

        LongfellowTranscriptBlockCipher blockCipher = (key, input, output) => cryptoSuite.BlockCipher(key, input, output);
        using LongfellowTranscript transcript = new(
            transcriptSeed, spec.ProofSpecVersion, LongfellowMdocBundles.TranscriptElementBytes,
            blockCipher, pool, cryptoSuite.IncrementalHashFactory);

        LongfellowMdocVerifier.Verify(
            proof.AsReadOnlySpan(), hashBundle, signatureBundle, statement.HashTemplate.Span, framedSignatureTemplate,
            transcript, cryptoSuite.MerkleHash, cryptoSuite.LeafHash, WellKnownHashAlgorithms.Sha256, pool,
            out LongfellowMdocVerificationResult result);

        framedSignatureTemplate.Clear();

        return result switch
        {
            LongfellowMdocVerificationResult.Accepted => LongfellowMdocVerdict.Accepted,
            LongfellowMdocVerificationResult.MalformedEnvelope => LongfellowMdocVerdict.MalformedEnvelope,
            LongfellowMdocVerificationResult.AttributeNumberMismatch => LongfellowMdocVerdict.AttributeNumberMismatch,
            LongfellowMdocVerificationResult.HashRejected => LongfellowMdocVerdict.HashRejected,
            LongfellowMdocVerificationResult.SigRejected => LongfellowMdocVerdict.SignatureRejected,
            _ => LongfellowMdocVerdict.MalformedEnvelope
        };
    }


    //Parses the signature circuit first (field id 1 / 32-byte elements) to learn its length, then the hash
    //circuit from the continuation span (field id 4 / 16-byte elements). Both must parse, and the hash
    //circuit's public-input count must match the specification: the public region is the template followed
    //by the six MACs and the shared key, so npub_in pins the specification's template element count and a
    //statement built for one specification cannot ride another specification's circuit bytes.
    private static void ParseCircuits(LongfellowMdocCircuitSource circuits, LongfellowMdocZkSpec spec, out LongfellowSumcheckCircuit signatureCircuit, out LongfellowSumcheckCircuit hashCircuit)
    {
        ReadOnlySpan<byte> raw = circuits.RawCircuitBytes.Span;

        if(!LongfellowCircuitReader.TryRead(raw, LongfellowMdocBundles.Point256FieldId, LongfellowMdocBundles.Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out int signatureBytes, LongfellowMdocBundles.InRangeFp256) || signature is null)
        {
            throw new ArgumentException("The signature circuit could not be parsed from the circuit-definition bytes.", nameof(circuits));
        }

        if(!LongfellowCircuitReader.TryRead(raw[signatureBytes..], LongfellowMdocBundles.Gf2128FieldId, LongfellowMdocBundles.Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out _, out _) || hash is null)
        {
            throw new ArgumentException("The hash circuit could not be parsed from the circuit-definition continuation.", nameof(circuits));
        }

        if(hash.PublicInputCount != spec.HashPublicInputCount)
        {
            throw new ArgumentException($"The hash circuit's public-input count is {hash.PublicInputCount}; the specification (version {spec.ProofSpecVersion}, {spec.AttributeCount} attribute(s)) requires {spec.HashPublicInputCount}.", nameof(circuits));
        }

        signatureCircuit = signature;
        hashCircuit = hash;
    }
}
