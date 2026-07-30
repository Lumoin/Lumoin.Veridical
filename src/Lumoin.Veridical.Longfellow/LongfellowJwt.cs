using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The public JWT-statement facade: a curated, serialization-free surface over the
/// kernel-compiled Longfellow JWT+KB2 statement. <see cref="Prove"/> turns a restricted
/// <c>issuerJws~keyBindingJws</c> presentation token into a pooled <see cref="LongfellowJwtProof"/>;
/// <see cref="Verify"/> recomputes the key-binding digest from the presented key-binding JWS —
/// the extractor's verifier half — and replays the ceremony to a <see cref="LongfellowJwtVerdict"/>.
/// </summary>
/// <remarks>
/// <para>
/// The statement is the reference's RESTRICTED JWT+KB2 format: a single tilde separates the
/// issuer JWS from the key-binding JWS, every proven claim is embedded in the issuer payload as
/// a quoted <c>"id":"value"</c> pair, and the format restrictions the reference states (no
/// spaces or escaped quotes inside claims; <c>:</c> only as the separator) carry over verbatim.
/// SD-JWT disclosure segments (<c>_sd</c> digests and <c>~</c>-joined disclosures) are not
/// processed. The issuer key is the verifier's out-of-band trust anchor. The key-binding
/// signature's device key is an unconstrained witness whose extraction from the <c>cnf</c> claim
/// is a prover convention, faithful to the reference.
/// </para>
/// <para>
/// The swappable primitives — the Merkle and leaf hashes, the transcript block cipher and
/// incremental hash, and the prover entropy — ride in the <see cref="LongfellowJwtCryptoSuite"/>;
/// <see cref="LongfellowJwtCryptoSuite.Default"/> is the production bundle. The circuit is
/// kernel-compiled per call; caching it across calls is a later performance refinement.
/// </para>
/// </remarks>
public static class LongfellowJwt
{
    /// <summary>
    /// Produces a JWT-statement zero-knowledge proof over a presentation token.
    /// </summary>
    /// <param name="token">The presentation token bytes in the <c>issuerJws~keyBindingJws</c> shape.</param>
    /// <param name="statement">The statement: the issuer key trust anchor, the disclosed attributes, and the block-capacity specification.</param>
    /// <param name="transcriptSeed">The session seed the transcript is constructed from.</param>
    /// <param name="pool">The pool the working buffers and the returned proof rent from.</param>
    /// <param name="suite">The cryptographic-primitive bundle; <see langword="null"/> selects <see cref="LongfellowJwtCryptoSuite.Default"/>.</param>
    /// <returns>A pooled proof wrapping the <c>[commitment root ‖ sumcheck ‖ Ligero]</c> envelope.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the token does not produce a witness for the statement: it is malformed, oversized for the block capacity, fails a signature, or lacks a required attribute or the device key.</exception>
    public static LongfellowJwtProof Prove(
        ReadOnlySpan<byte> token,
        LongfellowJwtStatement statement,
        ReadOnlySpan<byte> transcriptSeed,
        BaseMemoryPool pool,
        LongfellowJwtCryptoSuite? suite = null)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(pool);
        LongfellowJwtCryptoSuite cryptoSuite = suite ?? LongfellowJwtCryptoSuite.Default;

        //The witness computation is the cheap gate: a token the statement cannot prove is
        //rejected before the expensive circuit compilation.
        LongfellowLogicFieldOperations field = LongfellowJwtBundles.NewFieldBundle();
        LongfellowJwtWitness generator = LongfellowJwtBundles.NewWitnessGenerator(field, statement.Spec.BlockCapacity);
        var openedAttributes = new LongfellowJwtOpenedAttribute[statement.Attributes.Count];
        for(int i = 0; i < openedAttributes.Length; i++)
        {
            openedAttributes[i] = statement.Attributes[i].ToOpenedAttribute();
        }

        if(!generator.ComputeWitness(token, statement.IssuerKeyX.Span, statement.IssuerKeyY.Span, openedAttributes))
        {
            throw new ArgumentException("The token does not produce a witness for the statement: it is malformed, oversized for the block capacity, fails a signature, or lacks a required attribute or the device key.", nameof(token));
        }

        LongfellowSumcheckCircuit circuit = LongfellowJwtBundles.CompileStatement(field, statement.Spec.BlockCapacity, statement.Attributes.Count);
        LongfellowLigeroParameters parameters = LongfellowJwtBundles.DeriveParameters(circuit);

        //The column carries the private witness; it is pool-rented and cleared on every exit path.
        int columnBytes = circuit.InputCount * LongfellowJwtBundles.Fp256ElementBytes;
        using IMemoryOwner<byte> columnOwner = pool.Rent(columnBytes);
        Span<byte> column = columnOwner.Memory.Span[..columnBytes];
        try
        {
            int cursor = 0;
            LongfellowJwtBundles.FillPublicRegionCanonical(field, statement, generator.KbDigest.Span, column, ref cursor);
            int witnessElements = generator.GetElementCount(statement.Attributes.Count);
            if(cursor + witnessElements != circuit.InputCount)
            {
                throw new InvalidOperationException("The column layout must cover exactly the declared input wires.");
            }

            generator.FillWitness(column.Slice(cursor * LongfellowJwtBundles.Fp256ElementBytes, witnessElements * LongfellowJwtBundles.Fp256ElementBytes));

            Fp256RealFft fft = LongfellowJwtBundles.NewFft(pool);
            LongfellowRowEncoderFactory encoderFactory = LongfellowJwtBundles.NewEncoderFactory(fft, pool);
            using LongfellowFieldProfile profile = LongfellowJwtBundles.NewProfile(pool);
            using LongfellowSubfieldRunCodec codec = LongfellowJwtBundles.NewCodec(profile);

            LongfellowTranscriptBlockCipher blockCipher = (key, input, output) => cryptoSuite.BlockCipher(key, input, output);
            LongfellowRandomByteSource random = destination => cryptoSuite.ProverRandom(destination);
            using LongfellowTranscript transcript = new(
                transcriptSeed, LongfellowJwtBundles.TranscriptVersion, LongfellowJwtBundles.Fp256ElementBytes,
                blockCipher, pool, cryptoSuite.IncrementalHashFactory);

            using LongfellowZkProofEnvelope envelope = LongfellowJwtBundles.Prove(
                circuit, parameters, column, random, transcript, encoderFactory, profile, codec,
                cryptoSuite.MerkleHash, cryptoSuite.LeafHash, pool);

            return LongfellowJwtProof.FromCanonical(envelope.Bytes, pool);
        }
        finally
        {
            column.Clear();
        }
    }


    /// <summary>
    /// Verifies a JWT-statement proof against the statement and the presented key-binding JWS.
    /// </summary>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="keyBindingJws">The presented key-binding JWS bytes — the presentation part the verifier reads in clear; the key-binding digest public input is recomputed from it.</param>
    /// <param name="statement">The statement the proof claims.</param>
    /// <param name="transcriptSeed">The session seed the prover used.</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="suite">The cryptographic-primitive bundle; <see langword="null"/> selects <see cref="LongfellowJwtCryptoSuite.Default"/>.</param>
    /// <returns>The verdict; <see cref="LongfellowJwtVerdict.Accepted"/> only when the proof verifies against the recomputed digest.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The key-binding JWS is untrusted presentation input, so its defects answer verdicts rather
    /// than throw: a structurally unparseable JWS, or a signature segment whose strict unpadded
    /// base64url decoded length cannot hold the fixed-width <c>r ‖ s</c> pair, answers
    /// <see cref="LongfellowJwtVerdict.MalformedKeyBinding"/>. The length rule is arithmetic and
    /// deliberately stricter than the reference's zero-padding host decoder on malformed lengths;
    /// the segment's alphabet is not validated here — the proof itself is the cryptographic gate,
    /// and a relying party reads the key-binding payload (nonce, audience) through
    /// <see cref="LongfellowJwsCompact.DecodeSegment"/>, which validates what it decodes.
    /// </remarks>
    public static LongfellowJwtVerdict Verify(
        LongfellowJwtProof proof,
        ReadOnlySpan<byte> keyBindingJws,
        LongfellowJwtStatement statement,
        ReadOnlySpan<byte> transcriptSeed,
        BaseMemoryPool pool,
        LongfellowJwtCryptoSuite? suite = null)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(pool);
        LongfellowJwtCryptoSuite cryptoSuite = suite ?? LongfellowJwtCryptoSuite.Default;

        if(!LongfellowJwsCompact.TryParse(keyBindingJws, out LongfellowJwsCompactSegments segments))
        {
            return LongfellowJwtVerdict.MalformedKeyBinding;
        }

        if(LongfellowJwsCompact.StrictDecodedLength(segments.SignatureLength) < LongfellowJwsCompact.MinimumSignatureBytes)
        {
            return LongfellowJwtVerdict.MalformedKeyBinding;
        }

        Span<byte> keyBindingDigest = stackalloc byte[Scalar.SizeBytes];
        if(!LongfellowJwsCompact.TryComputeKeyBindingDigest(keyBindingJws, keyBindingDigest))
        {
            return LongfellowJwtVerdict.MalformedKeyBinding;
        }

        LongfellowLogicFieldOperations field = LongfellowJwtBundles.NewFieldBundle();
        LongfellowSumcheckCircuit circuit = LongfellowJwtBundles.CompileStatement(field, statement.Spec.BlockCapacity, statement.Attributes.Count);
        LongfellowLigeroParameters parameters = LongfellowJwtBundles.DeriveParameters(circuit);

        int elementCount = LongfellowJwtBundles.PublicInputElementCount(statement.Attributes.Count);
        if(elementCount != circuit.PublicInputCount)
        {
            throw new InvalidOperationException("The assembled public-input region must cover exactly the circuit's public input wires.");
        }

        int regionBytes = elementCount * LongfellowJwtBundles.Fp256ElementBytes;
        using IMemoryOwner<byte> publicInputOwner = pool.Rent(regionBytes);
        Span<byte> publicInputs = publicInputOwner.Memory.Span[..regionBytes];
        try
        {
            LongfellowJwtBundles.AssembleVerifierPublicInputs(field, statement, keyBindingDigest, publicInputs, pool);

            Fp256RealFft fft = LongfellowJwtBundles.NewFft(pool);
            LongfellowRowEncoderFactory encoderFactory = LongfellowJwtBundles.NewEncoderFactory(fft, pool);
            using LongfellowFieldProfile profile = LongfellowJwtBundles.NewProfile(pool);
            using LongfellowSubfieldRunCodec codec = LongfellowJwtBundles.NewCodec(profile);

            LongfellowTranscriptBlockCipher blockCipher = (key, input, output) => cryptoSuite.BlockCipher(key, input, output);
            using LongfellowTranscript transcript = new(
                transcriptSeed, LongfellowJwtBundles.TranscriptVersion, LongfellowJwtBundles.Fp256ElementBytes,
                blockCipher, pool, cryptoSuite.IncrementalHashFactory);

            return LongfellowJwtBundles.Verify(
                circuit, parameters, proof.AsReadOnlySpan(), publicInputs, transcript, encoderFactory, profile, codec,
                cryptoSuite.MerkleHash, cryptoSuite.LeafHash, pool);
        }
        finally
        {
            publicInputs.Clear();
        }
    }
}
