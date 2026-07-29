using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The kernel-ZK plumbing shared by the QuadCircuit-kernel test classes: the GF(2^128) and P-256
/// base field bundles, proof production and verification helpers, deterministic randomness and
/// transcript sources, and the additive/real FFT and canonical-scalar builders each compiled
/// statement needs to drive the field-generic Ligero-sumcheck prover and verifier end to end.
/// </summary>
/// <remarks>
/// Every member here is moved verbatim from the statements that first needed it; callers that
/// hard-code their own Fiat-Shamir seed pass it explicitly rather than relying on a fixed constant,
/// so the same helper serves every kernel-compiled statement regardless of which seed it proves and
/// verifies under.
/// </remarks>
internal static class LongfellowKernelZkTestHarness
{
    /// <summary>The field element width in bytes used for every witness column entry.</summary>
    public const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The number of circuit copies compiled, matching the reference's single-copy shape.</summary>
    public const int CopyCount = 1;

    /// <summary>The Fiat-Shamir transcript version tag.</summary>
    public const int TranscriptVersion = 6;

    /// <summary>The SHA-256 digest size in bytes.</summary>
    public const int DigestSize = 32;

    /// <summary>The GF(2^128) field element width in bytes for the Ligero ceremony.</summary>
    public const int Gf2128ElementBytes = 16;

    /// <summary>The Ligero sub-field element width in bytes for the production-16 field profile, shared by both wired fields.</summary>
    public const int Production16SubFieldBytes = 2;

    /// <summary>The Ligero code's inverse rate parameter, shared by both wired fields.</summary>
    public const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened per query, shared by both wired fields.</summary>
    public const int OpenedColumnCount = 2;

    /// <summary>Neither statement calls <c>BeginFullField</c>, so the subfield boundary stays zero.</summary>
    public const int SubfieldBoundary = 0;

    /// <summary>The P-256 base field element width in bytes.</summary>
    public const int Fp256ElementBytes = 32;

    /// <summary>The FIPS 204 sextic circuit-field element width in bytes (six 4-byte coordinates).</summary>
    public const int Fp24SexticElementBytes = 24;

    /// <summary>The FIPS 204 sextic circuit-field subfield element width in bytes (one base-field coordinate).</summary>
    public const int Fp24SexticSubFieldBytes = 4;

    /// <summary>The Merkle nonce width of the reference's <c>write_com_proof</c> layout (<c>MerkleNonce::kLength</c>).</summary>
    private const int MerkleNonceSize = 32;

    /// <summary>The offset of a 4-byte little-endian run-length prefix's most significant byte.</summary>
    private const int RunLengthPrefixTopByteOffset = 3;

    /// <summary>Sets the run length's most significant bit, driving it beyond the reader's <c>kMaxRunLen</c> cap (2^25) regardless of the run's original value — every real run length stays far below 2^24, so the corrupted top byte is deterministic.</summary>
    private const byte RunLengthPrefixCorruptionMask = 0x80;

    /// <summary>The GF(2^128) field addition delegate.</summary>
    public static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate.</summary>
    public static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate.</summary>
    public static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate.</summary>
    public static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The P-256 base field's modulus.</summary>
    public static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The P-256 base field addition delegate.</summary>
    public static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldReference.GetAdd();

    /// <summary>The P-256 base field subtraction delegate.</summary>
    public static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldReference.GetSubtract();

    /// <summary>The P-256 base field multiplication delegate.</summary>
    public static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldReference.GetMultiply();

    /// <summary>The P-256 base field inversion delegate.</summary>
    public static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldReference.GetInvert();

    /// <summary>The FIPS 204 sextic circuit-field addition delegate.</summary>
    public static ScalarAddDelegate Fp24SexticAdd { get; } = Fp24SexticBackend.GetAdd();

    /// <summary>The FIPS 204 sextic circuit-field subtraction delegate.</summary>
    public static ScalarSubtractDelegate Fp24SexticSubtract { get; } = Fp24SexticBackend.GetSubtract();

    /// <summary>The FIPS 204 sextic circuit-field multiplication delegate.</summary>
    public static ScalarMultiplyDelegate Fp24SexticMultiply { get; } = Fp24SexticBackend.GetMultiply();

    /// <summary>The FIPS 204 sextic circuit-field inversion delegate.</summary>
    public static ScalarInvertDelegate Fp24SexticInvert { get; } = Fp24SexticBackend.GetInvert();


    /// <summary>Builds the GF(2^128) field bundle used by the kernel compiler and evaluator.</summary>
    /// <returns>The GF(2^128) field operations bundle.</returns>
    public static LongfellowLogicFieldOperations NewGfBundle() =>
        LongfellowLogicFieldOperations.CreateGf2128(GfAdd, GfSubtract, GfMultiply, GfInvert);


    /// <summary>Builds the P-256 base field bundle used by the kernel compiler and evaluator.</summary>
    /// <returns>The P-256 base field operations bundle.</returns>
    public static LongfellowLogicFieldOperations NewFp256Bundle() =>
        LongfellowLogicFieldOperations.CreateFp256(Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, Canonical(Prime - 1));


    /// <summary>The sextic field's minus one as a canonical scalar — built once for the process because <c>CreateFp24Sextic</c> retains the memory it is handed.</summary>
    private static ReadOnlyMemory<byte> Fp24SexticMinusOne { get; } = BuildFp24SexticMinusOne();


    /// <summary>Builds the FIPS 204 sextic circuit-field bundle used by the kernel compiler and evaluator.</summary>
    /// <returns>The sextic field operations bundle.</returns>
    public static LongfellowLogicFieldOperations NewFp24SexticBundle() =>
        LongfellowLogicFieldOperations.CreateFp24Sextic(Fp24SexticAdd, Fp24SexticSubtract, Fp24SexticMultiply, Fp24SexticInvert, Fp24SexticMinusOne);


    /// <summary>Builds the one retained minus-one constant behind <see cref="Fp24SexticMinusOne"/>.</summary>
    /// <returns>The canonical scalar memory.</returns>
    private static ReadOnlyMemory<byte> BuildFp24SexticMinusOne()
    {
        var minusOne = new byte[ScalarSize];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(minusOne.AsSpan(ScalarSize - Fp24SexticSubFieldBytes, Fp24SexticSubFieldBytes), Fp24SexticBackend.Modulus - 1);

        return minusOne;
    }


    /// <summary>Produces a ZK proof over the compiled circuit under the FIPS 204 sextic circuit-field encoding.</summary>
    /// <param name="circuit">The compiled circuit to prove.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="witnessColumn">The witness column.</param>
    /// <param name="seed">The Fiat-Shamir transcript seed.</param>
    /// <returns>The pooled proof envelope; the caller owns its disposal.</returns>
    public static LongfellowZkProofEnvelope ProduceFp24SexticProof(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, ReadOnlySpan<byte> witnessColumn, ReadOnlySpan<byte> seed)
    {
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp24SexticEncoding.CreateEncoderFactory(BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp24SexticEncoding.CreateProfile(BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp24Sextic(profile);

        using LongfellowTranscript transcript = NewFp24SexticTranscript(seed);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            LongfellowFp24SexticEncoding.StatementSubfieldBoundary,
            random,
            transcript,
            encoderFactory,
            profile,
            codec,
            Fp24SexticAdd,
            Fp24SexticSubtract,
            Fp24SexticMultiply,
            Fp24SexticInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>Parses a FIPS 204 sextic circuit-field proof's segments, verifies it, and asserts the verdict matches the expected outcome.</summary>
    /// <param name="circuit">The compiled circuit the proof was produced over.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="proof">The proof bytes to verify.</param>
    /// <param name="publicInputs">The public input bytes.</param>
    /// <param name="seed">The Fiat-Shamir transcript seed.</param>
    /// <param name="expectedAccept">Whether the proof is expected to be accepted.</param>
    public static void AssertFp24SexticVerifies(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> proof,
        ReadOnlySpan<byte> publicInputs,
        ReadOnlySpan<byte> seed,
        bool expectedAccept)
    {
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp24SexticEncoding.CreateEncoderFactory(BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp24SexticEncoding.CreateProfile(BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp24Sextic(profile);

        ReadOnlySpan<byte> proofSpan = proof;
        if(proofSpan.Length < DigestSize)
        {
            Assert.IsFalse(expectedAccept, "A truncated proof can only be expected to reject.");

            return;
        }

        ReadOnlySpan<byte> root = proofSpan[..DigestSize];
        int sumcheckSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        ReadOnlySpan<byte> sumcheckBytes = proofSpan.Slice(DigestSize, sumcheckSize);
        ReadOnlySpan<byte> ligeroBytes = proofSpan[(DigestSize + sumcheckSize)..];

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, sumcheckBytes, out _);
        if(sumcheckProof is null)
        {
            Assert.IsFalse(expectedAccept, "An unparseable sumcheck segment can only be expected to reject.");

            return;
        }

        using LongfellowLigeroProof? ligeroProof = LongfellowLigeroProofSerializer.Read(parameters, profile, codec, BaseMemoryPool.Shared, ligeroBytes, out _);
        if(ligeroProof is null)
        {
            Assert.IsFalse(expectedAccept, "An unparseable Ligero segment can only be expected to reject.");

            return;
        }

        using LongfellowTranscript transcript = NewFp24SexticTranscript(seed);
        LongfellowZkVerifier.RecvCommitment(root, transcript);

        bool accepted = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
            circuit,
            parameters,
            sumcheckProof,
            ligeroProof,
            root,
            publicInputs,
            transcript,
            encoderFactory,
            profile,
            Fp24SexticAdd,
            Fp24SexticSubtract,
            Fp24SexticMultiply,
            Fp24SexticInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result);

        Assert.AreEqual(expectedAccept, accepted, $"The sextic verdict must be {(expectedAccept ? "accept" : "reject")} (result {result}).");

        if(!expectedAccept)
        {
            //A soundness reject must surface as a Ligero rejection, not a parse/transcript-shape failure;
            //pinning the cause stops a regression that rejects for a MalformedProof reason from
            //masquerading as a soundness reject. Parse failures return through the branches above.
            Assert.AreEqual(LongfellowZkVerificationResult.LigeroRejected, result, "A tampered sextic proof must reject with the Ligero soundness cause.");
        }
    }


    /// <summary>
    /// Corrupts the most significant byte of the first opened-columns run-length prefix in a sextic
    /// proof envelope, so the run-length reader's untrusted-length guard (the reference's
    /// <c>read_com_proof</c> <c>runlen &gt;= kMaxRunLen</c> rejection) must fail the parse gracefully
    /// instead of over-reading. The region's offset is fully parameter-shaped: past the root, the
    /// sumcheck segment, the four full-field response blocks and the per-leaf nonces.
    /// </summary>
    /// <param name="circuit">The compiled circuit the proof was produced over.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="proof">The proof envelope bytes, corrupted in place.</param>
    public static void TamperFirstOpenedColumnsRunLength(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, Span<byte> proof)
    {
        using LongfellowFieldProfile profile = LongfellowFp24SexticEncoding.CreateProfile(BaseMemoryPool.Shared);
        int responseElementCount = parameters.Block + parameters.DoubleBlock + parameters.RandomCount + (parameters.DoubleBlock - parameters.Block);
        int openedColumnsOffset =
            DigestSize
            + LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile)
            + (responseElementCount * Fp24SexticElementBytes)
            + (parameters.OpenedColumnCount * MerkleNonceSize);

        //Every valid run length stays far below 2^24 (the opened-element total bounds it), so the
        //prefix's top byte is zero in a well-formed proof; asserting it pins the offset arithmetic
        //to the actual layout before the corruption is applied.
        Assert.AreEqual((byte)0, proof[openedColumnsOffset + RunLengthPrefixTopByteOffset], "The first run-length prefix's top byte must be zero in a valid proof.");
        proof[openedColumnsOffset + RunLengthPrefixTopByteOffset] ^= RunLengthPrefixCorruptionMask;
    }


    /// <summary>Fills the public input element bytes (little-endian <c>to_bytes_field</c>) at the 24-byte sextic width into a caller-owned buffer.</summary>
    /// <param name="circuit">The compiled circuit declaring the public input count.</param>
    /// <param name="witnessColumn">The witness column to read the public inputs from.</param>
    /// <param name="destination">Receives the public input bytes; exactly the public input count times the sextic element width.</param>
    public static void FillFp24SexticPublicInputs(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> witnessColumn, Span<byte> destination)
    {
        Assert.AreEqual(circuit.PublicInputCount * Fp24SexticElementBytes, destination.Length, "The public input buffer must match the declared width.");
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            for(int b = 0; b < Fp24SexticElementBytes; b++)
            {
                destination[(i * Fp24SexticElementBytes) + b] = witnessColumn[(i * ScalarSize) + ScalarSize - 1 - b];
            }
        }
    }


    /// <summary>Derives the GF(2^128) Ligero ceremony parameters and produces a ZK proof over the compiled circuit.</summary>
    /// <param name="circuit">The compiled circuit to prove.</param>
    /// <param name="witnessColumn">The witness column.</param>
    /// <param name="seed">The Fiat-Shamir transcript seed.</param>
    /// <returns>The pooled proof envelope; the caller owns its disposal.</returns>
    public static LongfellowZkProofEnvelope ProduceGfProof(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> witnessColumn, ReadOnlySpan<byte> seed)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, Gf2128ElementBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewGfFft();
        using LongfellowTranscript transcript = NewGfTranscript(seed);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            Production16SubFieldBytes,
            SubfieldBoundary,
            random,
            transcript,
            fft,
            GfAdd,
            GfSubtract,
            GfMultiply,
            GfInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>Verifies a GF(2^128) proof and asserts the verdict matches the expected outcome.</summary>
    /// <param name="circuit">The compiled circuit the proof was produced over.</param>
    /// <param name="proof">The proof bytes to verify.</param>
    /// <param name="publicInputs">The public input bytes.</param>
    /// <param name="seed">The Fiat-Shamir transcript seed the proof was produced under.</param>
    /// <param name="expectedAccept">Whether the proof is expected to be accepted.</param>
    public static void AssertGfVerifies(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> proof, ReadOnlySpan<byte> publicInputs, ReadOnlySpan<byte> seed, bool expectedAccept)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, Gf2128ElementBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewGfFft();
        using LongfellowTranscript transcript = NewGfTranscript(seed);

        bool accepted = LongfellowZkVerifier.Verify(
            circuit,
            parameters,
            proof,
            publicInputs,
            Production16SubFieldBytes,
            transcript,
            fft,
            GfAdd,
            GfSubtract,
            GfMultiply,
            GfInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result);

        Assert.AreEqual(expectedAccept, accepted, $"The GF verdict must be {(expectedAccept ? "accept" : "reject")} (result {result}).");
    }


    /// <summary>Extracts the public input element bytes (little-endian <c>to_bytes_field</c>) at the 16-byte GF width.</summary>
    /// <param name="circuit">The compiled circuit declaring the public input count.</param>
    /// <param name="witnessColumn">The witness column to read the public inputs from.</param>
    /// <returns>The public input bytes.</returns>
    public static byte[] GfPublicInputBytes(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * Gf2128ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            for(int b = 0; b < Gf2128ElementBytes; b++)
            {
                publicInputs[(i * Gf2128ElementBytes) + b] = witnessColumn[(i * ScalarSize) + ScalarSize - 1 - b];
            }
        }

        return publicInputs;
    }


    /// <summary>Produces a ZK proof over the compiled circuit under the P-256 base field encoding.</summary>
    /// <param name="circuit">The compiled circuit to prove.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="witnessColumn">The witness column.</param>
    /// <param name="seed">The Fiat-Shamir transcript seed.</param>
    /// <returns>The pooled proof envelope; the caller owns its disposal.</returns>
    public static LongfellowZkProofEnvelope ProduceFp256Proof(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, ReadOnlySpan<byte> witnessColumn, ReadOnlySpan<byte> seed)
    {
        Fp256RealFft fft = NewFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        using LongfellowTranscript transcript = NewFp256Transcript(seed);
        LongfellowRandomByteSource random = NewBelowModulusSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            LongfellowFp256Encoding.SignatureSubfieldBoundary,
            random,
            transcript,
            encoderFactory,
            profile,
            codec,
            Fp256Add,
            Fp256Subtract,
            Fp256Multiply,
            Fp256Invert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>Parses a P-256 base field proof's segments, verifies it, and asserts the verdict matches the expected outcome.</summary>
    /// <param name="circuit">The compiled circuit the proof was produced over.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="proof">The proof bytes to verify.</param>
    /// <param name="publicInputs">The public input bytes.</param>
    /// <param name="seed">The Fiat-Shamir transcript seed.</param>
    /// <param name="expectedAccept">Whether the proof is expected to be accepted.</param>
    public static void AssertFp256Verifies(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> proof,
        ReadOnlySpan<byte> publicInputs,
        ReadOnlySpan<byte> seed,
        bool expectedAccept)
    {
        Fp256RealFft fft = NewFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        ReadOnlySpan<byte> proofSpan = proof;
        ReadOnlySpan<byte> root = proofSpan[..DigestSize];
        int sumcheckSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        ReadOnlySpan<byte> sumcheckBytes = proofSpan.Slice(DigestSize, sumcheckSize);
        ReadOnlySpan<byte> ligeroBytes = proofSpan[(DigestSize + sumcheckSize)..];

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, sumcheckBytes, out _);
        Assert.IsNotNull(sumcheckProof, "The sumcheck segment must parse.");

        using LongfellowLigeroProof? ligeroProof = LongfellowLigeroProofSerializer.Read(parameters, profile, codec, BaseMemoryPool.Shared, ligeroBytes, out _);
        Assert.IsNotNull(ligeroProof, "The Ligero segment must parse.");

        using LongfellowTranscript transcript = NewFp256Transcript(seed);
        LongfellowZkVerifier.RecvCommitment(root, transcript);

        bool accepted = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
            circuit,
            parameters,
            sumcheckProof,
            ligeroProof,
            root,
            publicInputs,
            transcript,
            encoderFactory,
            profile,
            Fp256Add,
            Fp256Subtract,
            Fp256Multiply,
            Fp256Invert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result);

        Assert.AreEqual(expectedAccept, accepted, $"The Fp256 verdict must be {(expectedAccept ? "accept" : "reject")} (result {result}).");
    }


    /// <summary>Extracts the public input element bytes (little-endian <c>to_bytes_field</c>) at the 32-byte Fp256 width.</summary>
    /// <param name="circuit">The compiled circuit declaring the public input count.</param>
    /// <param name="witnessColumn">The witness column to read the public inputs from.</param>
    /// <returns>The public input bytes.</returns>
    public static byte[] Fp256PublicInputBytes(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * Fp256ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            for(int b = 0; b < Fp256ElementBytes; b++)
            {
                publicInputs[(i * Fp256ElementBytes) + b] = witnessColumn[(i * ScalarSize) + ScalarSize - 1 - b];
            }
        }

        return publicInputs;
    }


    /// <summary>Builds a fresh deterministic counter source: the k-th byte produced is <c>(k &amp; 0xFF)</c>, identical to the C++ oracle's <c>CounterRandomEngine</c>.</summary>
    /// <returns>The random byte source.</returns>
    public static LongfellowRandomByteSource NewCounterSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(counter & 0xFF);
                counter++;
            }
        };
    }


    /// <summary>Builds a deterministic source whose every 32-byte draw is below <c>p</c>: the most significant little-endian byte is zeroed, so the integer is &lt; 2^248 &lt; <c>p</c> and <c>of_bytes_field</c> accepts it.</summary>
    /// <returns>The random byte source.</returns>
    public static LongfellowRandomByteSource NewBelowModulusSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)((counter * 31) + 7);
                counter++;
            }

            if(destination.Length == Fp256ElementBytes)
            {
                destination[^1] = 0;
            }
        };
    }


    /// <summary><c>of_scalar(u)</c> over Fp256: the integer <paramref name="coordinate"/> reduced mod <c>p</c> as a canonical big-endian scalar.</summary>
    /// <param name="coordinate">The integer to reduce.</param>
    /// <param name="destination">Receives the canonical big-endian scalar.</param>
    public static void OfScalarFp256(uint coordinate, Span<byte> destination) =>
        Canonical(new BigInteger(coordinate) % Prime).CopyTo(destination);


    /// <summary><c>fits(an)</c>: reports whether the canonical big-endian integer is below the modulus.</summary>
    /// <param name="canonical">The canonical big-endian integer to test.</param>
    /// <returns><see langword="true"/> if the integer is below the modulus.</returns>
    public static bool InRangeFp256(ReadOnlySpan<byte> canonical) =>
        new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


    /// <summary>Encodes a non-negative integer as a canonical big-endian scalar, zero-padded to <see cref="ScalarSize"/> bytes.</summary>
    /// <param name="value">The non-negative integer to encode.</param>
    /// <returns>The canonical big-endian scalar.</returns>
    public static byte[] Canonical(BigInteger value)
    {
        byte[] canonical = new byte[ScalarSize];
        byte[] bigEndian = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        bigEndian.CopyTo(canonical.AsSpan(ScalarSize - bigEndian.Length));

        return canonical;
    }


    /// <summary>Builds a Fiat-Shamir transcript at the GF(2^128) element width.</summary>
    /// <param name="seed">The transcript seed.</param>
    /// <returns>The transcript.</returns>
    public static LongfellowTranscript NewGfTranscript(ReadOnlySpan<byte> seed) =>
        new(seed, TranscriptVersion, Gf2128ElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Builds a Fiat-Shamir transcript at the Fp256 element width.</summary>
    /// <param name="seed">The transcript seed.</param>
    /// <returns>The transcript.</returns>
    public static LongfellowTranscript NewFp256Transcript(ReadOnlySpan<byte> seed) =>
        new(seed, TranscriptVersion, Fp256ElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Builds a Fiat-Shamir transcript at the FIPS 204 sextic element width.</summary>
    /// <param name="seed">The transcript seed.</param>
    /// <returns>The transcript.</returns>
    public static LongfellowTranscript NewFp24SexticTranscript(ReadOnlySpan<byte> seed) =>
        new(seed, TranscriptVersion, Fp24SexticElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Builds the additive FFT over the GF(2^128) production-16 subfield.</summary>
    /// <returns>The additive FFT.</returns>
    public static Lch14AdditiveFft NewGfFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Builds the real FFT over the P-256 base field, deriving its root of unity.</summary>
    /// <returns>The Fp256 real FFT.</returns>
    public static Fp256RealFft NewFp256Fft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Computes a one-shot SHA-256 digest, ignoring the requested hash function name (only SHA-256 is wired).</summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="output">Receives the digest.</param>
    /// <param name="hashFunction">The requested hash function name.</param>
    public static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Computes the two-to-one SHA-256 compression used by the Merkle transcript, hashing the concatenation of both inputs.</summary>
    /// <param name="left">The left input.</param>
    /// <param name="right">The right input.</param>
    /// <param name="output">Receives the digest.</param>
    public static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Encrypts one block under AES-256 in ECB mode with no padding, for the transcript's Fiat-Shamir incremental backend.</summary>
    /// <param name="key">The AES-256 key.</param>
    /// <param name="input">The plaintext block.</param>
    /// <param name="output">Receives the ciphertext block.</param>
    public static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }
}
