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


    /// <summary>Builds the GF(2^128) field bundle used by the kernel compiler and evaluator.</summary>
    /// <returns>The GF(2^128) field operations bundle.</returns>
    public static LongfellowLogicFieldOperations NewGfBundle() =>
        LongfellowLogicFieldOperations.CreateGf2128(GfAdd, GfSubtract, GfMultiply, GfInvert);


    /// <summary>Builds the P-256 base field bundle used by the kernel compiler and evaluator.</summary>
    /// <returns>The P-256 base field operations bundle.</returns>
    public static LongfellowLogicFieldOperations NewFp256Bundle() =>
        LongfellowLogicFieldOperations.CreateFp256(Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, Canonical(Prime - 1));


    /// <summary>Derives the GF(2^128) Ligero ceremony parameters and produces a ZK proof over the compiled circuit.</summary>
    /// <param name="circuit">The compiled circuit to prove.</param>
    /// <param name="witnessColumn">The witness column.</param>
    /// <param name="seed">The Fiat-Shamir transcript seed.</param>
    /// <returns>The serialized proof bytes.</returns>
    public static byte[] ProduceGfProof(LongfellowSumcheckCircuit circuit, byte[] witnessColumn, byte[] seed)
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
    public static void AssertGfVerifies(LongfellowSumcheckCircuit circuit, byte[] proof, byte[] publicInputs, byte[] seed, bool expectedAccept)
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
    public static byte[] GfPublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
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
    /// <returns>The serialized proof bytes.</returns>
    public static byte[] ProduceFp256Proof(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] seed)
    {
        Fp256RealFft fft = NewFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256);
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
        byte[] proof,
        byte[] publicInputs,
        byte[] seed,
        bool expectedAccept)
    {
        Fp256RealFft fft = NewFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256);
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
    public static byte[] Fp256PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
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
    public static LongfellowTranscript NewGfTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, Gf2128ElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Builds a Fiat-Shamir transcript at the Fp256 element width.</summary>
    /// <param name="seed">The transcript seed.</param>
    /// <returns>The transcript.</returns>
    public static LongfellowTranscript NewFp256Transcript(byte[] seed) =>
        new(seed, TranscriptVersion, Fp256ElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


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
