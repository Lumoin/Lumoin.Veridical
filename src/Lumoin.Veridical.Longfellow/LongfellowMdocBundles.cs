using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using System;
using System.Numerics;
using System.Runtime.Intrinsics;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The single place the dual-field mdoc bundles are assembled, so the facade's prove and verify paths cannot
/// drift: the pinned reference constants, the GF(2^128) hash-side and P-256 signature-side arithmetic
/// delegates, the field FFT/profile/codec/encoder-factory builders, the canonical-to-Montgomery column lift
/// and signature-template framing, and the four <see cref="LongfellowMdocFieldProver"/> /
/// <see cref="LongfellowMdocFieldVerifier"/> builders. The per-specification circuit-shape and
/// block-encoding values ride in the <see cref="LongfellowMdocZkSpec"/> the builders take; the values fixed
/// across every supported specification stay pinned here.
/// </summary>
/// <remarks>
/// The hash side runs over GF(2^128) and its quad-term coefficients are NOT lifted; the signature side runs
/// over the P-256 base field in the Montgomery working domain and its circuit coefficients ARE lifted. The
/// two field bundles ride the same FFT/profile/codec the facade owns and disposes — the bundles borrow them.
/// </remarks>
internal static class LongfellowMdocBundles
{
    /// <summary>One canonical field element per 32-byte big-endian slot, shared by every field and region.</summary>
    private const int ScalarSizeBytes = Scalar.SizeBytes;

    /// <summary>The reference's mdoc circuit version 7 Ligero inverse Reed-Solomon rate, shared by both fields.</summary>
    internal const int InverseRate = 7;

    /// <summary>The reference's mdoc circuit version 7 Ligero opened-column count, shared by both fields.</summary>
    internal const int OpenedColumnCount = 132;

    /// <summary>The reference's <c>FieldID</c> for the P-256 base field (1).</summary>
    internal const int Point256FieldId = 1;

    /// <summary>The P-256 base field's on-wire element width in bytes (32).</summary>
    internal const int Point256ElementBytes = 32;

    /// <summary>The reference's <c>FieldID</c> for the GF(2^128) field (4).</summary>
    internal const int Gf2128FieldId = 4;

    /// <summary>The GF(2^128) field's on-wire element width in bytes (16).</summary>
    internal const int Gf2128ElementBytes = 16;

    /// <summary>
    /// The GF(2^128) hash circuit's full field element width in bytes (16). Per-specification
    /// block-encoding lengths ride in <see cref="LongfellowMdocZkSpec"/> instead.
    /// </summary>
    internal const int HashFieldBytes = 16;

    /// <summary>The GF(2^128) hash circuit's GF(2^16) (Production16) subfield element width in bytes (2).</summary>
    internal const int HashSubFieldBytes = 2;

    /// <summary>The transcript's baked element width: the GF(2^128)/<c>a_v</c> width (16); the signature side passes its own 32-byte profile per operation instead.</summary>
    internal const int TranscriptElementBytes = 16;


    /// <summary>The GF(2^128) hash-side addition delegate (XOR).</summary>
    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) hash-side subtraction delegate; coincides with <see cref="GfAdd"/> (XOR).</summary>
    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) hash-side multiplication delegate.</summary>
    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) hash-side inversion delegate.</summary>
    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The Fp256 sig-side addition delegate; domain-linear, so the canonical delegate also serves the Montgomery working domain unchanged.</summary>
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    /// <summary>The Fp256 sig-side subtraction delegate; domain-linear, so the canonical delegate also serves the Montgomery working domain unchanged.</summary>
    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    /// <summary>The Fp256 sig-side Montgomery-domain (single-CIOS) multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Fp256MultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    /// <summary>The Fp256 sig-side Montgomery-domain inversion delegate.</summary>
    private static ScalarInvertDelegate Fp256InvertMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();

    /// <summary>The P-256 base-field prime the sig profile's <c>of_scalar</c> reduction and <c>in_range</c> predicate close over.</summary>
    private static BigInteger Fp256Prime { get; } = P256BigIntegerG1Reference.BaseFieldPrime;


    /// <summary>
    /// The lane-parallel Fp256 Montgomery batch multiply, selected by host capability: the AVX-512 octet
    /// backend when supported, else the AVX2 quartet backend, else <see langword="null"/> so the consumer
    /// falls back to the scalar multiply. The AVX-512 backend is selected only where the runtime also
    /// reports 512-bit vectors as hardware-accelerated (<see cref="Vector512.IsHardwareAccelerated"/>),
    /// because on parts whose JIT prefers 256-bit operation the 512-bit kernels can run below the AVX2
    /// kernels; where that report is false the ordering falls through to AVX2. Both SIMD backends are
    /// byte-identical to the scalar Montgomery oracle by construction.
    /// </summary>
    internal static ScalarBatchMultiplyDelegate? Fp256BatchMontgomery() =>
        P256BaseFieldMontgomeryBatchBackendAvx512.IsSupported && Vector512.IsHardwareAccelerated ? P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery()
        : P256BaseFieldMontgomeryBatchBackendAvx2.IsSupported ? P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery()
        : null;


    /// <summary>The base-field <c>of_scalar(u)</c>: the integer <paramref name="value"/> reduced mod p as a canonical 32-byte big-endian scalar.</summary>
    /// <param name="value">The little-endian-read coordinate integer.</param>
    /// <param name="canonical">Receives the canonical big-endian scalar; must be <see cref="ScalarSizeBytes"/> bytes.</param>
    internal static void OfScalarFp256(uint value, Span<byte> canonical)
    {
        canonical.Clear();
        BigInteger reduced = new BigInteger(value) % Fp256Prime;
        reduced.TryWriteBytes(canonical, out int written, isUnsigned: true, isBigEndian: true);

        //TryWriteBytes left-aligns the minimal big-endian bytes; shift them into the low bytes so the scalar
        //is right-aligned big-endian with the leading bytes zero.
        if(written < canonical.Length)
        {
            int shift = canonical.Length - written;
            canonical[..written].CopyTo(canonical[shift..]);
            canonical[..shift].Clear();
        }
    }


    /// <summary>The base-field <c>fits</c> predicate (<c>an &lt; p</c>) the <c>of_bytes_field</c> reversal applies.</summary>
    /// <param name="canonical">The canonical 32-byte big-endian scalar to test.</param>
    /// <returns><see langword="true"/> when the integer is below the modulus.</returns>
    internal static bool InRangeFp256(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Fp256Prime;


    /// <summary>Builds the LCH14 additive-FFT engine over the GF(2^16) production subfield.</summary>
    /// <param name="pool">The pool the FFT table and per-transform scratch rent from.</param>
    /// <returns>A fresh additive-FFT engine; the caller disposes it.</returns>
    internal static Lch14AdditiveFft NewGfFft(BaseMemoryPool pool) =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, pool);


    /// <summary>Builds the GF(2^128) field profile over <paramref name="fft"/>; the caller disposes it.</summary>
    /// <param name="fft">The shared LCH14 additive-FFT engine.</param>
    /// <param name="pool">Pool the profile's retained constant scalars rent from.</param>
    internal static LongfellowFieldProfile NewGfProfile(Lch14AdditiveFft fft, BaseMemoryPool pool) => LongfellowGf2k128Encoding.CreateProfile(fft, pool);


    /// <summary>Builds the GF(2^128) subfield-run codec (it owns a pooled basis reduction).</summary>
    /// <param name="profile">The GF(2^128) field profile.</param>
    /// <param name="fft">The shared LCH14 additive-FFT engine.</param>
    /// <param name="pool">The pool the basis reduction rents from.</param>
    /// <returns>A fresh codec; the caller disposes it.</returns>
    internal static LongfellowSubfieldRunCodec NewGfCodec(LongfellowFieldProfile profile, Lch14AdditiveFft fft, BaseMemoryPool pool) =>
        LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, HashSubFieldBytes, pool);


    /// <summary>Builds the Montgomery-domain P-256 base-field profile (canonical-to-Montgomery at the read/of_scalar/sample seams, Montgomery-to-canonical at the emit seam); the caller disposes it.</summary>
    /// <param name="pool">Pool the profile's retained constant scalars rent from.</param>
    internal static LongfellowFieldProfile NewMontgomerySigProfile(BaseMemoryPool pool) =>
        LongfellowFp256Encoding.CreateMontgomeryProfile(OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery, pool);


    /// <summary>
    /// Builds the Montgomery-domain real-FFT: the production root of unity is lifted per coordinate to its
    /// Montgomery residue and the twiddle multiplies are the Montgomery-domain delegates, so every multiply
    /// stays a single CIOS in domain.
    /// </summary>
    /// <param name="sigProfile">The Montgomery sig profile supplying the working-domain <c>of_scalar</c>.</param>
    /// <param name="pool">The pool the twiddle table and scratch rent from.</param>
    internal static Fp256RealFft NewFp256Fft(LongfellowFieldProfile sigProfile, BaseMemoryPool pool)
    {
        Span<byte> root = stackalloc byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnityWorking(root, P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new Fp256RealFft(
            root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery,
            sigProfile.OfScalar, CurveParameterSet.None, pool);
    }


    /// <summary>Builds the P-256 base-field subfield-run codec (the base field is its own subfield; it owns nothing).</summary>
    /// <param name="sigProfile">The Montgomery sig profile supplying the 32-byte framing.</param>
    /// <returns>A fresh codec; the caller disposes it.</returns>
    internal static LongfellowSubfieldRunCodec NewSigCodec(LongfellowFieldProfile sigProfile) => LongfellowSubfieldRunCodec.ForFp256(sigProfile);


    /// <summary>
    /// Lifts a canonical big-endian P-256 signature column to the Montgomery working domain element-wise: the
    /// prover commits and patches the column in domain.
    /// </summary>
    /// <param name="canonical">The canonical column; a multiple of 32 bytes.</param>
    /// <param name="destination">Receives the Montgomery column; the same length as <paramref name="canonical"/>.</param>
    internal static void LiftColumnToMontgomery(ReadOnlySpan<byte> canonical, Span<byte> destination)
    {
        int elementCount = canonical.Length / ScalarSizeBytes;
        for(int i = 0; i < elementCount; i++)
        {
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonical.Slice(i * ScalarSizeBytes, ScalarSizeBytes), destination.Slice(i * ScalarSizeBytes, ScalarSizeBytes));
        }
    }


    /// <summary>
    /// Frames a canonical signature public-input template into the little-endian wire form the verifier
    /// splices: each canonical element is lifted to its Montgomery residue and then dropped through the
    /// Montgomery profile's <c>to_bytes_field</c>, byte-identical to extracting the template from the
    /// Montgomery column the prover commits.
    /// </summary>
    /// <param name="profile">The Montgomery sig profile.</param>
    /// <param name="canonicalTemplate">The canonical big-endian template; a multiple of 32 bytes.</param>
    /// <param name="destination">Receives the little-endian wire bytes; <c>elementCount · profile.ElementBytes</c> bytes.</param>
    internal static void FrameSigTemplateMontgomery(LongfellowFieldProfile profile, ReadOnlySpan<byte> canonicalTemplate, Span<byte> destination)
    {
        int elementCount = canonicalTemplate.Length / ScalarSizeBytes;
        Span<byte> montgomery = stackalloc byte[ScalarSizeBytes];
        for(int i = 0; i < elementCount; i++)
        {
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalTemplate.Slice(i * ScalarSizeBytes, ScalarSizeBytes), montgomery);
            profile.ToBytesField(montgomery, destination.Slice(i * profile.ElementBytes, profile.ElementBytes));
        }

        montgomery.Clear();
    }


    /// <summary>Builds the GF(2^128) hash-circuit prove bundle.</summary>
    /// <param name="spec">The proof specification supplying the block-encoding length and the rebased subfield boundary.</param>
    /// <param name="circuit">The parsed hash circuit.</param>
    /// <param name="profile">The hash field profile (shared with the codec).</param>
    /// <param name="fft">The shared LCH14 additive-FFT engine.</param>
    /// <param name="codec">The hash subfield-run codec (borrowed; the caller disposes it).</param>
    /// <param name="pool">The pool the row encoders rent from.</param>
    internal static LongfellowMdocFieldProver BuildHashProver(LongfellowMdocZkSpec spec, LongfellowSumcheckCircuit circuit, LongfellowFieldProfile profile, Lch14AdditiveFft fft, LongfellowSubfieldRunCodec codec, BaseMemoryPool pool)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, HashFieldBytes, HashSubFieldBytes, spec.HashBlockEncoded);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, pool);

        return new LongfellowMdocFieldProver(
            circuit, parameters, encoderFactory, profile, codec,
            GfAdd, GfSubtract, GfMultiply, GfInvert, spec.HashSubfieldBoundary, CurveParameterSet.None,
            Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate(),
            Gf2k128BatchBackend.GetBindQuadReduce(),
            Gf2k128BatchBackend.GetGatherMultiplyAccumulate());
    }


    /// <summary>Builds the P-256 base-field signature-circuit prove bundle over the Montgomery-lifted circuit.</summary>
    /// <param name="spec">The proof specification supplying the signature block-encoding length.</param>
    /// <param name="canonicalCircuit">The parsed signature circuit (coefficients canonical; lifted internally).</param>
    /// <param name="profile">The Montgomery sig profile (shared with the codec and FFT).</param>
    /// <param name="fft">The Montgomery-domain real-FFT engine.</param>
    /// <param name="codec">The sig subfield-run codec (borrowed; the caller disposes it).</param>
    /// <param name="pool">The pool the row encoders rent from.</param>
    /// <returns>A bundle whose lifted circuit must be disposed by the caller after all bundle consumers finish.</returns>
    internal static LongfellowMdocFieldProver BuildSigProver(LongfellowMdocZkSpec spec, LongfellowSumcheckCircuit canonicalCircuit, LongfellowFieldProfile profile, Fp256RealFft fft, LongfellowSubfieldRunCodec codec, BaseMemoryPool pool)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(canonicalCircuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, spec.SignatureBlockEncoded);
        ScalarBatchMultiplyDelegate? batchMultiply = Fp256BatchMontgomery();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, pool, batchMultiply);
        LongfellowSumcheckCircuit montgomeryCircuit = canonicalCircuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        try
        {
            return new LongfellowMdocFieldProver(
                montgomeryCircuit, parameters, encoderFactory, profile, codec,
                Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, LongfellowFp256Encoding.SignatureSubfieldBoundary, CurveParameterSet.None,
                Fp256BatchMultiply: batchMultiply);
        }
        catch
        {
            montgomeryCircuit.Dispose();
            throw;
        }
    }


    /// <summary>Builds the GF(2^128) hash-circuit verification bundle (note the verifier record's optional order: BindQuad before Broadcast, no Gather, no SubfieldBoundary).</summary>
    /// <param name="spec">The proof specification supplying the block-encoding length.</param>
    /// <param name="circuit">The parsed hash circuit.</param>
    /// <param name="profile">The hash field profile (shared with the codec).</param>
    /// <param name="fft">The shared LCH14 additive-FFT engine.</param>
    /// <param name="codec">The hash subfield-run codec (borrowed; the caller disposes it).</param>
    /// <param name="pool">The pool the row encoders rent from.</param>
    internal static LongfellowMdocFieldVerifier BuildHashVerifier(LongfellowMdocZkSpec spec, LongfellowSumcheckCircuit circuit, LongfellowFieldProfile profile, Lch14AdditiveFft fft, LongfellowSubfieldRunCodec codec, BaseMemoryPool pool)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, HashFieldBytes, HashSubFieldBytes, spec.HashBlockEncoded);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, pool);

        return new LongfellowMdocFieldVerifier(
            circuit, parameters, encoderFactory, profile, codec,
            GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None,
            Gf2k128BatchBackend.GetBindQuadReduce(),
            Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate());
    }


    /// <summary>Builds the P-256 base-field signature-circuit verification bundle over the Montgomery-lifted circuit.</summary>
    /// <param name="spec">The proof specification supplying the signature block-encoding length.</param>
    /// <param name="canonicalCircuit">The parsed signature circuit (coefficients canonical; lifted internally).</param>
    /// <param name="profile">The Montgomery sig profile (shared with the codec and FFT).</param>
    /// <param name="fft">The Montgomery-domain real-FFT engine.</param>
    /// <param name="codec">The sig subfield-run codec (borrowed; the caller disposes it).</param>
    /// <param name="pool">The pool the row encoders rent from.</param>
    /// <returns>A bundle whose lifted circuit must be disposed by the caller after all bundle consumers finish.</returns>
    internal static LongfellowMdocFieldVerifier BuildSigVerifier(LongfellowMdocZkSpec spec, LongfellowSumcheckCircuit canonicalCircuit, LongfellowFieldProfile profile, Fp256RealFft fft, LongfellowSubfieldRunCodec codec, BaseMemoryPool pool)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(canonicalCircuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, spec.SignatureBlockEncoded);
        ScalarBatchMultiplyDelegate? batchMultiply = Fp256BatchMontgomery();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, pool, batchMultiply);
        LongfellowSumcheckCircuit montgomeryCircuit = canonicalCircuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        try
        {
            return new LongfellowMdocFieldVerifier(
                montgomeryCircuit, parameters, encoderFactory, profile, codec,
                Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None,
                Fp256BatchMultiply: batchMultiply);
        }
        catch
        {
            montgomeryCircuit.Dispose();
            throw;
        }
    }
}
