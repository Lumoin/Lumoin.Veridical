using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using System;
using System.Numerics;

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
    //One canonical field element per 32-byte big-endian slot, shared by every field and region.
    private const int ScalarSizeBytes = Scalar.SizeBytes;

    //The reference v7 Ligero pair: inverse Reed-Solomon rate and opened-column count, shared by both fields.
    internal const int InverseRate = 7;
    internal const int OpenedColumnCount = 132;

    //The two circuit field ids and on-wire element widths (the reference's FieldID: P256 = 1 / 32, GF2_128 = 4 / 16).
    internal const int Point256FieldId = 1;
    internal const int Point256ElementBytes = 32;
    internal const int Gf2128FieldId = 4;
    internal const int Gf2128ElementBytes = 16;

    //The GF(2^128) hash circuit: 16-byte full field over the GF(2^16) = Production16 subfield (2 bytes).
    //The per-specification block-encoding lengths ride in the LongfellowMdocZkSpec.
    internal const int HashFieldBytes = 16;
    internal const int HashSubFieldBytes = 2;

    //The transcript is baked at the GF/a_v width 16; the sig side passes its 32-byte profile per op.
    internal const int TranscriptElementBytes = 16;


    //The GF(2^128) hash-side delegates (all public in Backends.Managed). Subtract coincides with add (XOR).
    private static readonly ScalarAddDelegate GfAdd = Gf2k128Backend.GetAdd();
    private static readonly ScalarSubtractDelegate GfSubtract = Gf2k128Backend.GetSubtract();
    private static readonly ScalarMultiplyDelegate GfMultiply = Gf2k128Backend.GetMultiply();
    private static readonly ScalarInvertDelegate GfInvert = Gf2k128Backend.GetInvert();

    //The Fp256 sig-side delegates (internal in Backends.Managed, reached through the package's IVT). Add and
    //subtract are domain-linear, so the canonical delegates serve the Montgomery working domain unchanged; the
    //multiply and invert are the Montgomery-domain (single-CIOS) variants.
    private static readonly ScalarAddDelegate Fp256Add = P256BaseFieldMontgomeryBackend.GetAdd();
    private static readonly ScalarSubtractDelegate Fp256Subtract = P256BaseFieldMontgomeryBackend.GetSubtract();
    private static readonly ScalarMultiplyDelegate Fp256MultiplyMontgomery = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();
    private static readonly ScalarInvertDelegate Fp256InvertMontgomery = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();

    //The P-256 base-field prime the sig profile's of_scalar reduction and in_range predicate close over.
    private static readonly BigInteger Fp256Prime = P256BigIntegerG1Reference.BaseFieldPrime;


    /// <summary>
    /// The lane-parallel Fp256 Montgomery batch multiply, selected by host capability: the AVX-512 octet
    /// backend when supported, else the AVX2 quartet backend, else <see langword="null"/> so the consumer
    /// falls back to the scalar multiply. Both SIMD backends are byte-identical to the scalar Montgomery
    /// oracle by construction.
    /// </summary>
    internal static ScalarBatchMultiplyDelegate? Fp256BatchMontgomery() =>
        P256BaseFieldMontgomeryBatchBackendAvx512.IsSupported ? P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery()
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


    /// <summary>Builds the GF(2^128) field profile over <paramref name="fft"/>.</summary>
    /// <param name="fft">The shared LCH14 additive-FFT engine.</param>
    internal static LongfellowFieldProfile NewGfProfile(Lch14AdditiveFft fft) => LongfellowGf2k128Encoding.CreateProfile(fft);


    /// <summary>Builds the GF(2^128) subfield-run codec (it owns a pooled basis reduction).</summary>
    /// <param name="profile">The GF(2^128) field profile.</param>
    /// <param name="fft">The shared LCH14 additive-FFT engine.</param>
    /// <param name="pool">The pool the basis reduction rents from.</param>
    /// <returns>A fresh codec; the caller disposes it.</returns>
    internal static LongfellowSubfieldRunCodec NewGfCodec(LongfellowFieldProfile profile, Lch14AdditiveFft fft, BaseMemoryPool pool) =>
        LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, HashSubFieldBytes, pool);


    /// <summary>Builds the Montgomery-domain P-256 base-field profile (canonical-to-Montgomery at the read/of_scalar/sample seams, Montgomery-to-canonical at the emit seam).</summary>
    internal static LongfellowFieldProfile NewMontgomerySigProfile() =>
        LongfellowFp256Encoding.CreateMontgomeryProfile(OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery);


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
    internal static LongfellowMdocFieldProver BuildSigProver(LongfellowMdocZkSpec spec, LongfellowSumcheckCircuit canonicalCircuit, LongfellowFieldProfile profile, Fp256RealFft fft, LongfellowSubfieldRunCodec codec, BaseMemoryPool pool)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(canonicalCircuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, spec.SignatureBlockEncoded);
        ScalarBatchMultiplyDelegate? batchMultiply = Fp256BatchMontgomery();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, pool, batchMultiply);
        LongfellowSumcheckCircuit montgomeryCircuit = canonicalCircuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldProver(
            montgomeryCircuit, parameters, encoderFactory, profile, codec,
            Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, LongfellowFp256Encoding.SignatureSubfieldBoundary, CurveParameterSet.None,
            Fp256BatchMultiply: batchMultiply);
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
    internal static LongfellowMdocFieldVerifier BuildSigVerifier(LongfellowMdocZkSpec spec, LongfellowSumcheckCircuit canonicalCircuit, LongfellowFieldProfile profile, Fp256RealFft fft, LongfellowSubfieldRunCodec codec, BaseMemoryPool pool)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(canonicalCircuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, spec.SignatureBlockEncoded);
        ScalarBatchMultiplyDelegate? batchMultiply = Fp256BatchMontgomery();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, pool, batchMultiply);
        LongfellowSumcheckCircuit montgomeryCircuit = canonicalCircuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldVerifier(
            montgomeryCircuit, parameters, encoderFactory, profile, codec,
            Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None,
            Fp256BatchMultiply: batchMultiply);
    }
}
