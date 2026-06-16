using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The P-256 base-field (<c>Fp256</c>) binding of the wire-format Ligero seam: the
/// <see cref="LongfellowRowEncoderFactory"/> that builds <see cref="Fp256ReedSolomon"/>s over a shared
/// <see cref="Fp256RealFft"/>, and the <see cref="LongfellowFieldProfile"/> for the prime field. The
/// signature-circuit callers construct these once from the production root of unity and hand them to the
/// field-generic commitment, prover and verifier — the prime-field analogue of
/// <see cref="LongfellowGf2k128Encoding"/>.
/// </summary>
/// <remarks>
/// <para>
/// The production root of unity is google/longfellow-zk's <c>kRootX</c> / <c>kRootY</c> in
/// <c>lib/circuits/mdoc/mdoc_zk.cc</c>, parsed by the reference as the <c>Fp256</c><c>^2</c> extension
/// element <c>kRootX + i·kRootY</c> (<c>p256_2.of_string(kRootX, kRootY)</c>, mdoc_zk.cc:478) of
/// multiplicative order <c>2^31</c> (<c>FftExtConvolutionFactory(..., 1ull &lt;&lt; 31)</c>,
/// mdoc_zk.cc:479). The two decimal constants are pinned below as their canonical 32-byte big-endian
/// bytes; both lie below the P-256 base-field modulus. The <see cref="LongfellowFp256EncodingTests"/>
/// gate the pinned hex against the decimal parse so the two cannot drift.
/// </para>
/// <para>
/// The signature circuit's Ligero commits over <c>Fp256Base</c>, whose subfield IS the base field
/// (<c>fp_generic.h</c>: <c>kSubFieldBytes = kBytes = 32</c> at line 47, <c>in_subfield(e) ≡ true</c> at
/// line 284, <c>to_bytes_subfield ≡ to_bytes_field</c> at lines 386–388). The circuit reports
/// <c>subfield_boundary = 0</c> (the dumped <c>sig_subfield_boundary</c>), so no witness row is
/// subfield-only and every padding draw is a full 32-byte field draw — the commit's subfield-draw path
/// stays dormant for the signature circuit. <see cref="SignatureSubFieldBytes"/> and
/// <see cref="SignatureSubfieldBoundary"/> carry those two values for the commit/serialize callers.
/// </para>
/// </remarks>
internal static class LongfellowFp256Encoding
{
    //The diagnostic tag the Fp256 row encoders carry.
    private const string EncoderTag = "Fp256 RS";

    //The multiplicative order of the production root of unity: mdoc_zk.cc:479 builds the
    //FftExtConvolutionFactory with 1ull << 31.
    public const ulong OmegaOrder = 1UL << 31;

    //Fp256Base::kSubFieldBytes == kBytes == 32 (fp_generic.h:47): the prime field's subfield is itself.
    public const int SignatureSubFieldBytes = Scalar.SizeBytes;

    //The P-256 signature circuit's subfield_boundary, as dumped (sig_subfield_boundary=0). With it zero,
    //layout_witness_rows' subfield_only is never satisfied, so the commit never draws a subfield element.
    public const int SignatureSubfieldBoundary = 0;

    //The production root of unity (mdoc_zk.cc:83-88), parsed by the reference as the extension element
    //kRootX + i·kRootY. The two coordinates are pinned as canonical 32-byte big-endian bytes; the decimal
    //sources are quoted here and the gate re-parses them to confirm the pin.
    //
    //  kRootX =
    //    "112649224146410281873500457609690258373018840430489408729223714171582664680802"
    //  kRootY =
    //    "84087994358540907695740461427818660560182168997182378749313018254450460212908"
    private static ReadOnlySpan<byte> RootRealBigEndian =>
    [
        0xf9, 0x0d, 0x33, 0x8e, 0xbd, 0x84, 0xf5, 0x66, 0x5c, 0xfc, 0x85, 0xc6, 0x79, 0x90, 0xe3, 0x37,
        0x9f, 0xc9, 0x56, 0x3b, 0x38, 0x2a, 0x4a, 0x4c, 0x98, 0x5a, 0x65, 0x32, 0x4b, 0x24, 0x25, 0x62
    ];

    private static ReadOnlySpan<byte> RootImaginaryBigEndian =>
    [
        0xb9, 0xe8, 0x1e, 0x42, 0xbc, 0x97, 0xcc, 0x4d, 0xa0, 0x4f, 0xc2, 0xe2, 0x01, 0x06, 0xe3, 0x40,
        0x84, 0x73, 0x8a, 0x64, 0x74, 0xd2, 0x32, 0xc6, 0xdb, 0xf4, 0x17, 0x4f, 0x60, 0xa4, 0x3e, 0xac
    ];


    /// <summary>
    /// Writes the production root of unity into <paramref name="destination"/> as the 64-byte extension
    /// element <c>re ‖ im</c> the <see cref="Fp256RealFft"/> consumes: the real part <c>kRootX</c> in the
    /// first 32 bytes, the imaginary part <c>kRootY</c> in the next 32, both canonical big-endian.
    /// </summary>
    /// <param name="destination">Receives the 64-byte root; must be <see cref="Fp256QuadraticExtension.ElementSize"/> bytes.</param>
    public static void RootOfUnity(Span<byte> destination)
    {
        if(destination.Length != Fp256QuadraticExtension.ElementSize)
        {
            throw new ArgumentException($"The root of unity is {Fp256QuadraticExtension.ElementSize} bytes; received {destination.Length}.", nameof(destination));
        }

        RootRealBigEndian.CopyTo(destination[..Scalar.SizeBytes]);
        RootImaginaryBigEndian.CopyTo(destination.Slice(Scalar.SizeBytes, Scalar.SizeBytes));
    }


    /// <summary>
    /// Writes the production root of unity into <paramref name="destination"/> already lifted into the working
    /// domain (Perf Increment 1): the canonical <c>re ‖ im</c> coordinates are each converted through
    /// <paramref name="toWorking"/> SEPARATELY. The root is the <c>Fp256^2</c> extension element
    /// <c>kRootX + i·kRootY</c>, so the lift is a BASE-field conversion applied per coordinate (the extension's
    /// real and imaginary parts are each a base-field residue; the Montgomery lift does not commute with the
    /// extension's complex structure as a whole, only coordinate-wise). For the canonical working domain
    /// <paramref name="toWorking"/> is the identity and the result equals <see cref="RootOfUnity"/>; for the
    /// Montgomery working domain each coordinate becomes its Montgomery residue, which is what the
    /// <see cref="Fp256RealFft"/>'s root must be so its per-twiddle multiplies stay 1-CIOS in domain.
    /// </summary>
    /// <param name="destination">Receives the 64-byte working-domain root; must be <see cref="Fp256QuadraticExtension.ElementSize"/> bytes.</param>
    /// <param name="toWorking">The canonical-&gt;working-domain converter applied to each base-field coordinate (<c>to_montgomery</c> for the Montgomery domain).</param>
    public static void RootOfUnityWorking(Span<byte> destination, LongfellowDomainConvertDelegate toWorking)
    {
        ArgumentNullException.ThrowIfNull(toWorking);
        if(destination.Length != Fp256QuadraticExtension.ElementSize)
        {
            throw new ArgumentException($"The root of unity is {Fp256QuadraticExtension.ElementSize} bytes; received {destination.Length}.", nameof(destination));
        }

        Span<byte> real = destination[..Scalar.SizeBytes];
        Span<byte> imaginary = destination.Slice(Scalar.SizeBytes, Scalar.SizeBytes);
        RootRealBigEndian.CopyTo(real);
        RootImaginaryBigEndian.CopyTo(imaginary);
        toWorking(real, real);
        toWorking(imaginary, imaginary);
    }


    /// <summary>
    /// Builds the Fp256 row-encoder factory over <paramref name="fft"/>: each call wraps an
    /// <see cref="Fp256ReedSolomon"/> for the requested shape, whose per-<c>(N, M)</c> pooled precompute
    /// rides as the encoder's disposable state so it releases with the encoder. The shared
    /// <paramref name="fft"/> (built from <see cref="RootOfUnity"/>) is borrowed and outlives the
    /// encoders.
    /// </summary>
    /// <param name="fft">The shared Fp256 real-FFT engine over the production root of unity.</param>
    /// <param name="add">Base-field addition.</param>
    /// <param name="subtract">Base-field subtraction.</param>
    /// <param name="multiply">Base-field multiplication.</param>
    /// <param name="invert">Base-field inversion.</param>
    /// <param name="ofScalar">The base-field <c>of_scalar(u)</c> in the working domain; the RS engine's leading-constant, binomial and batch-inverse field constants are sourced through it instead of baked canonical bytes.</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <param name="pool">Pool the encoders' precompute and per-call scratch rent from.</param>
    /// <param name="batchMultiply">The optional batched element-wise multiply the encoder's <c>Interpolate</c> scalar-times-vector loops route through; the Montgomery Fp256 path supplies it, the canonical path leaves it <see langword="null"/> for the scalar fallback. It must implement the same field op as <paramref name="multiply"/>.</param>
    public static LongfellowRowEncoderFactory CreateEncoderFactory(
        Fp256RealFft fft,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBatchMultiplyDelegate? batchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(pool);

        return (dimension, blockLength) =>
        {
            Fp256ReedSolomon encoder = new(dimension, blockLength, fft, add, subtract, multiply, invert, ofScalar, curve, pool, batchMultiply);

            return new LongfellowRowEncoder(EncoderTag, dimension, blockLength, encoder.Interpolate, encoder);
        };
    }


    /// <summary>
    /// Builds the Montgomery-domain Fp256 row-encoder factory (Perf Increment 1): the clean entry point the Fp
    /// callers use so the RS engine's field constants are sourced through the SAME Montgomery profile that the
    /// prover/verifier read and emit through. The of_scalar handed to the RS engine is
    /// <paramref name="montgomeryProfile"/>'s <see cref="LongfellowFieldProfile.OfScalar"/> (which lifts each
    /// constant to its Montgomery residue), and <paramref name="fft"/> must be built from
    /// <see cref="RootOfUnityWorking"/> with the same <c>to_montgomery</c> lift, so every multiply in the
    /// encode/convolution is a single CIOS in domain. <paramref name="multiply"/>/<paramref name="invert"/>
    /// are the Montgomery-domain delegates; <paramref name="add"/>/<paramref name="subtract"/> are
    /// domain-linear and shared with the canonical path.
    /// </summary>
    /// <param name="fft">The shared Fp256 real-FFT engine over the Montgomery-lifted production root of unity (<see cref="RootOfUnityWorking"/>).</param>
    /// <param name="montgomeryProfile">The Montgomery-domain profile (<see cref="CreateMontgomeryProfile"/>) whose <see cref="LongfellowFieldProfile.OfScalar"/> sources the RS engine's field constants in domain.</param>
    /// <param name="add">Base-field addition (domain-linear; the canonical delegate serves both domains).</param>
    /// <param name="subtract">Base-field subtraction (domain-linear; the canonical delegate serves both domains).</param>
    /// <param name="multiply">The Montgomery-domain multiply (1 CIOS).</param>
    /// <param name="invert">The Montgomery-domain inversion (Montgomery in, Montgomery out).</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <param name="pool">Pool the encoders' precompute and per-call scratch rent from.</param>
    /// <param name="batchMultiply">The optional batched Montgomery-domain multiply the encoder's <c>Interpolate</c> scalar-times-vector loops route through (the lane-parallel SIMD backend); residue-in/residue-out, the batched form of <paramref name="multiply"/>. <see langword="null"/> falls back to the scalar multiply.</param>
    public static LongfellowRowEncoderFactory CreateMontgomeryEncoderFactory(
        Fp256RealFft fft,
        LongfellowFieldProfile montgomeryProfile,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBatchMultiplyDelegate? batchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(montgomeryProfile);

        return CreateEncoderFactory(fft, add, subtract, multiply, invert, montgomeryProfile.OfScalar, curve, pool, batchMultiply);
    }


    /// <summary>Builds the Fp256 field profile from the base-field <c>of_scalar</c> and <c>fits</c> predicate.</summary>
    /// <param name="ofScalar">The base-field <c>of_scalar(u)</c>: the integer <c>u</c> reduced mod p as a canonical big-endian scalar.</param>
    /// <param name="inRange">The <c>fits</c> predicate (<c>an &lt; p</c>) the <c>of_bytes_field</c> reversal applies.</param>
    public static LongfellowFieldProfile CreateProfile(Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate inRange) =>
        LongfellowFieldProfile.ForFp256(ofScalar, inRange);


    /// <summary>
    /// Builds the Montgomery-domain Fp256 field profile (Perf Increment 1). Wire behaviour is byte-identical
    /// to <see cref="CreateProfile"/>, but the working domain is the Montgomery residue: the converters lift
    /// canonical-&gt;Montgomery at the read/of_scalar/sample seams and drop Montgomery-&gt;canonical at the
    /// emit seam, so the 1-CIOS Montgomery multiply can run across the whole Fp computation. The converters
    /// are injected (the backend lives in the backend assembly, not Core).
    /// </summary>
    /// <param name="ofScalar">The base-field <c>of_scalar(u)</c> producing the canonical big-endian scalar (lifted to Montgomery internally).</param>
    /// <param name="inRange">The <c>fits</c> predicate (<c>an &lt; p</c>) applied to the canonical value before the Montgomery lift.</param>
    /// <param name="toMontgomery">The canonical-&gt;Montgomery lift (<c>to_montgomery</c>).</param>
    /// <param name="fromMontgomery">The Montgomery-&gt;canonical drop (<c>from_montgomery</c>).</param>
    public static LongfellowFieldProfile CreateMontgomeryProfile(Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate inRange, LongfellowDomainConvertDelegate toMontgomery, LongfellowDomainConvertDelegate fromMontgomery) =>
        LongfellowFieldProfile.ForFp256Montgomery(ofScalar, inRange, toMontgomery, fromMontgomery);
}
