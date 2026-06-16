using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Reference implementation of the NIST P-256 (secp256r1) <em>scalar</em>
/// field delegates — arithmetic modulo the group order <c>n</c> — using
/// <see cref="BigInteger"/>. Parallel in shape to
/// <see cref="Bls12Curve381BigIntegerScalarReference"/> and
/// <see cref="Bn254BigIntegerScalarReference"/>: it is the ground truth the
/// production backends are validated against, and the first-class scalar layer
/// that ECDSA-P-256 (signature <c>r, s</c> live mod <c>n</c>) and the
/// in-circuit verification proof build on.
/// </summary>
/// <remarks>
/// <para>
/// This is the <em>scalar</em> (group-order) field. The P-256 <em>base</em>
/// field — the prime <c>p</c> the point coordinates live in — is a separate
/// modulus handled by the base-field/G1 layer; do not confuse the two. ECDSA
/// mixes both: the coordinate arithmetic is over <c>p</c>, the signature
/// scalars over <c>n</c>.
/// </para>
/// <para>
/// Byte layout is the shared canonical 32-byte big-endian
/// (<see cref="Scalar.SizeBytes"/>); P-256's 256-bit order fits exactly.
/// Unlike the BLS12-381 and BN254 orders — whose top hex digit is below
/// <c>0x8</c> — P-256's <c>n</c> begins at <c>0xff</c>, so the literal carries
/// a leading <c>"0"</c> sign-guard to keep
/// <see cref="BigInteger.Parse(string, NumberStyles, IFormatProvider)"/> from
/// reading it as a negative two's-complement value.
/// </para>
/// <para>
/// Hash-to-scalar is the generic RFC 9380 reduction (<c>L = 48</c> from
/// <c>ceil((256 + 128) / 8)</c> at P-256's 128-bit security level), with the
/// expand-message backend supplied by the caller as for BN254.
/// </para>
/// </remarks>
internal static class P256BigIntegerScalarReference
{
    /// <summary>
    /// The NIST P-256 group order
    /// <c>n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551</c>,
    /// equal to
    /// <c>115792089210356248762697446949407573529996955224135760342422259061068512044369</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The leading hex digit is <c>f</c>, so the most-significant byte's high
    /// bit is set; the literal is prefixed with <c>"0"</c> so it parses as a
    /// positive value rather than a negative two's-complement one.
    /// </para>
    /// <para>
    /// Source of the constant: NIST SP 800-186 (2023), "Recommendations for
    /// Discrete Logarithm-Based Cryptography: Elliptic Curve Domain
    /// Parameters", Curve P-256, value <c>n</c>; equivalently SEC 2 v2.0
    /// (Certicom, 2010) §2.4.2 secp256r1 order <c>n</c>, and FIPS 186-4
    /// Appendix D.1.2.3 (curve P-256). Cross-checks the order exposed by the
    /// platform <c>ECCurve.NamedCurves.nistP256</c>.
    /// </para>
    /// </remarks>
    public static BigInteger FieldOrder { get; } = BigInteger.Parse(
        "0ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    private static readonly ProviderLibrary ProviderLibraryIdentity = new(
        Name: "Lumoin.Veridical.Tests",
        Version: "0.0.0");

    private static readonly CryptoLibrary CryptoLibraryIdentity = new(
        Name: "System.Numerics.BigInteger",
        Version: typeof(BigInteger).Assembly.GetName().Version?.ToString() ?? "unknown");

    private static readonly ProviderClass ProviderClassIdentity = new(
        Name: nameof(P256BigIntegerScalarReference));


    /// <summary>Returns the reference scalar-add delegate.</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the reference scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the reference scalar-multiply delegate.</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the reference scalar-negate delegate.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference scalar-invert delegate.</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>Returns the reference scalar-reduce delegate.</summary>
    public static ScalarReduceDelegate GetReduce() => Reduce;

    /// <summary>Returns the reference scalar-random delegate (rejection sampling modulo <c>n</c>).</summary>
    public static ScalarRandomDelegate GetRandom() => Random;

    /// <summary>Returns the reference batched scalar-add delegate (a loop over the single-element path, for cross-backend agreement).</summary>
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the reference batched scalar-subtract delegate.</summary>
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>Returns the reference batched scalar-multiply delegate.</summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;

    /// <summary>
    /// Returns a reference hash-to-scalar delegate (RFC 9380): expand to
    /// <c>L = 48</c> uniform bytes via <paramref name="expandMessage"/>,
    /// interpret big-endian, reduce modulo <c>n</c>.
    /// </summary>
    public static ScalarHashToScalarDelegate GetHashToScalar(ExpandMessageDelegate expandMessage)
    {
        ArgumentNullException.ThrowIfNull(expandMessage);
        return (message, domainSeparationTag, result, curve, inboundTag) =>
            HashToScalar(message, domainSeparationTag, result, curve, inboundTag, expandMessage);
    }


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);
        AddInternal(a, b, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarSubtract, curve);
        SubtractInternal(a, b, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);
        MultiplyInternal(a, b, result);
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarNegate, curve);

        BigInteger value = ReadCanonical(a);
        BigInteger negated = value.IsZero ? BigInteger.Zero : FieldOrder - value;
        WriteCanonical(negated, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarInvert, curve);

        BigInteger value = ReadCanonical(a);
        if(value.IsZero)
        {
            throw new InvalidOperationException("Zero is not invertible in the P-256 scalar field.");
        }

        //Fermat's little theorem: a^(n-2) mod n is the inverse when n is prime.
        BigInteger inverse = BigInteger.ModPow(value, FieldOrder - 2, FieldOrder);
        WriteCanonical(inverse, result);
    }


    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarReduce, curve);

        BigInteger value = ReadCanonical(input);
        BigInteger reduced = value % FieldOrder;
        WriteCanonical(reduced, result);
    }


    private static void BatchAdd(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchAdd, curve, count);
        ValidateBatchLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count);

        int stride = Scalar.SizeBytes;
        for(int i = 0; i < count; i++)
        {
            int offset = i * stride;
            AddInternal(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    private static void BatchSubtract(
        ReadOnlySpan<byte> minuendsConcatenated,
        ReadOnlySpan<byte> subtrahendsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchSubtract, curve, count);
        ValidateBatchLengths(minuendsConcatenated, subtrahendsConcatenated, resultsConcatenated, count);

        int stride = Scalar.SizeBytes;
        for(int i = 0; i < count; i++)
        {
            int offset = i * stride;
            SubtractInternal(
                minuendsConcatenated.Slice(offset, stride),
                subtrahendsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    private static void BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiply, curve, count);
        ValidateBatchLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count);

        int stride = Scalar.SizeBytes;
        for(int i = 0; i < count; i++)
        {
            int offset = i * stride;
            MultiplyInternal(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    private static void ValidateBatchLengths(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> result, int count)
    {
        int stride = Scalar.SizeBytes;
        if(a.Length != count * stride || b.Length != count * stride || result.Length != count * stride)
        {
            throw new ArgumentException($"Batched scalar buffers must each be exactly {count} * {stride} bytes for count = {count}.");
        }
    }


    private static void MultiplyInternal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        BigInteger product = (ReadCanonical(a) * ReadCanonical(b)) % FieldOrder;
        WriteCanonical(product, result);
    }


    private static void AddInternal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        BigInteger sum = (ReadCanonical(a) + ReadCanonical(b)) % FieldOrder;
        WriteCanonical(sum, result);
    }


    private static void SubtractInternal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        BigInteger difference = (((ReadCanonical(a) - ReadCanonical(b)) % FieldOrder) + FieldOrder) % FieldOrder;
        WriteCanonical(difference, result);
    }


    private static Tag Random(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarRandom, curve);

        //Rejection sampling: P-256's order sits just below 2^256 (top byte
        //0xff), so the acceptance probability per draw is ~1 and a single draw
        //all but always suffices.
        Span<byte> trial = stackalloc byte[Scalar.SizeBytes];
        while(true)
        {
            System.Security.Cryptography.RandomNumberGenerator.Fill(trial);
            BigInteger candidate = ReadCanonical(trial);
            if(candidate < FieldOrder)
            {
                WriteCanonical(candidate, destination);
                break;
            }
        }

        return ProviderInstrumentation.StampTag(
            inboundTag, ProviderLibraryIdentity, CryptoLibraryIdentity, ProviderClassIdentity, new ProviderOperation(nameof(Random)));
    }


    private const int HashToScalarUniformBytes = 48;


    private static Tag HashToScalar(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        Span<byte> result,
        CurveParameterSet curve,
        Tag inboundTag,
        ExpandMessageDelegate expandMessage)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.HashToScalar, curve);

        if(result.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"Hash-to-scalar result span must be exactly {Scalar.SizeBytes} bytes; received {result.Length}.", nameof(result));
        }

        Span<byte> uniform = stackalloc byte[HashToScalarUniformBytes];
        expandMessage(message, domainSeparationTag, uniform);

        BigInteger reduced = new BigInteger(uniform, isUnsigned: true, isBigEndian: true) % FieldOrder;
        WriteCanonical(reduced, result);

        return ProviderInstrumentation.StampTag(
            inboundTag, ProviderLibraryIdentity, CryptoLibraryIdentity, ProviderClassIdentity, new ProviderOperation(nameof(HashToScalar)));
    }


    private static BigInteger ReadCanonical(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
