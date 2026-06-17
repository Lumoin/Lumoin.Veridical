using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BN254 (alt_bn128) scalar delegates using
/// <see cref="BigInteger"/> arithmetic against the field order. Parallel in
/// shape to <see cref="Bls12Curve381BigIntegerScalarReference"/>: it exists
/// for the test project to wire against and serves as the ground truth that
/// production backends are validated to match.
/// </summary>
/// <remarks>
/// <para>
/// The wiring shown in <see cref="GetAdd"/>, <see cref="GetMultiply"/>, and
/// the rest is exactly the wiring an application performs at start-up: it
/// chooses a backend, retrieves the delegates the backend exposes, and passes
/// them into operations. The construction code never names this type; it
/// receives the delegates as arguments and dispatches on the
/// <see cref="CurveParameterSet"/> the operands carry.
/// </para>
/// <para>
/// The byte layout converts canonical big-endian to <see cref="BigInteger"/>
/// via <see cref="BigInteger(ReadOnlySpan{byte}, bool, bool)"/> with
/// <c>isUnsigned: true</c> and <c>isBigEndian: true</c>. The result is reduced
/// modulo the field order before serialising back to a 32-byte big-endian
/// span. <see cref="Scalar.SizeBytes"/> is the shared 32-byte width; BN254's
/// 254-bit scalar field fits identically to BLS12-381's.
/// </para>
/// <para>
/// Hash-to-scalar is deliberately absent: BN254 has no IETF BBS+ ciphersuite,
/// so there is no curve-pinned <c>L</c> or expansion to mirror here. The
/// generic RFC 9380 hash-to-scalar path for BN254 lands separately with its
/// own modular-reduction step.
/// </para>
/// </remarks>
internal static class Bn254BigIntegerScalarReference
{
    /// <summary>
    /// The BN254 (alt_bn128) scalar field order
    /// <c>r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001</c>,
    /// equal to
    /// <c>21888242871839275222246405745257275088548364400416034343698204186575808495617</c>.
    /// </summary>
    /// <remarks>
    /// The leading hex digit is <c>3</c>, so the high bit of the most
    /// significant byte is clear and
    /// <see cref="BigInteger.Parse(string, NumberStyles, IFormatProvider)"/>
    /// reads the literal as a positive value without a leading <c>"0"</c>
    /// sign-guard — the same situation as the BLS12-381 order, whose literal
    /// also begins below <c>0x80</c>. The leading-zero guard is required only
    /// for a value whose top hex digit is <c>8</c>–<c>f</c>; neither curve's
    /// scalar order is such a value. The canonical order matches both the
    /// Ethereum alt_bn128 precompile definition (EIP-196/197) and the arkworks
    /// <c>bn254</c> crate's <c>Fr</c> modulus.
    /// </remarks>
    public static BigInteger FieldOrder { get; } = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    private static readonly ProviderLibrary ProviderLibraryIdentity = new(
        Name: "Lumoin.Veridical.Backends.Managed",
        Version: typeof(Bn254BigIntegerScalarReference).Assembly.GetName().Version?.ToString() ?? "unknown");

    private static readonly CryptoLibrary CryptoLibraryIdentity = new(
        Name: "System.Numerics.BigInteger",
        Version: typeof(BigInteger).Assembly.GetName().Version?.ToString() ?? "unknown");

    private static readonly ProviderClass ProviderClassIdentity = new(
        Name: nameof(Bn254BigIntegerScalarReference));


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

    /// <summary>
    /// Returns the reference scalar-random delegate, which samples uniformly
    /// modulo the field order via rejection sampling on
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>.
    /// </summary>
    public static ScalarRandomDelegate GetRandom() => Random;

    /// <summary>
    /// Returns the reference batched scalar-add delegate. Implemented as a
    /// loop over the single-element <see cref="GetAdd"/> path — this reference
    /// gains nothing from batching, and the loop exists only to honour the
    /// <see cref="ScalarBatchAddDelegate"/> contract for cross-backend
    /// agreement testing.
    /// </summary>
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the reference batched scalar-subtract delegate. See <see cref="GetBatchAdd"/> for the rationale.</summary>
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>Returns the reference batched scalar-multiply delegate (a loop over the single-element multiply). See <see cref="GetBatchAdd"/> for the rationale.</summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;

    /// <summary>
    /// Returns a reference hash-to-scalar delegate that maps a message and DST
    /// to a canonical scalar via RFC 9380: produce <c>L = 48</c> uniform bytes
    /// with the supplied <paramref name="expandMessage"/>, interpret them
    /// big-endian, and reduce modulo the scalar-field order <c>r</c>.
    /// <c>L = ceil((ceil(log2(r)) + k) / 8) = ceil((254 + 128) / 8) = 48</c>
    /// with BN254's <c>k = 128</c>-bit security level.
    /// </summary>
    /// <param name="expandMessage">
    /// The expand-message backend — the hash enters through this delegate, not
    /// a hardcoded call, so the application chooses it. SHA-256
    /// (<see cref="Rfc9380ExpandMessage.ExpandMessageXmdSha256"/>, backed by the
    /// platform <c>System.Security.Cryptography.SHA256</c>) is the expected
    /// choice; a SHAKE-256 or other XOF is a different
    /// <see cref="ExpandMessageDelegate"/> the caller can supply instead.
    /// </param>
    /// <remarks>
    /// BN254 has no IETF BBS+ ciphersuite (BBS+ stays BLS-pinned), so this is
    /// the generic RFC 9380 hash-to-scalar — not a ciphersuite-specific pair.
    /// Taking <paramref name="expandMessage"/> as a delegate (rather than baking
    /// in SHA-256 the way the BLS12-381 reference does) keeps the hash a backend
    /// swap point.
    /// </remarks>
    public static ScalarHashToScalarDelegate GetHashToScalar(ExpandMessageDelegate expandMessage)
    {
        ArgumentNullException.ThrowIfNull(expandMessage);
        return (message, domainSeparationTag, result, curve, inboundTag) =>
            HashToScalar(message, domainSeparationTag, result, curve, inboundTag, expandMessage);
    }


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);

        BigInteger left = ReadCanonical(a);
        BigInteger right = ReadCanonical(b);
        BigInteger sum = (left + right) % FieldOrder;
        WriteCanonical(sum, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarSubtract, curve);

        BigInteger left = ReadCanonical(a);
        BigInteger right = ReadCanonical(b);
        BigInteger difference = ((left - right) % FieldOrder + FieldOrder) % FieldOrder;
        WriteCanonical(difference, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);

        BigInteger left = ReadCanonical(a);
        BigInteger right = ReadCanonical(b);
        BigInteger product = (left * right) % FieldOrder;
        WriteCanonical(product, result);
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
            throw new InvalidOperationException("Zero is not invertible in the BN254 scalar field.");
        }

        // Fermat's little theorem: a^(r-2) mod r is the inverse when r is prime.
        BigInteger inverse = BigInteger.ModPow(value, FieldOrder - 2, FieldOrder);
        WriteCanonical(inverse, result);
    }


    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarReduce, curve);

        // Interpret input as a big-endian unsigned integer of arbitrary width;
        // reduce modulo r. The BigInteger ctor produces a non-negative value, so a
        // single mod suffices; the style stays uniform with Subtract for readability.
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

        int stride = Scalar.SizeBytes;
        if(leftOperandsConcatenated.Length != count * stride
            || rightOperandsConcatenated.Length != count * stride
            || resultsConcatenated.Length != count * stride)
        {
            throw new ArgumentException(
                $"Batched scalar buffers must each be exactly {count} * {stride} bytes for count = {count}.");
        }

        //Use AddInternal rather than Add to avoid double-counting: the batched
        //counter has already been incremented by count, the inner per-element
        //operations must not bump ScalarAdd again on top of that.
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

        int stride = Scalar.SizeBytes;
        if(minuendsConcatenated.Length != count * stride
            || subtrahendsConcatenated.Length != count * stride
            || resultsConcatenated.Length != count * stride)
        {
            throw new ArgumentException(
                $"Batched scalar buffers must each be exactly {count} * {stride} bytes for count = {count}.");
        }

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

        int stride = Scalar.SizeBytes;
        if(leftOperandsConcatenated.Length != count * stride
            || rightOperandsConcatenated.Length != count * stride
            || resultsConcatenated.Length != count * stride)
        {
            throw new ArgumentException(
                $"Batched scalar buffers must each be exactly {count} * {stride} bytes for count = {count}.");
        }

        for(int i = 0; i < count; i++)
        {
            int offset = i * stride;
            MultiplyInternal(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>The arithmetic body of <see cref="Multiply"/> without the operation-counter increment, used by the batched path which has already counted the batch.</summary>
    private static void MultiplyInternal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        BigInteger left = ReadCanonical(a);
        BigInteger right = ReadCanonical(b);
        BigInteger product = (left * right) % FieldOrder;
        WriteCanonical(product, result);
    }


    /// <summary>The arithmetic body of <see cref="Add"/> without the operation-counter increment, used by the batched path which has already counted the batch.</summary>
    private static void AddInternal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        BigInteger left = ReadCanonical(a);
        BigInteger right = ReadCanonical(b);
        BigInteger sum = (left + right) % FieldOrder;
        WriteCanonical(sum, result);
    }


    /// <summary>The arithmetic body of <see cref="Subtract"/> without the operation-counter increment.</summary>
    private static void SubtractInternal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        BigInteger left = ReadCanonical(a);
        BigInteger right = ReadCanonical(b);
        BigInteger difference = ((left - right) % FieldOrder + FieldOrder) % FieldOrder;
        WriteCanonical(difference, result);
    }


    private static Tag Random(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarRandom, curve);
        return RandomCore(destination, curve, inboundTag);
    }


    private static Tag RandomCore(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        // Rejection sampling over a 32-byte buffer: draw, compare, retry if not less than r.
        // BN254's r begins at 0x30..., occupying roughly 19% of the 32-byte range, so the
        // acceptance probability per draw is about 0.19 and the expected number of draws is
        // around five — higher than BLS12-381's because BN254's order sits lower in the
        // 256-bit space, but still a small constant.
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
            inboundTag,
            ProviderLibraryIdentity,
            CryptoLibraryIdentity,
            ProviderClassIdentity,
            new ProviderOperation(nameof(Random)));
    }


    /// <summary>
    /// The uniform-output length <c>L = 48</c> for BN254 hash-to-scalar:
    /// <c>ceil((ceil(log2(r)) + k) / 8) = ceil((254 + 128) / 8)</c>.
    /// </summary>
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
            throw new ArgumentException(
                $"Hash-to-scalar result span must be exactly {Scalar.SizeBytes} bytes; received {result.Length}.",
                nameof(result));
        }

        Span<byte> uniform = stackalloc byte[HashToScalarUniformBytes];
        expandMessage(message, domainSeparationTag, uniform);

        BigInteger raw = new(uniform, isUnsigned: true, isBigEndian: true);
        BigInteger reduced = raw % FieldOrder;
        WriteCanonical(reduced, result);

        return ProviderInstrumentation.StampTag(
            inboundTag,
            ProviderLibraryIdentity,
            CryptoLibraryIdentity,
            ProviderClassIdentity,
            new ProviderOperation(nameof(HashToScalar)));
    }


    private static BigInteger ReadCanonical(ReadOnlySpan<byte> bytes)
    {
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        // Right-align: BigInteger.TryWriteBytes writes the minimal-length representation
        // starting at offset zero. Canonical big-endian needs the bytes at the high end
        // of the fixed-width span, with leading zeros in front.
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
