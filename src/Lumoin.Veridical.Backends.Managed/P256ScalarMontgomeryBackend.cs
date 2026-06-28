using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Constant-time Montgomery arithmetic for the NIST P-256 (secp256r1)
/// <em>scalar</em> field — arithmetic modulo the group order
/// <c>n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551</c> —
/// exposed as the canonical <see cref="ScalarAddDelegate"/> family. It is the
/// production replacement for the variable-time <see cref="BigInteger"/> path in
/// <see cref="P256BigIntegerScalarReference"/> on the secret-sensitive operations
/// (reduce, add, subtract, multiply, negate, invert), built to the same constant-time
/// discipline as the base-field <see cref="P256BaseFieldMontgomeryBackend"/> but over
/// <c>n</c> instead of <c>p</c>. It produces byte-identical results to the reference and
/// keeps the reference's <see cref="CryptographicOperationCounters"/> increments.
/// </summary>
/// <remarks>
/// <para>
/// Multiplication is the generic Coarsely Integrated Operand Scanning (CIOS) Montgomery
/// reduction (the per-step term <c>m·n</c> formed through the full per-limb modulus
/// product, since <c>n</c> is not signed-sparse the way <c>p</c> is), and inversion is
/// Fermat (<c>a^(n−2)</c>) over a fixed-window square-and-multiply ladder run entirely in
/// the Montgomery domain. The Montgomery constants are derived once at static init from
/// <see cref="P256BigIntegerScalarReference.FieldOrder"/> via
/// <see cref="P256ScalarMontgomeryParameters"/>, so the per-op path is
/// <see cref="BigInteger"/>-free.
/// </para>
/// <para>
/// <strong>Constant-time contract.</strong> No per-operation branch, array index, or loop
/// bound depends on a secret operand: loop counts are fixed by the limb count, the
/// add/subtract/Montgomery corrections use the branch-free <see cref="PrimeField256.Select"/>
/// mask, and the inversion ladder's control flow depends only on the bits of the
/// <em>public</em> fixed exponent <c>n − 2</c>, never on the secret base. The single
/// data-dependent branch in the whole backend is the documented zero-operand guard in
/// <see cref="Invert"/>, which throws (preserving the reference's contract) — the
/// non-invertible input is the public error condition, not a secret whose timing must be
/// hidden. The <c>curve</c> argument is <see cref="CurveParameterSet.P256"/> for counter
/// attribution; the arithmetic itself is not curve-routed.
/// </para>
/// </remarks>
internal static class P256ScalarMontgomeryBackend
{
    private const int LimbCount = P256ScalarMontgomeryParameters.LimbCount;
    private const int ExponentBitCount = LimbCount * 64;

    /// <summary>The number of accumulator limbs in the CIOS window: <see cref="LimbCount"/> plus two headroom limbs.</summary>
    private const int AccumulatorLimbCount = LimbCount + 2;


    private static ReadOnlySpan<ulong> ModulusLimbs => P256ScalarMontgomeryParameters.ModulusLimbs;

    private static ReadOnlySpan<ulong> RSquaredLimbs => P256ScalarMontgomeryParameters.RSquaredLimbs;

    private static ReadOnlySpan<ulong> OneMontgomeryLimbs => P256ScalarMontgomeryParameters.OneMontgomeryLimbs;

    private static ReadOnlySpan<ulong> InversionExponentLimbs => P256ScalarMontgomeryParameters.InversionExponentLimbs;


    /// <summary>Returns the constant-time scalar-add delegate.</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the constant-time scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the constant-time scalar-multiply delegate.</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the constant-time scalar-negate delegate.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>Returns the constant-time scalar-invert delegate.</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>Returns the constant-time scalar-reduce delegate.</summary>
    public static ScalarReduceDelegate GetReduce() => Reduce;

    /// <summary>Returns the batched scalar-add delegate (a loop over the single-element constant-time path).</summary>
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the batched scalar-subtract delegate.</summary>
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>Returns the batched scalar-multiply delegate.</summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;


    /// <summary>
    /// Converts a canonical (32-byte big-endian, &lt; n) scalar into its Montgomery residue
    /// <c>aR mod n</c> via a single CIOS multiply by <c>R²</c>.
    /// </summary>
    /// <param name="canonical">The canonical value (32 bytes, big-endian, below the order).</param>
    /// <param name="montgomery">Receives the Montgomery residue (32 bytes, big-endian).</param>
    public static void ToMontgomery(ReadOnlySpan<byte> canonical, Span<byte> montgomery)
    {
        Span<ulong> limbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(canonical, limbs);

        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiply(limbs, RSquaredLimbs, product);
        PrimeField256.StoreLimbsToCanonical(product, montgomery);
    }


    /// <summary>
    /// Converts a Montgomery residue <c>aR mod n</c> back to its canonical value via a single CIOS multiply
    /// by canonical <c>1</c> (<c>aR·1·R⁻¹ = a</c>).
    /// </summary>
    /// <param name="montgomery">The Montgomery residue (32 bytes, big-endian).</param>
    /// <param name="canonical">Receives the canonical value (32 bytes, big-endian).</param>
    public static void FromMontgomery(ReadOnlySpan<byte> montgomery, Span<byte> canonical)
    {
        Span<ulong> limbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(montgomery, limbs);

        Span<ulong> canonicalOne = stackalloc ulong[LimbCount];
        canonicalOne.Clear();
        canonicalOne[0] = 1UL;

        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiply(limbs, canonicalOne, product);
        PrimeField256.StoreLimbsToCanonical(product, canonical);
    }


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);
        AddCore(a, b, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarSubtract, curve);
        SubtractCore(a, b, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);
        MultiplyCore(a, b, result);
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarNegate, curve);
        NegateCore(a, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarInvert, curve);

        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);

        //The one data-dependent branch in the backend: zero is non-invertible, the public error condition the
        //reference also throws on (BigInteger.ModPow would silently return 0). IsZero accumulates all limbs with
        //no early exit, so the test itself is constant-time; only the throw discriminates, and a non-invertible
        //operand is not a secret whose timing must be hidden.
        if(PrimeField256.IsZero(aLimbs))
        {
            throw new InvalidOperationException("Zero is not invertible in the P-256 scalar field.");
        }

        //Fermat inverse a^(n−2) mod n via a fixed-window square-and-multiply ladder run entirely in the
        //Montgomery domain: lift a to aR, exponentiate with the Montgomery identity R mod n as the seed, and
        //a^(n−2)·R results. The ladder's control flow (squarings, the per-window multiply skip) depends only on
        //the bits of the PUBLIC fixed exponent n−2, never on the secret base.
        Span<ulong> baseMontgomery = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, RSquaredLimbs, baseMontgomery);

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        PrimeField256.WindowedExponentiate(baseMontgomery, OneMontgomeryLimbs, InversionExponentLimbs, ExponentBitCount, MontgomeryMultiply, accumulator);

        //Leave the Montgomery domain: MontMul by canonical 1.
        Span<ulong> canonicalOne = stackalloc ulong[LimbCount];
        canonicalOne.Clear();
        canonicalOne[0] = 1UL;

        Span<ulong> canonical = stackalloc ulong[LimbCount];
        MontgomeryMultiply(accumulator, canonicalOne, canonical);
        PrimeField256.StoreLimbsToCanonical(canonical, result);
    }


    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarReduce, curve);
        ReduceCore(input, result);
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
            AddCore(
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
            SubtractCore(
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
            MultiplyCore(
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


    private static void AddCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> sum = stackalloc ulong[LimbCount];
        PrimeField256.AddModP(aLimbs, bLimbs, ModulusLimbs, sum);
        PrimeField256.StoreLimbsToCanonical(sum, result);
    }


    private static void SubtractCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> difference = stackalloc ulong[LimbCount];
        PrimeField256.SubtractModP(aLimbs, bLimbs, ModulusLimbs, difference);
        PrimeField256.StoreLimbsToCanonical(difference, result);
    }


    private static void MultiplyCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        //Lift a to Montgomery form (aR) via MontMul(a, R²), then MontMul(aR, b) = ab mod n — the Montgomery
        //domain is entered and left within this call.
        Span<ulong> aMontgomery = stackalloc ulong[LimbCount];
        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, RSquaredLimbs, aMontgomery);
        MontgomeryMultiply(aMontgomery, bLimbs, product);
        PrimeField256.StoreLimbsToCanonical(product, result);
    }


    private static void NegateCore(ReadOnlySpan<byte> a, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);

        //n − a mod n, computed branch-free as (0 − a) mod n: SubtractModP adds n back exactly when the
        //subtraction borrows (a > 0), so a = 0 maps to 0 and a > 0 maps to n − a, matching the reference's
        //value.IsZero ? 0 : n − value without a value-dependent branch.
        Span<ulong> zero = stackalloc ulong[LimbCount];
        zero.Clear();

        Span<ulong> negated = stackalloc ulong[LimbCount];
        PrimeField256.SubtractModP(zero, aLimbs, ModulusLimbs, negated);
        PrimeField256.StoreLimbsToCanonical(negated, result);
    }


    //Reduces an up-to-512-bit canonical big-endian input mod n. Splits the input as hi·2²⁵⁶ + lo; since
    //2²⁵⁶ < 2n a single conditional subtraction canonicalises each half, hi·2²⁵⁶ mod n is MontMul(hi, R²)
    //(because R = 2²⁵⁶), and the two halves are then added mod n. Branch-free apart from the public input-length
    //guard. Mirrors the base-field P256BaseFieldMontgomeryBackend.Reduce.
    private static void ReduceCore(ReadOnlySpan<byte> input, Span<byte> result)
    {
        if(input.Length > 2 * LimbCount * 8)
        {
            throw new ArgumentException($"Reduce input must be at most {2 * LimbCount * 8} bytes; received {input.Length}.", nameof(input));
        }

        Span<byte> wide = stackalloc byte[2 * LimbCount * 8];
        wide.Clear();
        input.CopyTo(wide[(wide.Length - input.Length)..]);

        Span<ulong> lo = stackalloc ulong[LimbCount];
        Span<ulong> hi = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(wide[(LimbCount * 8)..], lo);
        PrimeField256.LoadCanonicalToLimbs(wide[..(LimbCount * 8)], hi);

        Span<ulong> loReduced = stackalloc ulong[LimbCount];
        Span<ulong> hiReduced = stackalloc ulong[LimbCount];
        PrimeField256.ConditionalSubtractOnce(lo, ModulusLimbs, loReduced);
        PrimeField256.ConditionalSubtractOnce(hi, ModulusLimbs, hiReduced);

        Span<ulong> hiShifted = stackalloc ulong[LimbCount];
        MontgomeryMultiply(hiReduced, RSquaredLimbs, hiShifted);

        Span<ulong> reduced = stackalloc ulong[LimbCount];
        PrimeField256.AddModP(hiShifted, loReduced, ModulusLimbs, reduced);
        PrimeField256.StoreLimbsToCanonical(reduced, result);
    }


    //Generic constant-time CIOS Montgomery multiply: result = a·b·R⁻¹ mod n, inputs assumed < n, output reduced
    //by one branch-free conditional subtraction. Each outer step accumulates the a·b[i] column, forms the
    //quotient digit m = t[0]·N', then adds m·n through the full per-limb modulus product before shifting the
    //(LimbCount+2)-limb window down one limb. Unlike the base field's p, n is not signed-sparse, so the generic
    //per-limb reduction (mirroring FpGeneric) is the only form here. Loop bounds are fixed by LimbCount; no
    //control flow depends on operand values.
    private static void MontgomeryMultiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        ReadOnlySpan<ulong> n = ModulusLimbs;
        ulong nPrime = P256ScalarMontgomeryParameters.NPrime;

        Span<ulong> t = stackalloc ulong[AccumulatorLimbCount];
        t.Clear();

        for(int i = 0; i < LimbCount; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount; j++)
            {
                UInt128 product = (UInt128)t[j] + ((UInt128)a[j] * b[i]) + carry;
                t[j] = (ulong)product;
                carry = (ulong)(product >> 64);
            }

            UInt128 highSum = (UInt128)t[LimbCount] + carry;
            t[LimbCount] = (ulong)highSum;
            t[LimbCount + 1] = (ulong)(highSum >> 64);

            ulong m = unchecked(t[0] * nPrime);
            UInt128 reduceLow = (UInt128)t[0] + ((UInt128)m * n[0]);
            carry = (ulong)(reduceLow >> 64);
            for(int j = 1; j < LimbCount; j++)
            {
                UInt128 reduceTerm = (UInt128)t[j] + ((UInt128)m * n[j]) + carry;
                t[j - 1] = (ulong)reduceTerm;
                carry = (ulong)(reduceTerm >> 64);
            }

            UInt128 reduceHigh = (UInt128)t[LimbCount] + carry;
            t[LimbCount - 1] = (ulong)reduceHigh;
            t[LimbCount] = t[LimbCount + 1] + (ulong)(reduceHigh >> 64);
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount];
        t[..LimbCount].CopyTo(reduced);
        bool borrow = PrimeField256.SubtractWithBorrow(reduced, n);
        PrimeField256.Select(reduced, t[..LimbCount], (t[LimbCount] != 0UL) || !borrow, result);
    }
}
