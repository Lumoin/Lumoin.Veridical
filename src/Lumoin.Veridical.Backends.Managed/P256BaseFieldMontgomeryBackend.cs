using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Allocation-free Montgomery arithmetic for the P-256 base field Fp256
/// (<c>p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1</c>), exposed as the canonical
/// <see cref="ScalarAddDelegate"/> family. This is one of two reduction-strategy
/// backends over the shared <see cref="PrimeField256"/> limb core (the other is
/// <see cref="P256BaseFieldSolinasBackend"/>); both are validated bit-for-bit
/// against the BigInteger oracle <see cref="P256BaseFieldReference"/>.
/// </summary>
/// <remarks>
/// <para>
/// Multiplication is Coarsely Integrated Operand Scanning (CIOS) Montgomery
/// reduction — multiply and reduce fused, the accumulator kept below 2p — and
/// inversion is Fermat (<c>a^(p−2)</c>) over a square-and-multiply ladder run
/// entirely in the Montgomery domain. The Montgomery constants (<c>N' = −p⁻¹ mod
/// 2⁶⁴</c>, <c>R² mod p</c>, <c>R mod p</c>, <c>p − 2</c>) are derived once at static
/// init from <see cref="P256BigIntegerG1Reference.BaseFieldPrime"/>, so the per-op
/// path is BigInteger-free and allocation-free. The <c>curve</c> argument is ignored
/// (base-field arithmetic is not curve-routed); callers pass
/// <see cref="CurveParameterSet.None"/>.
/// </para>
/// </remarks>
internal static class P256BaseFieldMontgomeryBackend
{
    private const int LimbCount = PrimeField256.LimbCount;
    private const int ExponentBitCount = LimbCount * 64;

    /// <summary>The number of accumulator limbs in the CIOS window: <see cref="LimbCount"/> plus two headroom limbs.</summary>
    private const int AccumulatorLimbCount = LimbCount + 2;

    //Signed-sparse limb offsets of p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1 in the 64-bit-limb specialized reduction.
    //With the quotient digit r = t[0] (because N' = 1), r·p = r·2²⁵⁶ − r·2²²⁴ + r·2¹⁹² + r·2⁹⁶ − r. The whole-limb
    //2²⁵⁶/2¹⁹²/2⁰ terms land on limbs {4, 3, 0}; the half-limb 2²²⁴ and 2⁹⁶ terms straddle two adjacent 64-bit
    //limbs, splitting into (r<<32) in the lower limb and (r>>32) in the next. The reference 64-bit
    //Fp256Reduce::reduction_step encodes these as negaccum l = {r, 0, 0, r<<32, r>>32} and accum h = {r<<32,
    //r>>32, r, r} starting one limb up.

    /// <summary>The limb where the specialized reduction subtracts <c>r</c> for the <c>−2⁰</c> term.</summary>
    private const int SparseSubtractWholeLimb = 0;

    /// <summary>The limb where the specialized reduction subtracts <c>r&lt;&lt;32</c> for the lower half of the <c>−2²²⁴</c> term.</summary>
    private const int SparseSubtractHalfLimbLow = 3;

    /// <summary>The limb where the specialized reduction subtracts <c>r&gt;&gt;32</c> for the upper half of the <c>−2²²⁴</c> term.</summary>
    private const int SparseSubtractHalfLimbHigh = 4;

    /// <summary>The limb where the specialized reduction's add window starts, adding <c>r&lt;&lt;32</c> for the lower half of the <c>+2⁹⁶</c> term.</summary>
    private const int SparseAddHalfLimbLow = 1;

    /// <summary>The limb where the specialized reduction adds <c>r&gt;&gt;32</c> for the upper half of the <c>+2⁹⁶</c> term.</summary>
    private const int SparseAddHalfLimbHigh = 2;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2¹⁹²</c> term.</summary>
    private const int SparseAddWholeLimbMid = 3;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2²⁵⁶</c> term.</summary>
    private const int SparseAddWholeLimbHigh = 4;

    private static readonly ulong[] ModulusLimbValues = ComputeModulusLimbs();
    private static readonly ulong NPrimeValue = ComputeNPrime();
    private static readonly ulong[] RSquaredLimbValues = ComputeRSquared();
    private static readonly ulong[] OneMontgomeryLimbValues = ComputeOneMontgomery();
    private static readonly ulong[] InversionExponentLimbValues = ComputeInversionExponent();

    private static ReadOnlySpan<ulong> ModulusLimbs => ModulusLimbValues;


    public static ScalarAddDelegate GetAdd() => Add;

    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    public static ScalarInvertDelegate GetInvert() => Invert;

    public static ScalarReduceDelegate GetReduce() => Reduce;


    //Montgomery-domain delegate family (Perf Increment 1).
    //The canonical delegates above lift to/from the Montgomery domain inside every multiply/invert (2 CIOS).
    //The Montgomery-domain delegates treat the 32-byte values as Montgomery residues (aR mod p), so a
    //multiply is a SINGLE CIOS (mont(a)·mont(b)·R⁻¹ = mont(ab)). Add/Subtract are domain-linear (residues
    //mod p), so the canonical Add/Subtract serve both domains unchanged. Values cross canonical<->Montgomery
    //only at the profile/witness/template/FFT-root boundaries via ToMontgomery/FromMontgomery.

    public static ScalarMultiplyDelegate GetMultiplyMontgomery() => MultiplyMontgomery;

    public static ScalarInvertDelegate GetInvertMontgomery() => InvertMontgomery;


    /// <summary>
    /// Converts a canonical (32-byte big-endian, &lt; p) base-field value into its Montgomery residue
    /// <c>aR mod p</c> via a single CIOS multiply by <c>R²</c>. The boundary lift the Fp256 Montgomery
    /// working domain enters through (the profile <c>OfScalar</c>/<c>FromBytesField</c>/<c>SampleElement</c>
    /// seams, the witness/template boundary, and the FFT root).
    /// </summary>
    /// <param name="canonical">The canonical value (32 bytes, big-endian, below the modulus).</param>
    /// <param name="montgomery">Receives the Montgomery residue (32 bytes, big-endian).</param>
    public static void ToMontgomery(ReadOnlySpan<byte> canonical, Span<byte> montgomery)
    {
        Span<ulong> limbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(canonical, limbs);

        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiply(limbs, RSquaredLimbValues, product);
        PrimeField256.StoreLimbsToCanonical(product, montgomery);
    }


    /// <summary>
    /// Converts a Montgomery residue <c>aR mod p</c> back to its canonical value via a single CIOS multiply
    /// by canonical <c>1</c> (<c>aR·1·R⁻¹ = a</c>). The boundary drop the Fp256 Montgomery working domain
    /// leaves through (the profile <c>ToBytesField</c> seam emitting wire bytes, and the template extraction).
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
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> sum = stackalloc ulong[LimbCount];
        PrimeField256.AddModP(aLimbs, bLimbs, ModulusLimbs, sum);
        PrimeField256.StoreLimbsToCanonical(sum, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> difference = stackalloc ulong[LimbCount];
        PrimeField256.SubtractModP(aLimbs, bLimbs, ModulusLimbs, difference);
        PrimeField256.StoreLimbsToCanonical(difference, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        //Lift a to Montgomery form (aR) via MontMul(a, R²), then MontMul(aR, b) =
        //ab mod p — the Montgomery domain is entered and left within this call.
        Span<ulong> aMontgomery = stackalloc ulong[LimbCount];
        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, RSquaredLimbValues, aMontgomery);
        MontgomeryMultiply(aMontgomery, bLimbs, product);
        PrimeField256.StoreLimbsToCanonical(product, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        if(PrimeField256.IsZero(aLimbs))
        {
            throw new InvalidOperationException("Zero is not invertible in the P-256 base field.");
        }

        //Windowed square-and-multiply over p − 2, entirely in the Montgomery domain:
        //the base is aR, the identity is R mod p, and base^(p−2) = a^(p−2)·R.
        Span<ulong> baseMontgomery = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, RSquaredLimbValues, baseMontgomery);

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        PrimeField256.WindowedExponentiate(baseMontgomery, OneMontgomeryLimbValues, InversionExponentLimbValues, ExponentBitCount, MontgomeryMultiply, accumulator);

        //Leave the Montgomery domain: MontMul by canonical 1.
        Span<ulong> canonicalOne = stackalloc ulong[LimbCount];
        canonicalOne.Clear();
        canonicalOne[0] = 1UL;

        Span<ulong> canonical = stackalloc ulong[LimbCount];
        MontgomeryMultiply(accumulator, canonicalOne, canonical);
        PrimeField256.StoreLimbsToCanonical(canonical, result);
    }


    //Reduces an up-to-512-bit canonical big-endian input mod p. Splits the input as
    //hi·2²⁵⁶ + lo; hi·2²⁵⁶ mod p is MontMul(hi, R²) (since R = 2²⁵⁶), then add lo.
    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve)
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
        MontgomeryMultiply(hiReduced, RSquaredLimbValues, hiShifted);

        Span<ulong> reduced = stackalloc ulong[LimbCount];
        PrimeField256.AddModP(hiShifted, loReduced, ModulusLimbs, reduced);
        PrimeField256.StoreLimbsToCanonical(reduced, result);
    }


    //Montgomery-domain multiply: both operands are Montgomery residues (aR, bR); MontMul(aR, bR) = abR =
    //mont(ab) in ONE CIOS (no R²-lift, the saving vs the canonical Multiply's two CIOS).
    private static void MultiplyMontgomery(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve) =>
        MultiplyMontgomeryCore(a, b, result);


    /// <summary>
    /// Counter-free single-CIOS Montgomery-domain multiply: both operands are Montgomery residues
    /// (<c>aR</c>, <c>bR</c>) and the result is <c>abR = mont(ab)</c>, byte-for-byte the body of
    /// <see cref="MultiplyMontgomery"/> (which is itself counter-free). The lane-parallel SIMD batch
    /// backends call this for their trailing 1–3 (AVX2) / 1–7 (AVX-512) elements so the batch's single
    /// per-call <c>ScalarBatchMultiply</c> increment — which already counts the tail elements — is not
    /// joined by a separate per-element bump, and so the tail produces output bit-identical to the
    /// quartet/octet kernel.
    /// </summary>
    /// <param name="a">The left Montgomery residue (32 bytes, big-endian).</param>
    /// <param name="b">The right Montgomery residue (32 bytes, big-endian).</param>
    /// <param name="result">Receives the Montgomery residue of the product (32 bytes, big-endian).</param>
    internal static void MultiplyMontgomeryCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, bLimbs, product);
        PrimeField256.StoreLimbsToCanonical(product, result);
    }


    /// <summary>
    /// Single-CIOS Montgomery-domain multiply that reduces with the P-256-specialized signed-sparse step
    /// (<see cref="MontgomeryMultiplySpecializedReduce"/>) rather than the generic per-limb modulus product
    /// (<c>m·n[j]</c>) that the live <see cref="MultiplyMontgomeryCore"/> runs. It produces the byte-identical
    /// Montgomery residue — Montgomery reduction is unique given <c>(p, R)</c> — and exists so the agreement gate
    /// can pin live(generic) == specialized == BigInteger over the same residues; it is the specialized
    /// reduction's hook into the scalar test, the counterpart of the batch backend's
    /// <c>P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomerySpecializedReduce</c>.
    /// </summary>
    /// <param name="a">The left Montgomery residue (32 bytes, big-endian).</param>
    /// <param name="b">The right Montgomery residue (32 bytes, big-endian).</param>
    /// <param name="result">Receives the Montgomery residue of the product (32 bytes, big-endian).</param>
    internal static void MultiplyMontgomerySpecializedReduce(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiplySpecializedReduce(aLimbs, bLimbs, product);
        PrimeField256.StoreLimbsToCanonical(product, result);
    }


    //Montgomery-domain inversion: the input is a Montgomery residue (aR), so the Fermat ladder runs with the
    //base ALREADY in the domain (no R²-lift) and the result a^(p−2)·R = mont(a⁻¹) is returned WITHOUT the
    //final drop to canonical — Montgomery in, Montgomery out.
    private static void InvertMontgomery(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> baseMontgomery = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, baseMontgomery);
        if(PrimeField256.IsZero(baseMontgomery))
        {
            throw new InvalidOperationException("Zero is not invertible in the P-256 base field.");
        }

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        PrimeField256.WindowedExponentiate(baseMontgomery, OneMontgomeryLimbValues, InversionExponentLimbValues, ExponentBitCount, MontgomeryMultiply, accumulator);
        PrimeField256.StoreLimbsToCanonical(accumulator, result);
    }


    //--- CIOS Montgomery multiply: two reduction strategies over the shared multiply-accumulate column ---
    //
    //Both compute result = a·b·R⁻¹ mod p; inputs are assumed < p and the output is reduced by one
    //constant-time conditional subtraction. The two methods share the identical multiply-accumulate half
    //(the a·b[i] column sum and the high-limb carry-out into the (LimbCount+2)-limb accumulator window); they
    //differ only in the per-outer-step CIOS reduction that adds the modulus multiple before the divide-by-2⁶⁴.
    //Montgomery reduction is unique given (p, R), so both emit the SAME canonical residue (the agreement test
    //pins live(generic) == specialized == BigInteger).
    //
    //MontgomeryMultiply is the generic CIOS reduction and the one the live Fp256 path runs: it forms the
    //per-step term r·p through the full m·n[j] modulus product (the textbook reduction, mirroring FpGeneric).
    //MontgomeryMultiplySpecializedReduce is the P-256-specialized signed-sparse reduction: because
    //p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1 is signed-sparse, the same r·p (with quotient digit r = t[0], since
    //N' = 1) is formed by subtracting/adding r at a handful of limb positions with no multiply by the modulus.
    //It is retained as the comparison/oracle counterpart (see its summary for why the generic form is the live
    //managed path). Both mirror Fp256Reduce in lib/algebra/fp_p256.h / fp_generic.h respectively.


    //Generic CIOS Montgomery multiply (the live sig-prove reduction). Each outer step accumulates the a·b[i]
    //column, then forms the quotient digit m = t[0]·N' (here N' = 1) and adds m·p through the full per-limb
    //modulus product before shifting the window down one limb. Textbook generic Montgomery reduction; mirrors
    //FpGeneric's reduction.
    private static void MontgomeryMultiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        ReadOnlySpan<ulong> n = ModulusLimbs;
        ulong nPrime = NPrimeValue;

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


    //Adds r·p for r = t[0] via the signed-sparse form of p, then shifts the accumulator window down one limb
    //(the CIOS divide by 2⁶⁴). With p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1 and N' = 1, the quotient digit is r = t[0]
    //and r·p = r·2²⁵⁶ − r·2²²⁴ + r·2¹⁹² + r·2⁹⁶ − r. In 64-bit limbs the whole-limb terms land on limbs
    //{0, 3, 4} and the half-limb 2²²⁴/2⁹⁶ terms split into (r<<32)/(r>>32) across adjacent limbs:
    //  negaccum: subtract {r@0, (r<<32)@3, (r>>32)@4}, borrow up through the full window (reference l = {r, 0,
    //            0, r<<32, r>>32} over width 6).
    //  accum:    add {(r<<32)@1, (r>>32)@2, r@3, r@4}, carry up through the window from limb 1 (reference
    //            h = {r<<32, r>>32, r, r} over width 5 starting one limb up).
    //Limb 0 cancels to zero after the r@0 subtraction, so the subsequent window shift discards it. Borrow/carry
    //ride bit 64 of the UInt128 difference/sum, matching the multiply-accumulate carry style above.
    private static void SpecializedReduceStep(Span<ulong> t)
    {
        ulong r = t[0];
        ulong rLow = r << 32;
        ulong rHigh = r >> 32;

        ulong borrow = 0UL;
        for(int j = 0; j < AccumulatorLimbCount; j++)
        {
            ulong subtrahend = j switch
            {
                SparseSubtractWholeLimb => r,
                SparseSubtractHalfLimbLow => rLow,
                SparseSubtractHalfLimbHigh => rHigh,
                _ => 0UL
            };
            UInt128 difference = (UInt128)t[j] - subtrahend - borrow;
            t[j] = (ulong)difference;
            borrow = (ulong)(difference >> 64) & 1UL;
        }

        ulong carry = 0UL;
        for(int j = SparseAddHalfLimbLow; j < AccumulatorLimbCount; j++)
        {
            ulong addend = j switch
            {
                SparseAddHalfLimbLow => rLow,
                SparseAddHalfLimbHigh => rHigh,
                SparseAddWholeLimbMid => r,
                SparseAddWholeLimbHigh => r,
                _ => 0UL
            };
            UInt128 sum = (UInt128)t[j] + addend + carry;
            t[j] = (ulong)sum;
            carry = (ulong)(sum >> 64);
        }

        for(int j = 1; j < AccumulatorLimbCount; j++)
        {
            t[j - 1] = t[j];
        }

        t[AccumulatorLimbCount - 1] = 0UL;
    }


    /// <summary>
    /// P-256-specialized signed-sparse CIOS Montgomery multiply, retained as the comparison/oracle counterpart
    /// of the live generic <see cref="MontgomeryMultiply"/>. It mirrors the 64-bit <c>Fp256Reduce</c> in
    /// google/longfellow-zk <c>lib/algebra/fp_p256.h</c>: with quotient digit <c>r = t[0]</c> (because
    /// <c>N' = 1</c>) the per-step term <c>r·p</c> is added as <c>−r</c>/<c>+r</c> at a handful of limb positions
    /// (see <see cref="SpecializedReduceStep"/>) with no multiply by the modulus, removing 20 of the 36 ulong
    /// multiplies per Montgomery multiply. In managed .NET it is nonetheless SLOWER than the generic
    /// <c>m·Modulus</c> reduction (no ADX/ADCX/ADOX, so the dependent borrow/carry chains cost more than the
    /// generic's pipelined multiplies). It is kept as the reference-faithful form and the right reduction for a
    /// future hand-asm / ADX-intrinsic backend; the generic reduction is the live managed path. The output is
    /// byte-identical to <see cref="MontgomeryMultiply"/> — Montgomery reduction is unique given <c>(p, R)</c>.
    /// </summary>
    private static void MontgomeryMultiplySpecializedReduce(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        ReadOnlySpan<ulong> n = ModulusLimbs;

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

            SpecializedReduceStep(t);
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount];
        t[..LimbCount].CopyTo(reduced);
        bool borrow = PrimeField256.SubtractWithBorrow(reduced, n);
        PrimeField256.Select(reduced, t[..LimbCount], (t[LimbCount] != 0UL) || !borrow, result);
    }


    //--- Constant derivation from the base-field prime (static-init only) ---

    private static ulong[] ComputeModulusLimbs()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(P256BigIntegerG1Reference.BaseFieldPrime, limbs);

        return limbs;
    }


    private static ulong ComputeNPrime()
    {
        BigInteger twoTo64 = BigInteger.One << 64;
        BigInteger lowInverse = ModularInverse(ModulusLimbValues[0] % twoTo64, twoTo64);

        return (ulong)((((twoTo64 - lowInverse) % twoTo64) + twoTo64) % twoTo64);
    }


    private static ulong[] ComputeRSquared()
    {
        BigInteger modulus = P256BigIntegerG1Reference.BaseFieldPrime;
        BigInteger rSquared = (BigInteger.One << (128 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(rSquared, limbs);

        return limbs;
    }


    private static ulong[] ComputeOneMontgomery()
    {
        BigInteger modulus = P256BigIntegerG1Reference.BaseFieldPrime;
        BigInteger r = (BigInteger.One << (64 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(r, limbs);

        return limbs;
    }


    private static ulong[] ComputeInversionExponent()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(P256BigIntegerG1Reference.BaseFieldPrime - 2, limbs);

        return limbs;
    }


    private static void BigIntegerToLimbs(BigInteger value, Span<ulong> limbs)
    {
        BigInteger mask = (BigInteger.One << 64) - 1;
        for(int i = 0; i < limbs.Length; i++)
        {
            limbs[i] = (ulong)((value >> (64 * i)) & mask);
        }
    }


    private static BigInteger ModularInverse(BigInteger value, BigInteger modulus)
    {
        BigInteger t = BigInteger.Zero;
        BigInteger newT = BigInteger.One;
        BigInteger r = modulus;
        BigInteger newR = value;

        while(newR != BigInteger.Zero)
        {
            BigInteger quotient = r / newR;
            (t, newT) = (newT, t - (quotient * newT));
            (r, newR) = (newR, r - (quotient * newR));
        }

        return ((t % modulus) + modulus) % modulus;
    }
}
