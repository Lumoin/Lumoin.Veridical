using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Benchmarks.Scalar;

/// <summary>
/// Per-call timing of the limb carry chains behind the Montgomery and schoolbook multiplies,
/// written two ways: the <see cref="UInt128"/> form the kernels use, where each inner step is
/// <c>(UInt128)t + (UInt128)a · b + carry</c>, and a form built on
/// <see cref="Math.BigMul(ulong, ulong, out ulong)"/> with the two carries propagated by hand.
/// Each pair of rows is the same algorithm over the same operands, so a ratio other than 1.00
/// is the cost or gain of the product form alone.
/// </summary>
/// <remarks>
/// <para>
/// Three chains are measured, each in both forms: the four-limb CIOS Montgomery multiply over
/// the BLS12-381 scalar field, which is the shape of every 256-bit Montgomery kernel; the
/// six-limb CIOS multiply over the BLS12-381 base field; and the four-by-four schoolbook
/// widening product. Loop bounds are compile-time constants, as in the kernels, so the JIT sees
/// the same trip counts, and each CIOS row ends with the branch-free conditional subtraction of
/// <see cref="PrimeField256"/> or <see cref="PrimeField384"/>, the tail the base-field kernels
/// call (the scalar-field kernels carry a private tail of the same shape), so a row is the cost
/// of one whole multiply.
/// </para>
/// <para>
/// <see cref="Setup"/> checks the two forms against each other on the benchmark operands and on
/// two sweeps of further operands, one below the moduli and one over the full limb range, so
/// every carry site of the hand-propagated form, the guard words included, is exercised and a
/// defect fails the setup instead of timing a wrong computation.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class LimbProductFormBenchmarks
{
    /// <summary>Category of the four-limb CIOS Montgomery multiply rows.</summary>
    private const string Cios256Category = "CIOS 4-limb";

    /// <summary>Category of the six-limb CIOS Montgomery multiply rows.</summary>
    private const string Cios384Category = "CIOS 6-limb";

    /// <summary>Category of the four-by-four schoolbook widening product rows.</summary>
    private const string SchoolbookCategory = "Schoolbook 4x4";

    /// <summary>Limbs in a 256-bit element, the library's own count.</summary>
    private const int LimbCount256 = PrimeField256.LimbCount;

    /// <summary>Limbs in a 384-bit element, the library's own count.</summary>
    private const int LimbCount384 = PrimeField384.LimbCount;

    /// <summary>Bits per limb.</summary>
    private const int LimbBits = 64;

    /// <summary>Guard words above the result words that hold each CIOS pass's carry-out.</summary>
    private const int GuardLimbCount = 2;

    /// <summary>Accumulator width of the four-limb CIOS multiply.</summary>
    private const int AccumulatorLimbCount256 = LimbCount256 + GuardLimbCount;

    /// <summary>Accumulator width of the six-limb CIOS multiply.</summary>
    private const int AccumulatorLimbCount384 = LimbCount384 + GuardLimbCount;

    /// <summary>A 256 × 256-bit product spans eight limbs, the library's own wide count.</summary>
    private const int WideLimbCount = PrimeField256.WideLimbCount;

    /// <summary>Seed of the deterministic operand fill, so successive runs measure the same inputs.</summary>
    private const int BenchmarkSeed = 0x5EED5EED;

    /// <summary>Further operand pairs the setup cross-check sweeps beyond the benchmark operands.</summary>
    private const int CrossCheckPairs = 256;

    /// <summary>
    /// Clears the top four bits of the top limb, so a random 256-bit operand stays below the
    /// BLS12-381 scalar-field modulus, whose top limb is 0x73ed…, as the CIOS inputs must.
    /// </summary>
    private const ulong TopLimbMask256 = 0x0FFFFFFFFFFFFFFFUL;

    /// <summary>
    /// Clears the top eight bits of the top limb, so a random 384-bit operand stays below the
    /// BLS12-381 base-field modulus, whose top limb is 0x1a01….
    /// </summary>
    private const ulong TopLimbMask384 = 0x00FFFFFFFFFFFFFFUL;

    /// <summary>
    /// Keeps every limb bit, so the unreduced sweep drives the accumulator's guard-word carries,
    /// which operands below the moduli can never set: for a, b below n the CIOS value stays
    /// below (2n − 1) · 2⁶⁴, one bit short of the guard word.
    /// </summary>
    private const ulong FullLimbMask = ulong.MaxValue;

    /// <summary>−p⁻¹ mod 2⁶⁴ for the BLS12-381 base field p: the CIOS quotient-digit multiplier.</summary>
    private const ulong BaseFieldNPrime = 0x89f3fffcfffcfffdUL;

    /// <summary>The BLS12-381 base-field modulus p as six little-endian 64-bit limbs.</summary>
    private static ulong[] BaseFieldModulusLimbs { get; } =
    [
        0xb9feffffffffaaabUL,
        0x1eabfffeb153ffffUL,
        0x6730d2a0f6b0f624UL,
        0x64774b84f38512bfUL,
        0x4b1ba7b6434bacd7UL,
        0x1a0111ea397fe69aUL
    ];


    /// <summary>First operand of the four-limb rows: a scalar-field element below r, little-endian limbs.</summary>
    private ulong[] scalarFieldA = null!;

    /// <summary>Second operand of the four-limb rows: a scalar-field element below r, little-endian limbs.</summary>
    private ulong[] scalarFieldB = null!;

    /// <summary>First operand of the six-limb rows: a base-field element below p, little-endian limbs.</summary>
    private ulong[] baseFieldA = null!;

    /// <summary>Second operand of the six-limb rows: a base-field element below p, little-endian limbs.</summary>
    private ulong[] baseFieldB = null!;

    /// <summary>Result buffer of the four-limb CIOS rows.</summary>
    private ulong[] product256 = null!;

    /// <summary>Result buffer of the six-limb CIOS rows.</summary>
    private ulong[] product384 = null!;

    /// <summary>Result buffer of the schoolbook rows: the eight-limb widening product.</summary>
    private ulong[] productWide = null!;


    /// <summary>
    /// Fills the operands deterministically, verifies the base-field constants against the
    /// library's own prime, and cross-checks the two forms of every chain on the operands, on a
    /// sweep below the moduli, on a sweep over the full limb range and on all-ones operands.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        if(unchecked(BaseFieldNPrime * BaseFieldModulusLimbs[0]) != ulong.MaxValue)
        {
            throw new InvalidOperationException("The base-field N' does not satisfy N'·p ≡ −1 mod 2⁶⁴.");
        }

        Span<ulong> primeLimbs = stackalloc ulong[LimbCount384];
        BigInteger prime = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
        BigInteger limbMask = (BigInteger.One << LimbBits) - BigInteger.One;
        for(int i = 0; i < LimbCount384; i++)
        {
            primeLimbs[i] = (ulong)((prime >> (LimbBits * i)) & limbMask);
        }

        if(!primeLimbs.SequenceEqual(BaseFieldModulusLimbs))
        {
            throw new InvalidOperationException("The base-field modulus limbs differ from the library's BLS12-381 base-field prime.");
        }

        Random rng = new(BenchmarkSeed);
        scalarFieldA = RandomOperand(rng, LimbCount256, TopLimbMask256);
        scalarFieldB = RandomOperand(rng, LimbCount256, TopLimbMask256);
        baseFieldA = RandomOperand(rng, LimbCount384, TopLimbMask384);
        baseFieldB = RandomOperand(rng, LimbCount384, TopLimbMask384);
        product256 = new ulong[LimbCount256];
        product384 = new ulong[LimbCount384];
        productWide = new ulong[WideLimbCount];

        CrossCheck(scalarFieldA, scalarFieldB, baseFieldA, baseFieldB);
        SweepCrossCheck(rng, TopLimbMask256, TopLimbMask384);
        SweepCrossCheck(rng, FullLimbMask, FullLimbMask);

        Span<ulong> allOnes256 = stackalloc ulong[LimbCount256];
        allOnes256.Fill(ulong.MaxValue);
        Span<ulong> allOnes384 = stackalloc ulong[LimbCount384];
        allOnes384.Fill(ulong.MaxValue);
        CrossCheck(allOnes256, allOnes256, allOnes384, allOnes384);
    }


    /// <summary>
    /// Cross-checks every chain on <see cref="CrossCheckPairs"/> further operand pairs drawn from
    /// <paramref name="rng"/>, with the top limbs masked as given: the reduced masks keep the
    /// operands below the moduli, <see cref="FullLimbMask"/> lets them exceed them.
    /// </summary>
    private static void SweepCrossCheck(Random rng, ulong topLimbMask256, ulong topLimbMask384)
    {
        Span<ulong> sweepScalarA = stackalloc ulong[LimbCount256];
        Span<ulong> sweepScalarB = stackalloc ulong[LimbCount256];
        Span<ulong> sweepBaseA = stackalloc ulong[LimbCount384];
        Span<ulong> sweepBaseB = stackalloc ulong[LimbCount384];
        for(int pair = 0; pair < CrossCheckPairs; pair++)
        {
            FillOperand(rng, sweepScalarA, topLimbMask256);
            FillOperand(rng, sweepScalarB, topLimbMask256);
            FillOperand(rng, sweepBaseA, topLimbMask384);
            FillOperand(rng, sweepBaseB, topLimbMask384);
            CrossCheck(sweepScalarA, sweepScalarB, sweepBaseA, sweepBaseB);
        }
    }


    /// <summary>Benchmarks the four-limb CIOS multiply in the <see cref="UInt128"/> form the kernels use.</summary>
    [BenchmarkCategory(Cios256Category)]
    [Benchmark(Baseline = true, Description = "UInt128 form")]
    public void Cios256UInt128() =>
        MontgomeryMultiply256UInt128(scalarFieldA, scalarFieldB, Bls12Curve381MontgomeryParameters.ModulusLimbs, Bls12Curve381MontgomeryParameters.NPrime, product256);


    /// <summary>Benchmarks the four-limb CIOS multiply in the <see cref="Math.BigMul(ulong, ulong, out ulong)"/> form.</summary>
    [BenchmarkCategory(Cios256Category)]
    [Benchmark(Description = "BigMul form")]
    public void Cios256BigMul() =>
        MontgomeryMultiply256BigMul(scalarFieldA, scalarFieldB, Bls12Curve381MontgomeryParameters.ModulusLimbs, Bls12Curve381MontgomeryParameters.NPrime, product256);


    /// <summary>Benchmarks the six-limb CIOS multiply in the <see cref="UInt128"/> form the kernels use.</summary>
    [BenchmarkCategory(Cios384Category)]
    [Benchmark(Baseline = true, Description = "UInt128 form")]
    public void Cios384UInt128() =>
        MontgomeryMultiply384UInt128(baseFieldA, baseFieldB, BaseFieldModulusLimbs, BaseFieldNPrime, product384);


    /// <summary>Benchmarks the six-limb CIOS multiply in the <see cref="Math.BigMul(ulong, ulong, out ulong)"/> form.</summary>
    [BenchmarkCategory(Cios384Category)]
    [Benchmark(Description = "BigMul form")]
    public void Cios384BigMul() =>
        MontgomeryMultiply384BigMul(baseFieldA, baseFieldB, BaseFieldModulusLimbs, BaseFieldNPrime, product384);


    /// <summary>Benchmarks the four-by-four schoolbook widening product in the <see cref="UInt128"/> form the kernels use.</summary>
    [BenchmarkCategory(SchoolbookCategory)]
    [Benchmark(Baseline = true, Description = "UInt128 form")]
    public void SchoolbookUInt128() => MultiplyWideUInt128(scalarFieldA, scalarFieldB, productWide);


    /// <summary>Benchmarks the four-by-four schoolbook widening product in the <see cref="Math.BigMul(ulong, ulong, out ulong)"/> form.</summary>
    [BenchmarkCategory(SchoolbookCategory)]
    [Benchmark(Description = "BigMul form")]
    public void SchoolbookBigMul() => MultiplyWideBigMul(scalarFieldA, scalarFieldB, productWide);


    /// <summary>Allocates an operand of <paramref name="limbCount"/> limbs and fills it through <see cref="FillOperand"/>.</summary>
    private static ulong[] RandomOperand(Random rng, int limbCount, ulong topLimbMask)
    {
        ulong[] operand = new ulong[limbCount];
        FillOperand(rng, operand, topLimbMask);

        return operand;
    }


    /// <summary>Fills every limb from <paramref name="rng"/> and masks the top limb so the operand stays below the field modulus.</summary>
    private static void FillOperand(Random rng, Span<ulong> operand, ulong topLimbMask)
    {
        rng.NextBytes(MemoryMarshal.AsBytes(operand));
        operand[^1] &= topLimbMask;
    }


    /// <summary>
    /// Runs every chain in both forms on the given operands and throws when a pair disagrees, so
    /// the benchmark never times a form that computes a different value.
    /// </summary>
    private static void CrossCheck(ReadOnlySpan<ulong> scalarA, ReadOnlySpan<ulong> scalarB, ReadOnlySpan<ulong> baseA, ReadOnlySpan<ulong> baseB)
    {
        ReadOnlySpan<ulong> scalarModulus = Bls12Curve381MontgomeryParameters.ModulusLimbs;
        ulong scalarNPrime = Bls12Curve381MontgomeryParameters.NPrime;

        Span<ulong> expected256 = stackalloc ulong[LimbCount256];
        Span<ulong> actual256 = stackalloc ulong[LimbCount256];
        MontgomeryMultiply256UInt128(scalarA, scalarB, scalarModulus, scalarNPrime, expected256);
        MontgomeryMultiply256BigMul(scalarA, scalarB, scalarModulus, scalarNPrime, actual256);
        if(!expected256.SequenceEqual(actual256))
        {
            throw new InvalidOperationException("The BigMul form of the four-limb CIOS multiply disagrees with the UInt128 form.");
        }

        Span<ulong> expected384 = stackalloc ulong[LimbCount384];
        Span<ulong> actual384 = stackalloc ulong[LimbCount384];
        MontgomeryMultiply384UInt128(baseA, baseB, BaseFieldModulusLimbs, BaseFieldNPrime, expected384);
        MontgomeryMultiply384BigMul(baseA, baseB, BaseFieldModulusLimbs, BaseFieldNPrime, actual384);
        if(!expected384.SequenceEqual(actual384))
        {
            throw new InvalidOperationException("The BigMul form of the six-limb CIOS multiply disagrees with the UInt128 form.");
        }

        Span<ulong> expectedWide = stackalloc ulong[WideLimbCount];
        Span<ulong> actualWide = stackalloc ulong[WideLimbCount];
        MultiplyWideUInt128(scalarA, scalarB, expectedWide);
        MultiplyWideBigMul(scalarA, scalarB, actualWide);
        if(!expectedWide.SequenceEqual(actualWide))
        {
            throw new InvalidOperationException("The BigMul form of the schoolbook product disagrees with the UInt128 form.");
        }
    }


    /// <summary>
    /// One carry-chain step in the <see cref="Math.BigMul(ulong, ulong, out ulong)"/> form: returns
    /// the low word of <c>a · b + addend + carryIn</c> and writes the high word to
    /// <paramref name="carryOut"/>. The sum fits in 128 bits for every input, because
    /// (2⁶⁴ − 1)² + 2 · (2⁶⁴ − 1) = 2¹²⁸ − 1, so neither carry addition can overflow the high word.
    /// The carries are read off comparisons through the same bool-to-byte reinterpretation
    /// <see cref="PrimeField256.Select"/> and <see cref="PrimeField384.Select"/> use for their
    /// masks, so no value-dependent branch enters the chain.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong MultiplyAccumulate(ulong a, ulong b, ulong addend, ulong carryIn, out ulong carryOut)
    {
        ulong high = Math.BigMul(a, b, out ulong low);
        ulong sum = low + addend;
        ulong sumCarry = (ulong)Unsafe.BitCast<bool, byte>(sum < low);
        ulong total = sum + carryIn;
        ulong totalCarry = (ulong)Unsafe.BitCast<bool, byte>(total < sum);
        carryOut = high + sumCarry + totalCarry;

        return total;
    }


    /// <summary>
    /// The four-limb CIOS Montgomery multiply with the loop of
    /// <see cref="Bls12Curve381MontgomeryArithmetic"/>, every inner step a <see cref="UInt128"/>
    /// sum, and the conditional subtraction of <see cref="PrimeField256"/> as its tail.
    /// </summary>
    private static void MontgomeryMultiply256UInt128(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, ReadOnlySpan<ulong> n, ulong nPrime, Span<ulong> result)
    {
        Span<ulong> t = stackalloc ulong[AccumulatorLimbCount256];
        t.Clear();

        for(int i = 0; i < LimbCount256; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount256; j++)
            {
                UInt128 product = (UInt128)t[j] + ((UInt128)a[j] * b[i]) + carry;
                t[j] = (ulong)product;
                carry = (ulong)(product >> 64);
            }

            UInt128 highSum = (UInt128)t[LimbCount256] + carry;
            t[LimbCount256] = (ulong)highSum;
            t[LimbCount256 + 1] = (ulong)(highSum >> 64);

            ulong m = unchecked(t[0] * nPrime);
            UInt128 reduceLow = (UInt128)t[0] + ((UInt128)m * n[0]);
            carry = (ulong)(reduceLow >> 64);
            for(int j = 1; j < LimbCount256; j++)
            {
                UInt128 reduceTerm = (UInt128)t[j] + ((UInt128)m * n[j]) + carry;
                t[j - 1] = (ulong)reduceTerm;
                carry = (ulong)(reduceTerm >> 64);
            }

            UInt128 reduceHigh = (UInt128)t[LimbCount256] + carry;
            t[LimbCount256 - 1] = (ulong)reduceHigh;
            t[LimbCount256] = t[LimbCount256 + 1] + (ulong)(reduceHigh >> 64);
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount256];
        t[..LimbCount256].CopyTo(reduced);
        bool borrow = PrimeField256.SubtractWithBorrow(reduced, n);
        PrimeField256.Select(reduced, t[..LimbCount256], (t[LimbCount256] != 0UL) | !borrow, result);
    }


    /// <summary>The four-limb CIOS Montgomery multiply with every inner step in the <see cref="MultiplyAccumulate"/> form.</summary>
    private static void MontgomeryMultiply256BigMul(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, ReadOnlySpan<ulong> n, ulong nPrime, Span<ulong> result)
    {
        Span<ulong> t = stackalloc ulong[AccumulatorLimbCount256];
        t.Clear();

        for(int i = 0; i < LimbCount256; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount256; j++)
            {
                t[j] = MultiplyAccumulate(a[j], b[i], t[j], carry, out carry);
            }

            ulong highSum = t[LimbCount256] + carry;
            t[LimbCount256 + 1] = (ulong)Unsafe.BitCast<bool, byte>(highSum < carry);
            t[LimbCount256] = highSum;

            //The low word of t[0] + m·n[0] is zero by the choice of m, so only its carry is kept.
            ulong m = unchecked(t[0] * nPrime);
            _ = MultiplyAccumulate(m, n[0], t[0], 0UL, out carry);
            for(int j = 1; j < LimbCount256; j++)
            {
                t[j - 1] = MultiplyAccumulate(m, n[j], t[j], carry, out carry);
            }

            ulong reduceHigh = t[LimbCount256] + carry;
            t[LimbCount256 - 1] = reduceHigh;
            t[LimbCount256] = t[LimbCount256 + 1] + (ulong)Unsafe.BitCast<bool, byte>(reduceHigh < carry);
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount256];
        t[..LimbCount256].CopyTo(reduced);
        bool borrow = PrimeField256.SubtractWithBorrow(reduced, n);
        PrimeField256.Select(reduced, t[..LimbCount256], (t[LimbCount256] != 0UL) | !borrow, result);
    }


    /// <summary>The six-limb CIOS Montgomery multiply exactly as the 384-bit kernel writes it: every inner step is a <see cref="UInt128"/> sum.</summary>
    private static void MontgomeryMultiply384UInt128(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, ReadOnlySpan<ulong> n, ulong nPrime, Span<ulong> result)
    {
        Span<ulong> t = stackalloc ulong[AccumulatorLimbCount384];
        t.Clear();

        for(int i = 0; i < LimbCount384; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount384; j++)
            {
                UInt128 product = (UInt128)t[j] + ((UInt128)a[j] * b[i]) + carry;
                t[j] = (ulong)product;
                carry = (ulong)(product >> 64);
            }

            UInt128 highSum = (UInt128)t[LimbCount384] + carry;
            t[LimbCount384] = (ulong)highSum;
            t[LimbCount384 + 1] = (ulong)(highSum >> 64);

            ulong m = unchecked(t[0] * nPrime);
            UInt128 reduceLow = (UInt128)t[0] + ((UInt128)m * n[0]);
            carry = (ulong)(reduceLow >> 64);
            for(int j = 1; j < LimbCount384; j++)
            {
                UInt128 reduceTerm = (UInt128)t[j] + ((UInt128)m * n[j]) + carry;
                t[j - 1] = (ulong)reduceTerm;
                carry = (ulong)(reduceTerm >> 64);
            }

            UInt128 reduceHigh = (UInt128)t[LimbCount384] + carry;
            t[LimbCount384 - 1] = (ulong)reduceHigh;
            t[LimbCount384] = t[LimbCount384 + 1] + (ulong)(reduceHigh >> 64);
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount384];
        t[..LimbCount384].CopyTo(reduced);
        bool borrow = PrimeField384.SubtractWithBorrow(reduced, n);
        PrimeField384.Select(reduced, t[..LimbCount384], (t[LimbCount384] != 0UL) | !borrow, result);
    }


    /// <summary>The six-limb CIOS Montgomery multiply with every inner step in the <see cref="MultiplyAccumulate"/> form.</summary>
    private static void MontgomeryMultiply384BigMul(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, ReadOnlySpan<ulong> n, ulong nPrime, Span<ulong> result)
    {
        Span<ulong> t = stackalloc ulong[AccumulatorLimbCount384];
        t.Clear();

        for(int i = 0; i < LimbCount384; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount384; j++)
            {
                t[j] = MultiplyAccumulate(a[j], b[i], t[j], carry, out carry);
            }

            ulong highSum = t[LimbCount384] + carry;
            t[LimbCount384 + 1] = (ulong)Unsafe.BitCast<bool, byte>(highSum < carry);
            t[LimbCount384] = highSum;

            //The low word of t[0] + m·n[0] is zero by the choice of m, so only its carry is kept.
            ulong m = unchecked(t[0] * nPrime);
            _ = MultiplyAccumulate(m, n[0], t[0], 0UL, out carry);
            for(int j = 1; j < LimbCount384; j++)
            {
                t[j - 1] = MultiplyAccumulate(m, n[j], t[j], carry, out carry);
            }

            ulong reduceHigh = t[LimbCount384] + carry;
            t[LimbCount384 - 1] = reduceHigh;
            t[LimbCount384] = t[LimbCount384 + 1] + (ulong)Unsafe.BitCast<bool, byte>(reduceHigh < carry);
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount384];
        t[..LimbCount384].CopyTo(reduced);
        bool borrow = PrimeField384.SubtractWithBorrow(reduced, n);
        PrimeField384.Select(reduced, t[..LimbCount384], (t[LimbCount384] != 0UL) | !borrow, result);
    }


    /// <summary>The 256 × 256 → 512-bit schoolbook product exactly as <see cref="PrimeField256.MultiplyWide"/> writes it.</summary>
    private static void MultiplyWideUInt128(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result512)
    {
        result512.Clear();
        for(int i = 0; i < LimbCount256; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount256; j++)
            {
                UInt128 term = ((UInt128)a[i] * b[j]) + result512[i + j] + carry;
                result512[i + j] = (ulong)term;
                carry = (ulong)(term >> 64);
            }

            result512[i + LimbCount256] = carry;
        }
    }


    /// <summary>The 256 × 256 → 512-bit schoolbook product with every inner step in the <see cref="MultiplyAccumulate"/> form.</summary>
    private static void MultiplyWideBigMul(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result512)
    {
        result512.Clear();
        for(int i = 0; i < LimbCount256; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount256; j++)
            {
                result512[i + j] = MultiplyAccumulate(a[i], b[j], result512[i + j], carry, out carry);
            }

            result512[i + LimbCount256] = carry;
        }
    }
}
