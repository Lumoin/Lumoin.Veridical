using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the Logic/BitW gadget layer (<see cref="LongfellowLogic"/>), a faithful port of
/// google/longfellow-zk's <c>logic_test.cc</c>: the boolean gates over the affine bit representation,
/// the carry-propagation scans and adders, the comparison and multiplier gadgets, the GF(2)
/// polynomial multipliers (schoolbook, Karatsuba, and the GF(2^128) field multiplication built on
/// them), and the bit-vector family built on top.
/// </summary>
/// <remarks>
/// <para>
/// Every gadget runs over an evaluating backend (<see cref="LongfellowEvaluationLogicBackend"/>), so
/// each gate directly produces a concrete field value rather than a compiled node; correctness is
/// checked by comparing the evaluated canonical bytes of the gate's output against the evaluated
/// bytes of a hand-computed expectation, exactly as the reference's <c>EXPECT_EQ(L.eval(x), L.eval(y))</c>
/// pattern does.
/// </para>
/// <para>
/// The gates that admit both field bundles (<see cref="Gf2128Field"/>, characteristic two, and
/// <see cref="Fp256Field"/>, the odd-prime P-256 base field) run over both: the odd-prime field is the
/// only one that takes <see cref="LongfellowLogic.Xor(LongfellowBitWire, LongfellowBitWire)"/>'s
/// basis-change arm (the characteristic-two field takes the plain <c>addv</c> arm instead), so a gate
/// battery that never runs over Fp256 would never exercise that arm at all.
/// </para>
/// <para>
/// The reference sweeps every gadget exhaustively at C++ speed, several at widths this managed suite
/// cannot match inside the non-Slow test budget. Each reduced width is recorded next to its constant
/// below: the gadgets themselves are width-uniform recurrences (a fixed per-bit combine rule, or a
/// fixed midpoint-split association tree), so an exhaustive sweep at a smaller width still exercises
/// every branch shape the recurrence can take — it only forfeits coverage of widths the reference
/// never gives distinct code paths for in the first place.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowLogicEvaluationTests
{
    /// <summary>Every simple-gate truth table is exhaustive over single bits; no reduction applies here.</summary>
    private const int BitValues = 2;

    /// <summary>
    /// The reference sweeps w = 1..16; the forward/backward Sklansky fan is a fixed midpoint-split
    /// recurrence, so 1..6 still exercises the single-leaf, even-split and odd-split branches.
    /// </summary>
    private const int ScanMaxWidth = 6;

    /// <summary>
    /// The reference sweeps w = 7; all four adder kinds share one generate/propagate scan engine, so a
    /// narrower width still exercises the ripple and Sklansky combine steps end to end.
    /// </summary>
    private const int AdderWidthGf2128 = 4;

    /// <summary>
    /// Narrower than the GF(2^128) sweep: this run exists only to exercise the odd-prime basis-change
    /// arm inside the adder's internal Xor calls, not to re-cover the width range already swept above.
    /// </summary>
    private const int AdderWidthFp256 = 3;

    /// <summary>
    /// The reference sweeps w = 9; the equal/less-than reduction is a single midpoint-recursion shape,
    /// so w = 4 still exercises its leaf, even-split and odd-split combine cases.
    /// </summary>
    private const int ComparisonWidth = 4;

    /// <summary>
    /// The reference sweeps w = 7; every row of the schoolbook multiplier is structurally identical
    /// (an And row folded in by a ripple add), so a shorter width still exercises every row transition.
    /// </summary>
    private const int MultiplierWidth = 4;

    /// <summary>
    /// The reference sweeps w = 5; assert_sum's carry chain is a uniform per-bit recurrence, so w = 3
    /// still covers the first-bit, middle and last-bit special cases the recurrence special-cases.
    /// </summary>
    private const int AssertSumWidth = 3;

    /// <summary>
    /// The reference sweeps w = 10; below the Karatsuba width threshold both the schoolbook multiplier
    /// and its Karatsuba wrapper resolve to the same call, so the exact width only needs to stay small
    /// and exhaustive to pin the shifted-xor arithmetization both routes share.
    /// </summary>
    private const int Gf2PolynomialWidth = 5;

    /// <summary>
    /// The reference sweeps w = 7; kept the smallest width whose full (a, b, c) triple loop still
    /// finishes inside the suite's fast-test budget while remaining exhaustive.
    /// </summary>
    private const int BitvecWidth = 5;

    /// <summary>The P-256 base field's modulus-minus-one, canonical big-endian, used to construct <see cref="Fp256Field"/>.</summary>
    private static ReadOnlyMemory<byte> Fp256MinusOne { get; } = BuildFp256MinusOne();

    /// <summary>The GF(2^128) field bundle gated over by every GF(2^128) test.</summary>
    private static LongfellowLogicFieldOperations Gf2128Field { get; } = LongfellowLogicFieldOperations.CreateGf2128(
        Gf2k128Backend.GetAdd(),
        Gf2k128Backend.GetSubtract(),
        Gf2k128Backend.GetMultiply(),
        Gf2k128Backend.GetInvert());

    /// <summary>The P-256 base field bundle gated over by every Fp256 test.</summary>
    private static LongfellowLogicFieldOperations Fp256Field { get; } = LongfellowLogicFieldOperations.CreateFp256(
        P256BaseFieldReference.GetAdd(),
        P256BaseFieldReference.GetSubtract(),
        P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(),
        Fp256MinusOne);

    /// <summary>
    /// The eight sage-generated GF(2^128) test vectors from the reference's <c>Logic.GF2_128Multiplier</c>
    /// test, transcribed verbatim: each entry is a triple of sparse nonzero-index lists for <c>a</c>,
    /// <c>b</c> and the expected product <c>a * b</c> under the field's fixed irreducible polynomial.
    /// </summary>
    private static (int[] A, int[] B, int[] C)[] Gf2128TestVectors { get; } =
    [
        ([0], [0], [0]),
        ([1], [1], [2]),
        (
            [0, 2, 4, 5, 7, 8, 9, 10, 11, 13, 15, 17, 18, 19, 20, 22, 23, 25, 28, 30, 33, 34, 38, 39, 42, 44,
             45, 46, 49, 53, 56, 61, 64, 65, 66, 69, 70, 71, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 90, 91,
             93, 96, 97, 98, 99, 103, 105, 110, 113, 116, 117, 125, 126, 127],
            [0, 1, 2, 5, 9, 10, 11, 12, 14, 15, 17, 18, 19, 21, 22, 25, 27, 28, 30, 32, 33, 34, 35, 39, 40, 41,
             42, 45, 50, 52, 54, 60, 64, 66, 67, 68, 69, 70, 71, 76, 79, 83, 85, 87, 88, 89, 97, 98, 99, 102,
             105, 107, 109, 110, 111, 112, 114, 115, 116, 118, 121, 122, 124, 126],
            [0, 1, 3, 5, 6, 7, 10, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 28, 29, 31, 32, 33, 36, 38, 41,
             50, 51, 53, 54, 55, 57, 58, 59, 60, 61, 63, 64, 66, 68, 69, 71, 76, 77, 78, 81, 82, 83, 86, 88,
             90, 94, 96, 98, 101, 104, 105, 108, 109, 111, 112, 116, 118, 119, 120, 121, 122, 125, 126]
        ),
        (
            [1, 5, 8, 10, 12, 13, 15, 16, 19, 21, 23, 24, 25, 26, 27, 30, 32, 33, 34, 40, 42, 43, 47, 48, 51,
             52, 56, 57, 59, 62, 64, 67, 68, 71, 72, 74, 76, 77, 78, 79, 80, 85, 87, 88, 89, 92, 93, 94, 95,
             97, 98, 101, 102, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 117, 120, 121, 123, 124,
             125, 127],
            [1, 4, 8, 9, 10, 16, 17, 21, 24, 25, 28, 29, 31, 33, 35, 36, 39, 40, 41, 44, 45, 46, 48, 49, 50,
             54, 55, 56, 57, 59, 61, 62, 64, 65, 66, 67, 68, 69, 71, 72, 73, 75, 78, 79, 80, 83, 87, 92, 95,
             96, 97, 98, 104, 105, 106, 107, 108, 109, 111, 113, 114, 117, 119, 120, 122, 123, 124, 125],
            [0, 1, 5, 6, 9, 11, 12, 16, 18, 21, 22, 23, 24, 25, 26, 27, 29, 32, 33, 34, 35, 36, 37, 43, 44, 45,
             49, 50, 52, 53, 54, 56, 57, 59, 60, 61, 62, 63, 65, 67, 68, 69, 70, 72, 75, 79, 81, 82, 84, 87,
             89, 91, 94, 95, 96, 97, 99, 100, 101, 103, 105, 106, 109, 111, 112, 113, 114, 117, 118, 119, 120,
             125, 126, 127]
        ),
        (
            [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 22, 25, 26, 28, 29, 33, 34, 37, 38, 39, 41, 43, 44,
             45, 46, 48, 49, 50, 53, 54, 55, 56, 57, 58, 60, 62, 64, 65, 68, 69, 70, 73, 76, 78, 80, 83, 84,
             85, 86, 88, 90, 91, 94, 100, 101, 103, 104, 105, 106, 110, 113, 115, 119, 124, 125, 127],
            [0, 11, 12, 14, 15, 18, 20, 22, 23, 29, 31, 34, 35, 39, 43, 45, 47, 48, 49, 51, 52, 54, 59, 60, 62,
             66, 67, 68, 70, 71, 72, 73, 74, 75, 76, 77, 79, 80, 85, 89, 90, 92, 93, 95, 96, 97, 99, 101, 102,
             104, 105, 107, 109, 110, 111, 112, 115, 116, 118, 119, 123, 124, 125],
            [2, 4, 6, 11, 12, 13, 15, 18, 19, 20, 21, 23, 24, 25, 26, 30, 31, 33, 34, 35, 36, 39, 40, 44, 47,
             48, 51, 52, 53, 57, 58, 59, 60, 64, 65, 67, 69, 71, 74, 76, 78, 79, 80, 81, 87, 88, 89, 92, 93,
             94, 99, 100, 101, 109, 110, 113, 114, 115, 116, 117, 119, 120, 121, 122, 125, 126]
        ),
        (
            [0, 1, 2, 6, 7, 8, 10, 14, 15, 16, 18, 19, 21, 25, 27, 28, 29, 30, 40, 44, 45, 52, 56, 57, 58, 59,
             60, 62, 63, 66, 67, 70, 71, 72, 73, 74, 77, 78, 86, 91, 92, 93, 96, 97, 98, 102, 103, 105, 107,
             108, 109, 115, 116, 121, 122, 125, 126],
            [0, 1, 3, 4, 5, 6, 9, 10, 15, 16, 18, 19, 21, 22, 24, 25, 28, 29, 33, 34, 36, 40, 41, 43, 45, 46,
             50, 51, 53, 54, 56, 59, 60, 62, 63, 67, 70, 71, 72, 73, 77, 78, 79, 81, 82, 83, 84, 85, 87, 90,
             92, 94, 96, 98, 99, 100, 101, 102, 103, 105, 107, 108, 109, 110, 111, 112, 114, 116, 117, 118,
             120, 121, 122],
            [0, 1, 3, 5, 6, 7, 8, 11, 12, 14, 15, 17, 18, 19, 20, 22, 26, 27, 28, 33, 34, 35, 43, 45, 47, 50,
             51, 53, 54, 56, 58, 61, 65, 66, 71, 76, 77, 78, 79, 85, 86, 87, 90, 91, 92, 95, 97, 98, 99, 101,
             103, 105, 106, 109, 110, 111, 112, 115, 116, 118, 119, 120, 123, 124, 125, 126, 127]
        ),
        (
            [0, 1, 2, 5, 6, 8, 10, 14, 16, 19, 20, 21, 25, 26, 28, 29, 31, 32, 36, 37, 40, 41, 42, 43, 45, 47,
             49, 50, 51, 52, 53, 55, 59, 60, 61, 63, 65, 66, 68, 69, 74, 75, 76, 77, 79, 80, 81, 82, 84, 87,
             91, 92, 94, 96, 99, 100, 101, 102, 103, 104, 108, 110, 112, 114, 115, 116, 117, 120, 121, 127],
            [0, 1, 2, 4, 7, 9, 12, 15, 19, 22, 25, 26, 29, 30, 32, 34, 35, 37, 39, 41, 42, 43, 46, 50, 54, 58,
             59, 65, 68, 69, 71, 73, 75, 76, 79, 80, 82, 83, 84, 88, 90, 92, 95, 98, 99, 100, 102, 103, 104,
             105, 106, 109, 110, 112, 113, 115, 117, 120, 123, 125],
            [2, 5, 6, 7, 13, 16, 17, 19, 21, 22, 23, 24, 26, 28, 29, 34, 35, 37, 40, 41, 45, 46, 47, 48, 49,
             54, 57, 58, 61, 63, 65, 67, 68, 71, 73, 74, 75, 76, 77, 80, 82, 85, 86, 87, 91, 92, 93, 96, 97,
             100, 104, 105, 107, 109, 111, 112, 113, 117, 118, 120, 122, 125]
        ),
        (
            [5, 6, 7, 8, 9, 11, 12, 13, 17, 19, 20, 25, 28, 29, 30, 39, 40, 41, 42, 47, 48, 49, 51, 52, 54,
             61, 63, 68, 70, 71, 73, 75, 76, 77, 80, 81, 82, 88, 89, 90, 91, 98, 100, 101, 104, 105, 106, 111,
             114, 116, 119, 122, 124, 127],
            [4, 6, 7, 8, 9, 10, 12, 13, 14, 15, 17, 18, 19, 20, 21, 23, 24, 26, 27, 28, 31, 32, 38, 40, 41, 43,
             44, 45, 47, 49, 51, 53, 59, 60, 61, 65, 66, 67, 69, 72, 74, 75, 77, 78, 79, 80, 83, 85, 86, 89,
             92, 94, 95, 97, 99, 100, 103, 104, 105, 113, 120, 123, 124, 126, 127],
            [0, 3, 4, 5, 7, 8, 14, 15, 16, 17, 19, 23, 24, 25, 26, 27, 28, 29, 33, 34, 38, 39, 41, 42, 43, 44,
             45, 49, 51, 52, 60, 61, 63, 64, 69, 70, 71, 73, 74, 75, 76, 77, 80, 82, 87, 90, 91, 93, 94, 97,
             98, 99, 100, 104, 105, 107, 109, 114, 115, 116, 119, 120, 121, 122, 123, 124, 125, 126, 127]
        ),
    ];

    /// <summary>The reference's four adder kinds, dispatched over the shared ripple/Sklansky engine.</summary>
    private enum AdderKind
    {
        /// <summary>The reference's <c>ripple_carry_add</c>.</summary>
        RippleAdd,

        /// <summary>The reference's <c>ripple_carry_sub</c>.</summary>
        RippleSubtract,

        /// <summary>The reference's <c>parallel_prefix_add</c>.</summary>
        ParallelPrefixAdd,

        /// <summary>The reference's <c>parallel_prefix_sub</c>.</summary>
        ParallelPrefixSubtract,
    }


    /// <summary>Pins that the unary/binary/ternary boolean gates match their truth tables over GF(2^128).</summary>
    [TestMethod]
    public void SimpleGatesMatchTheirTruthTablesOverGf2128()
    {
        AssertSimpleGates(Gf2128Field);
    }


    /// <summary>Pins that the unary/binary/ternary boolean gates match their truth tables over the P-256 base field.</summary>
    [TestMethod]
    public void SimpleGatesMatchTheirTruthTablesOverFp256()
    {
        AssertSimpleGates(Fp256Field);
    }


    /// <summary>Pins that AssertZero throws on a panicking backend when the wire is nonzero.</summary>
    [TestMethod]
    public void AssertZeroThrowsOnAPanickingBackendWhenTheWireIsNonzero()
    {
        LongfellowLogic logic = NewGf2128Logic();
        int nonzeroWire = logic.Eval(logic.Bit(1));

        Assert.ThrowsExactly<InvalidOperationException>(() => logic.AssertZero(nonzeroWire));
    }


    /// <summary>Pins that AssertZero latches the assertion-failed flag on a non-panicking backend and that reading the flag resets it.</summary>
    [TestMethod]
    public void AssertZeroLatchesAssertionFailedOnANonPanickingBackendAndResetsOnRead()
    {
        var backend = new LongfellowEvaluationLogicBackend(Gf2128Field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, Gf2128Field);
        int nonzeroWire = logic.Eval(logic.Bit(1));

        _ = logic.AssertZero(nonzeroWire);

        Assert.IsTrue(backend.AssertionFailed, "The first read after a failed assertion must observe the latch set.");
        Assert.IsFalse(backend.AssertionFailed, "Reading the latch must reset it, so the second read observes it cleared.");
    }


    /// <summary>Pins that the forward and backward Sklansky And/Or/Xor scans match sequential prefix recomputation across every swept width and input.</summary>
    [TestMethod]
    public void ScanAndScanOrScanXorMatchSequentialPrefixesForwardAndBackward()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int width = 1; width <= ScanMaxWidth; width++)
        {
            for(int a = 0; a < (1 << width); a++)
            {
                var x = new LongfellowBitWire[width];
                for(int i = 0; i < width; i++)
                {
                    x[i] = logic.Bit((a >> i) & 1);
                }

                AssertForwardScan(logic, x, width);
                AssertBackwardScan(logic, x, width);
            }
        }
    }


    /// <summary>Pins that all four adder kinds match unsigned arithmetic over GF(2^128).</summary>
    [TestMethod]
    public void TheFourAdderKindsMatchUnsignedArithmeticOverGf2128()
    {
        AssertAdders(Gf2128Field, AdderWidthGf2128);
    }


    /// <summary>Pins that all four adder kinds match unsigned arithmetic over the P-256 base field.</summary>
    [TestMethod]
    public void TheFourAdderKindsMatchUnsignedArithmeticOverFp256()
    {
        AssertAdders(Fp256Field, AdderWidthFp256);
    }


    /// <summary>Pins that Equal, LessThan and LessThanOrEqual match unsigned comparison across every operand pair over GF(2^128).</summary>
    [TestMethod]
    public void EqualLessThanAndLessThanOrEqualMatchUnsignedComparisonOverGf2128()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int a = 0; a < (1 << ComparisonWidth); a++)
        {
            for(int b = 0; b < (1 << ComparisonWidth); b++)
            {
                LongfellowBitWire[] ea = logic.BitVector(ComparisonWidth, (ulong)a);
                LongfellowBitWire[] eb = logic.BitVector(ComparisonWidth, (ulong)b);

                AssertBitEquals(logic, logic.Equal(ea, eb), a == b ? 1 : 0, $"Equal must match a == b for a={a}, b={b}.");
                AssertBitEquals(logic, logic.LessThan(ea, eb), a < b ? 1 : 0, $"LessThan must match a < b for a={a}, b={b}.");
                AssertBitEquals(logic, logic.LessThanOrEqual(ea, eb), a <= b ? 1 : 0, $"LessThanOrEqual must match a <= b for a={a}, b={b}.");
            }
        }
    }


    /// <summary>Pins that LessThan and Equal over an empty range return their documented corner values (false and true respectively).</summary>
    [TestMethod]
    public void LessThanAndEqualOfAnEmptyRangeReturnTheirDocumentedCorners()
    {
        LongfellowLogic logic = NewGf2128Logic();
        LongfellowBitWire[] empty = [];

        AssertBitEquals(logic, logic.LessThan(empty, empty), 0, "LessThan over an empty range must be the false bit.");
        AssertBitEquals(logic, logic.Equal(empty, empty), 1, "Equal over an empty range must be the true bit.");
    }


    /// <summary>Pins that every field-operation domain guard (OfScalar, Beta, the characteristic-specific constants, AsScalar, AssertSum) rejects its documented out-of-domain input.</summary>
    [TestMethod]
    public void TheFieldOperationGuardsRejectTheirDocumentedOutOfDomainInputs()
    {
        //of_scalar over GF(2^128) covers only the 16-bit subfield basis.
        const ulong BeyondSubfieldScalar = 1UL << 16;
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Gf2128Field.OfScalar(BeyondSubfieldScalar), "of_scalar beyond the subfield basis must throw over GF(2^128).");

        //The basis index bounds: 16 over GF(2^128), 64 over the odd-prime field.
        const int SubfieldBasisBound = 16;
        const int PrimeBasisBound = 64;
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Gf2128Field.Beta(SubfieldBasisBound), "beta at the subfield bound must throw over GF(2^128).");
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Fp256Field.Beta(PrimeBasisBound), "beta at the native-scalar bound must throw over the odd-prime field.");

        //The characteristic-specific constants throw on the wrong field kind.
        Assert.ThrowsExactly<InvalidOperationException>(() => _ = Fp256Field.X, "The generator polynomial is characteristic-two only.");
        Assert.ThrowsExactly<InvalidOperationException>(() => _ = Gf2128Field.Two, "Two is odd-prime only.");
        Assert.ThrowsExactly<InvalidOperationException>(() => _ = Gf2128Field.Half, "Half is odd-prime only.");

        //as_scalar re-runs the representability check at the all-ones value: seventeen GF bits overflow it.
        const int BeyondSubfieldWidth = 17;
        LongfellowLogic gfLogic = NewGf2128Logic();
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => gfLogic.AsScalar(gfLogic.BitVector(BeyondSubfieldWidth, 0UL)), "as_scalar beyond the subfield width must throw over GF(2^128).");

        //The constant-depth sum assertion reads the first carry unconditionally and needs two bits.
        LongfellowBitWire[] single = [gfLogic.Bit(0)];
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => gfLogic.AssertSum(single, single, single), "assert_sum below two bits must throw.");
    }


    /// <summary>Pins that the schoolbook multiplier gadget matches unsigned products over GF(2^128).</summary>
    [TestMethod]
    public void TheMultiplierMatchesUnsignedProductsOverGf2128()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int a = 0; a < (1 << MultiplierWidth); a++)
        {
            for(int b = 0; b < (1 << MultiplierWidth); b++)
            {
                LongfellowBitWire[] ea = logic.BitVector(MultiplierWidth, (ulong)a);
                LongfellowBitWire[] eb = logic.BitVector(MultiplierWidth, (ulong)b);
                var ec = new LongfellowBitWire[2 * MultiplierWidth];

                logic.Multiplier(ec, ea, eb);

                uint expected = (uint)(a * b);
                for(int i = 0; i < (2 * MultiplierWidth); i++)
                {
                    AssertBitEquals(logic, ec[i], (int)((expected >> i) & 1u), $"Multiplier bit {i} must match a * b for a={a}, b={b}.");
                }
            }
        }
    }


    /// <summary>Pins that AssertSum's failure latch matches the closed-form carry disagreement over GF(2^128).</summary>
    [TestMethod]
    public void AssertSumLatchesExactlyWhenTheClaimedSumDisagreesOverGf2128()
    {
        int mask = (1 << AssertSumWidth) - 1;

        for(int a = 0; a < (1 << AssertSumWidth); a++)
        {
            for(int b = 0; b < (1 << AssertSumWidth); b++)
            {
                for(int c = 0; c < (1 << AssertSumWidth); c++)
                {
                    var backend = new LongfellowEvaluationLogicBackend(Gf2128Field, panicOnAssertionFailure: false);
                    var logic = new LongfellowLogic(backend, Gf2128Field);

                    LongfellowBitWire[] ea = logic.BitVector(AssertSumWidth, (ulong)a);
                    LongfellowBitWire[] eb = logic.BitVector(AssertSumWidth, (ulong)b);
                    LongfellowBitWire[] ec = logic.BitVector(AssertSumWidth, (ulong)c);

                    logic.AssertSum(ec, ea, eb);

                    bool expectedFailure = (((a + b) ^ c) & mask) != 0;
                    Assert.AreEqual(expectedFailure, backend.AssertionFailed, $"AssertSum's failure latch must match ((a + b) ^ c) & mask for a={a}, b={b}, c={c}.");
                }
            }
        }
    }


    /// <summary>Pins that the schoolbook and Karatsuba GF(2) polynomial multipliers agree with the shifted-xor reference across every operand pair.</summary>
    [TestMethod]
    public void Gf2PolynomialMultiplierSchoolbookAndKaratsubaAgreeWithTheShiftedXorReference()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int a = 0; a < (1 << Gf2PolynomialWidth); a++)
        {
            for(int b = 0; b < (1 << Gf2PolynomialWidth); b++)
            {
                LongfellowBitWire[] ea = logic.BitVector(Gf2PolynomialWidth, (ulong)a);
                LongfellowBitWire[] eb = logic.BitVector(Gf2PolynomialWidth, (ulong)b);

                LongfellowBitWire[] schoolbook = logic.Gf2PolynomialMultiplier(Gf2PolynomialWidth, ea, eb);
                LongfellowBitWire[] karatsuba = logic.Gf2PolynomialMultiplierKaratsuba(Gf2PolynomialWidth, ea, eb);

                uint expected = 0;
                for(int i = 0; i < Gf2PolynomialWidth; i++)
                {
                    if(((a >> i) & 1) != 0)
                    {
                        expected ^= (uint)(b << i);
                    }
                }

                for(int i = 0; i < (2 * Gf2PolynomialWidth); i++)
                {
                    int expectedBit = (int)((expected >> i) & 1u);
                    AssertBitEquals(logic, schoolbook[i], expectedBit, $"The schoolbook GF(2) polynomial product bit {i} must match the shifted-xor reference for a={a}, b={b}.");
                    AssertBitEquals(logic, karatsuba[i], expectedBit, $"The Karatsuba GF(2) polynomial product bit {i} must match the shifted-xor reference for a={a}, b={b}.");
                }
            }
        }
    }


    /// <summary>Pins that GF(2^128) field multiplication matches the sage-generated test vectors.</summary>
    [TestMethod]
    public void Gf2128MultiplyMatchesTheSageGeneratedTestVectors()
    {
        LongfellowLogic logic = NewGf2128Logic();

        foreach((int[] a, int[] b, int[] c) in Gf2128TestVectors)
        {
            LongfellowBitWire[] ea = Gf2SparseVector(logic, a);
            LongfellowBitWire[] eb = Gf2SparseVector(logic, b);
            LongfellowBitWire[] want = Gf2SparseVector(logic, c);

            LongfellowBitWire[] got = logic.Gf2128Multiply(ea, eb);

            logic.AssertEqual(got, want);
        }
    }


    /// <summary>Pins that vector Not complements every bit and that AsScalar matches OfScalar over GF(2^128).</summary>
    [TestMethod]
    public void BitVectorNotRoundTripsAndAsScalarMatchesOfScalarOverGf2128()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int a = 0; a < (1 << BitvecWidth); a++)
        {
            LongfellowBitWire[] ea = logic.BitVector(BitvecWidth, (ulong)a);
            LongfellowBitWire[] notEa = logic.Not(ea);

            AssertVectorEqualsImmediate(logic, notEa, ~(ulong)a, $"Not must complement every bit of a={a}.");

            int scalarWire = logic.AsScalar(ea);
            byte[] expected = Gf2128Field.OfScalar((ulong)a).ToArray();
            Assert.IsTrue(EvaluatedBytes(logic, scalarWire).AsSpan().SequenceEqual(expected), $"AsScalar must match OfScalar for a={a}.");
        }
    }


    /// <summary>Pins that the vector And, Or, Xor, Add, Equal, LessThan and LessThanOrEqual gadgets (and their immediate overloads) match their scalar semantics over GF(2^128).</summary>
    [TestMethod]
    public void VectorAndOrXorAddEqualLessThanAndLessThanOrEqualMatchTheirScalarSemanticsOverGf2128()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int a = 0; a < (1 << BitvecWidth); a++)
        {
            LongfellowBitWire[] ea = logic.BitVector(BitvecWidth, (ulong)a);

            for(int b = 0; b < (1 << BitvecWidth); b++)
            {
                LongfellowBitWire[] eb = logic.BitVector(BitvecWidth, (ulong)b);

                AssertVectorEqualsImmediate(logic, logic.And(ea, eb), (ulong)(a & b), $"Vector And must match a & b for a={a}, b={b}.");
                AssertVectorEqualsImmediate(logic, logic.Or(ea, eb), (ulong)(a | b), $"Vector Or must match a | b for a={a}, b={b}.");
                AssertVectorEqualsImmediate(logic, logic.Xor(ea, eb), (ulong)(a ^ b), $"Vector Xor must match a ^ b for a={a}, b={b}.");
                AssertVectorEqualsImmediate(logic, logic.Add(ea, eb), (ulong)(a + b), $"Vector Add must match a + b truncated to the width for a={a}, b={b}.");

                AssertBitEquals(logic, logic.Equal(ea, eb), a == b ? 1 : 0, $"Vector Equal must match a == b for a={a}, b={b}.");
                AssertBitEquals(logic, logic.Equal(ea, (ulong)b), a == b ? 1 : 0, $"Immediate Equal must match a == b for a={a}, b={b}.");
                AssertBitEquals(logic, logic.LessThan(ea, eb), a < b ? 1 : 0, $"Vector LessThan must match a < b for a={a}, b={b}.");
                AssertBitEquals(logic, logic.LessThan(ea, (ulong)b), a < b ? 1 : 0, $"Immediate LessThan must match a < b for a={a}, b={b}.");
                AssertBitEquals(logic, logic.LessThanOrEqual(ea, eb), a <= b ? 1 : 0, $"Vector LessThanOrEqual must match a <= b for a={a}, b={b}.");
                AssertBitEquals(logic, logic.LessThanOrEqual(ea, (ulong)b), a <= b ? 1 : 0, $"Immediate LessThanOrEqual must match a <= b for a={a}, b={b}.");
            }
        }
    }


    /// <summary>Pins that the 3-arg vector Xor, Choose, Majority and EqualMasked gadgets (and the immediate EqualMasked overload) match their scalar semantics over GF(2^128).</summary>
    [TestMethod]
    public void VectorXor3ChooseMajorityAndEqualMaskedMatchTheirScalarSemanticsOverGf2128()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int a = 0; a < (1 << BitvecWidth); a++)
        {
            LongfellowBitWire[] ea = logic.BitVector(BitvecWidth, (ulong)a);

            for(int b = 0; b < (1 << BitvecWidth); b++)
            {
                LongfellowBitWire[] eb = logic.BitVector(BitvecWidth, (ulong)b);

                for(int c = 0; c < (1 << BitvecWidth); c++)
                {
                    LongfellowBitWire[] ec = logic.BitVector(BitvecWidth, (ulong)c);

                    AssertVectorEqualsImmediate(logic, logic.Xor(ea, eb, ec), (ulong)(a ^ b ^ c), $"The 3-arg vector Xor must match a ^ b ^ c for a={a}, b={b}, c={c}.");

                    ulong expectedChoose = ((ulong)a & (ulong)b) ^ (~(ulong)a & (ulong)c);
                    AssertVectorEqualsImmediate(logic, logic.Choose(ea, eb, ec), expectedChoose, $"Vector Choose must match (a & b) ^ (!a & c) for a={a}, b={b}, c={c}.");

                    ulong expectedMajority = ((ulong)a & (ulong)b) ^ ((ulong)a & (ulong)c) ^ ((ulong)b & (ulong)c);
                    AssertVectorEqualsImmediate(logic, logic.Majority(ea, eb, ec), expectedMajority, $"Vector Majority must match (a & b) ^ (a & c) ^ (b & c) for a={a}, b={b}, c={c}.");

                    int expectedMasked = ((a ^ c) & b) == 0 ? 1 : 0;
                    AssertBitEquals(logic, logic.EqualMasked(ea, (ulong)b, ec), expectedMasked, $"Vector EqualMasked must match ((a ^ c) & mask) == 0 for a={a}, mask={b}, c={c}.");
                    AssertBitEquals(logic, logic.EqualMasked(ea, (ulong)b, (ulong)c), expectedMasked, $"Immediate EqualMasked must match ((a ^ c) & mask) == 0 for a={a}, mask={b}, c={c}.");
                }
            }
        }
    }


    /// <summary>Pins that ShiftRight, RotateRight and RotateLeft match their scalar semantics across every shift amount over GF(2^128).</summary>
    [TestMethod]
    public void ShiftRightRotateRightAndRotateLeftMatchTheirScalarSemanticsOverGf2128()
    {
        LongfellowLogic logic = NewGf2128Logic();

        for(int a = 0; a < (1 << BitvecWidth); a++)
        {
            LongfellowBitWire[] ea = logic.BitVector(BitvecWidth, (ulong)a);

            for(int shift = 0; shift <= BitvecWidth; shift++)
            {
                AssertVectorEqualsImmediate(logic, logic.ShiftRight(ea, shift), (ulong)a >> shift, $"ShiftRight by {shift} must match a >> shift for a={a}.");

                ulong expectedRotateRight = ((ulong)a >> shift) | ((ulong)a << (BitvecWidth - shift));
                AssertVectorEqualsImmediate(logic, LongfellowLogic.RotateRight(ea, shift), expectedRotateRight, $"RotateRight by {shift} must match the reference rotation formula for a={a}.");

                ulong expectedRotateLeft = ((ulong)a << shift) | ((ulong)a >> (BitvecWidth - shift));
                AssertVectorEqualsImmediate(logic, LongfellowLogic.RotateLeft(ea, shift), expectedRotateLeft, $"RotateLeft by {shift} must match the reference rotation formula for a={a}.");
            }
        }
    }


    /// <summary>Pins that the ranged Or, OrExclusive, And, Multiply and Add folds over an empty range return their documented identity constants.</summary>
    [TestMethod]
    public void RangedFoldsOverAnEmptyRangeMatchTheirDocumentedConstants()
    {
        LongfellowLogic logic = NewGf2128Logic();

        //Matches the reference's L.vbit<w>(9); the value is irrelevant since the folded range is empty.
        const ulong ArbitraryVectorValue = 9;
        LongfellowBitWire[] ea = logic.BitVector(BitvecWidth, ArbitraryVectorValue);

        AssertBitEquals(logic, logic.Or(1, 0, i => ea[i]), 0, "The ranged Or over an empty range must be the false bit.");
        AssertBitEquals(logic, logic.OrExclusive(1, 0, i => ea[i]), 0, "The ranged OrExclusive over an empty range must be the false bit.");
        AssertBitEquals(logic, logic.And(1, 0, i => ea[i]), 1, "The ranged And over an empty range must be the true bit.");

        int emptyProduct = logic.Multiply(1, 0, i => logic.Eval(ea[i]));
        Assert.IsTrue(EvaluatedBytes(logic, emptyProduct).AsSpan().SequenceEqual(Gf2128Field.Compiler.One.Span), "The ranged Multiply over an empty range must be the field's one.");

        int emptySum = logic.Add(1, 0, i => logic.Eval(ea[i]));
        Assert.IsTrue(EvaluatedBytes(logic, emptySum).AsSpan().SequenceEqual(Gf2128Field.Compiler.Zero.Span), "The ranged Add over an empty range must be the field's zero.");
    }


    /// <summary>Pins that AsScalar matches OfScalar over the P-256 base field.</summary>
    [TestMethod]
    public void AsScalarMatchesOfScalarOverFp256()
    {
        LongfellowLogic logic = NewFp256Logic();

        for(int a = 0; a < (1 << BitvecWidth); a++)
        {
            LongfellowBitWire[] ea = logic.BitVector(BitvecWidth, (ulong)a);
            int scalarWire = logic.AsScalar(ea);

            byte[] expected = Fp256Field.OfScalar((ulong)a).ToArray();
            Assert.IsTrue(EvaluatedBytes(logic, scalarWire).AsSpan().SequenceEqual(expected), $"AsScalar must match OfScalar over Fp256 for a={a}.");
        }
    }


    /// <summary>
    /// Runs the reference's <c>Logic.Simple</c> battery over one field bundle: the unary/binary/ternary
    /// gates' truth tables, exhaustive over every bit combination, plus the assert-equal identity the
    /// reference checks alongside them.
    /// </summary>
    /// <param name="field">The field bundle to gate over.</param>
    private static void AssertSimpleGates(LongfellowLogicFieldOperations field)
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(field), field);

        for(int a = 0; a < BitValues; a++)
        {
            LongfellowBitWire ea = logic.Bit(a);
            AssertBitEquals(logic, logic.Not(ea), 1 - a, "Not must flip the bit.");

            for(int b = 0; b < BitValues; b++)
            {
                LongfellowBitWire eb = logic.Bit(b);

                AssertBitEquals(logic, logic.And(ea, eb), a & b, "And must match a & b.");
                AssertBitEquals(logic, logic.And(ea, logic.Not(eb)), a & (1 - b), "And must match a & !b.");
                AssertBitEquals(logic, logic.And(eb, logic.Not(ea)), (1 - a) & b, "And must match !a & b.");
                AssertBitEquals(logic, logic.And(logic.Not(ea), logic.Not(eb)), (1 - a) & (1 - b), "And must match !a & !b.");

                AssertBitEquals(logic, logic.Or(ea, eb), a | b, "Or must match a | b.");
                AssertBitEquals(logic, logic.Or(ea, logic.Not(eb)), a | (1 - b), "Or must match a | !b.");
                AssertBitEquals(logic, logic.Or(eb, logic.Not(ea)), (1 - a) | b, "Or must match !a | b.");
                AssertBitEquals(logic, logic.Or(logic.Not(ea), logic.Not(eb)), (1 - a) | (1 - b), "Or must match !a | !b.");

                AssertBitEquals(logic, logic.Xor(ea, eb), a ^ b, "Xor must match a ^ b.");
                AssertBitEquals(logic, logic.Xor(ea, logic.Not(eb)), a ^ (1 - b), "Xor must match a ^ !b.");
                AssertBitEquals(logic, logic.Xor(eb, logic.Not(ea)), (1 - a) ^ b, "Xor must match !a ^ b.");
                AssertBitEquals(logic, logic.Xor(logic.Not(ea), logic.Not(eb)), (1 - a) ^ (1 - b), "Xor must match !a ^ !b.");

                if((a & b) == 0)
                {
                    AssertBitEquals(logic, logic.OrExclusive(ea, eb), a | b, "OrExclusive must match a | b when the operands are mutually exclusive.");
                }

                LongfellowBitWire axb = logic.Bit(a ^ b);
                _ = logic.AssertEqual(axb, logic.Xor(ea, eb));

                for(int c = 0; c < BitValues; c++)
                {
                    LongfellowBitWire ec = logic.Bit(c);

                    AssertBitEquals(logic, logic.Xor(ea, eb, ec), a ^ b ^ c, "The 3-arg Xor must match a ^ b ^ c.");
                    AssertBitEquals(logic, logic.And(ea, logic.Xor(eb, ec)), a & (b ^ c), "And must match a & (b ^ c).");
                    AssertBitEquals(logic, logic.And(ea, logic.Or(eb, ec)), a & (b | c), "And must match a & (b | c).");
                    AssertBitEquals(logic, logic.Or(ea, logic.And(eb, ec)), a | (b & c), "Or must match a | (b & c).");
                    AssertBitEquals(logic, logic.Or(ea, logic.Xor(eb, ec)), a | (b ^ c), "Or must match a | (b ^ c).");
                    AssertBitEquals(logic, logic.Xor(ea, logic.And(eb, ec)), a ^ (b & c), "Xor must match a ^ (b & c).");
                    AssertBitEquals(logic, logic.Xor(ea, logic.Or(eb, ec)), a ^ (b | c), "Xor must match a ^ (b | c).");
                    AssertBitEquals(logic, logic.Mux(ea, eb, ec), a != 0 ? b : c, "Mux must select b when a is true, else c.");
                    AssertBitEquals(logic, logic.Choose(ea, eb, ec), (a & b) ^ ((1 - a) & c), "Choose must match (a & b) ^ (!a & c).");
                    AssertBitEquals(logic, logic.Majority(ea, eb, ec), (a & b) ^ (a & c) ^ (b & c), "Majority must match (a & b) ^ (a & c) ^ (b & c).");
                }
            }
        }
    }


    /// <summary>Runs a forward Sklansky scan of And/Or/Xor over <paramref name="x"/> and checks it against sequential prefix recomputation.</summary>
    /// <param name="logic">The gadget layer to run the scans over.</param>
    /// <param name="x">The source bits; never mutated.</param>
    /// <param name="width">The bit count.</param>
    private static void AssertForwardScan(LongfellowLogic logic, LongfellowBitWire[] x, int width)
    {
        var ya = (LongfellowBitWire[])x.Clone();
        var yo = (LongfellowBitWire[])x.Clone();
        var yx = (LongfellowBitWire[])x.Clone();

        logic.ScanAnd(ya, 0, width);
        logic.ScanOr(yo, 0, width);
        logic.ScanXor(yx, 0, width);

        LongfellowBitWire runningAnd = logic.Bit(1);
        LongfellowBitWire runningOr = logic.Bit(0);
        LongfellowBitWire runningXor = logic.Bit(0);
        for(int i = 0; i < width; i++)
        {
            runningAnd = logic.And(runningAnd, x[i]);
            AssertBitEquals(logic, ya[i], runningAnd, $"The forward AND scan at width {width}, position {i} must match the sequential prefix.");
            runningOr = logic.Or(runningOr, x[i]);
            AssertBitEquals(logic, yo[i], runningOr, $"The forward OR scan at width {width}, position {i} must match the sequential prefix.");
            runningXor = logic.Xor(runningXor, x[i]);
            AssertBitEquals(logic, yx[i], runningXor, $"The forward XOR scan at width {width}, position {i} must match the sequential prefix.");
        }
    }


    /// <summary>Runs a backward Sklansky scan of And/Or/Xor over <paramref name="x"/> and checks it against sequential prefix recomputation.</summary>
    /// <param name="logic">The gadget layer to run the scans over.</param>
    /// <param name="x">The source bits; never mutated.</param>
    /// <param name="width">The bit count.</param>
    private static void AssertBackwardScan(LongfellowLogic logic, LongfellowBitWire[] x, int width)
    {
        var ya = (LongfellowBitWire[])x.Clone();
        var yo = (LongfellowBitWire[])x.Clone();
        var yx = (LongfellowBitWire[])x.Clone();

        logic.ScanAnd(ya, 0, width, backward: true);
        logic.ScanOr(yo, 0, width, backward: true);
        logic.ScanXor(yx, 0, width, backward: true);

        LongfellowBitWire runningAnd = logic.Bit(1);
        LongfellowBitWire runningOr = logic.Bit(0);
        LongfellowBitWire runningXor = logic.Bit(0);
        for(int i = width; i-- > 0;)
        {
            runningAnd = logic.And(runningAnd, x[i]);
            AssertBitEquals(logic, ya[i], runningAnd, $"The backward AND scan at width {width}, position {i} must match the sequential prefix.");
            runningOr = logic.Or(runningOr, x[i]);
            AssertBitEquals(logic, yo[i], runningOr, $"The backward OR scan at width {width}, position {i} must match the sequential prefix.");
            runningXor = logic.Xor(runningXor, x[i]);
            AssertBitEquals(logic, yx[i], runningXor, $"The backward XOR scan at width {width}, position {i} must match the sequential prefix.");
        }
    }


    /// <summary>Runs the reference's <c>Logic.AddSub</c> battery for all four adder kinds at one width over one field bundle, checking every sum/difference bit and the carry against unsigned arithmetic.</summary>
    /// <param name="field">The field bundle to gate over.</param>
    /// <param name="width">The operand width.</param>
    private static void AssertAdders(LongfellowLogicFieldOperations field, int width)
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(field), field);
        int widthPlusOneMask = (1 << (width + 1)) - 1;

        foreach(AdderKind kind in Enum.GetValues<AdderKind>())
        {
            for(int a = 0; a < (1 << width); a++)
            {
                for(int b = 0; b < (1 << width); b++)
                {
                    var ea = new LongfellowBitWire[width];
                    var eb = new LongfellowBitWire[width];
                    for(int i = 0; i < width; i++)
                    {
                        ea[i] = logic.Bit((a >> i) & 1);
                        eb[i] = logic.Bit((b >> i) & 1);
                    }

                    var ec = new LongfellowBitWire[width];
                    LongfellowBitWire carry = kind switch
                    {
                        AdderKind.RippleAdd => logic.RippleCarryAdd(ec, ea, eb),
                        AdderKind.RippleSubtract => logic.RippleCarrySubtract(ec, ea, eb),
                        AdderKind.ParallelPrefixAdd => logic.ParallelPrefixAdd(ec, ea, eb),
                        AdderKind.ParallelPrefixSubtract => logic.ParallelPrefixSubtract(ec, ea, eb),
                        _ => throw new System.Diagnostics.UnreachableException($"Unhandled adder kind: {kind}."),
                    };

                    uint expected = kind is AdderKind.RippleAdd or AdderKind.ParallelPrefixAdd
                        ? (uint)(a + b)
                        : (uint)((a - b) & widthPlusOneMask);

                    for(int i = 0; i < width; i++)
                    {
                        AssertBitEquals(logic, ec[i], (int)((expected >> i) & 1u), $"{kind} bit {i} must match unsigned arithmetic for a={a}, b={b}.");
                    }

                    AssertBitEquals(logic, carry, (int)((expected >> width) & 1u), $"{kind}'s carry must match unsigned arithmetic for a={a}, b={b}.");
                }
            }
        }
    }


    /// <summary>Builds a sparse GF(2^k) vector: every bit zero except the given nonzero indices, matching the reference's <c>gf2_init</c>.</summary>
    /// <param name="logic">The gadget layer whose constant-one/zero wires back the vector.</param>
    /// <param name="nonzeroIndices">The indices whose bit is one.</param>
    /// <returns>The sparse bit vector, <see cref="LongfellowLogic.BitWidth128"/> bits wide.</returns>
    private static LongfellowBitWire[] Gf2SparseVector(LongfellowLogic logic, int[] nonzeroIndices)
    {
        var vector = new LongfellowBitWire[LongfellowLogic.BitWidth128];
        for(int i = 0; i < vector.Length; i++)
        {
            vector[i] = logic.Bit(0);
        }

        foreach(int index in nonzeroIndices)
        {
            vector[index] = logic.Bit(1);
        }

        return vector;
    }


    /// <summary>Constructs a fresh evaluating <see cref="LongfellowLogic"/> over <see cref="Gf2128Field"/>, panicking on a failed assertion.</summary>
    /// <returns>The gadget layer.</returns>
    private static LongfellowLogic NewGf2128Logic() => new(new LongfellowEvaluationLogicBackend(Gf2128Field), Gf2128Field);


    /// <summary>Constructs a fresh evaluating <see cref="LongfellowLogic"/> over <see cref="Fp256Field"/>, panicking on a failed assertion.</summary>
    /// <returns>The gadget layer.</returns>
    private static LongfellowLogic NewFp256Logic() => new(new LongfellowEvaluationLogicBackend(Fp256Field), Fp256Field);


    /// <summary>Reads a bit's evaluated canonical bytes off its backend.</summary>
    /// <param name="logic">The gadget layer the bit was built over.</param>
    /// <param name="bit">The bit to read.</param>
    /// <returns>The evaluated canonical bytes.</returns>
    private static byte[] EvaluatedBytes(LongfellowLogic logic, LongfellowBitWire bit) => EvaluatedBytes(logic, logic.Eval(bit));


    /// <summary>Reads a wire's canonical bytes off its evaluating backend.</summary>
    /// <param name="logic">The gadget layer the wire was built over.</param>
    /// <param name="wire">The wire to read.</param>
    /// <returns>The wire's canonical bytes.</returns>
    private static byte[] EvaluatedBytes(LongfellowLogic logic, int wire) => ((LongfellowEvaluationLogicBackend)logic.Backend).ElementAt(wire).ToArray();


    /// <summary>Asserts that two bits evaluate to the same field element.</summary>
    /// <param name="logic">The gadget layer both bits were built over.</param>
    /// <param name="actual">The bit under test.</param>
    /// <param name="expected">The expected bit.</param>
    /// <param name="message">The assertion failure message.</param>
    private static void AssertBitEquals(LongfellowLogic logic, LongfellowBitWire actual, LongfellowBitWire expected, string message) =>
        Assert.IsTrue(EvaluatedBytes(logic, actual).AsSpan().SequenceEqual(EvaluatedBytes(logic, expected)), message);


    /// <summary>Asserts that a bit evaluates to the field's zero or one, per <paramref name="expectedValue"/>.</summary>
    /// <param name="logic">The gadget layer the bit was built over.</param>
    /// <param name="actual">The bit under test.</param>
    /// <param name="expectedValue">Zero or nonzero, matching <see cref="LongfellowLogic.Bit(int)"/>'s convention.</param>
    /// <param name="message">The assertion failure message.</param>
    private static void AssertBitEquals(LongfellowLogic logic, LongfellowBitWire actual, int expectedValue, string message) =>
        AssertBitEquals(logic, actual, logic.Bit(expectedValue), message);


    /// <summary>Asserts that two bit vectors are equal elementwise, matching the reference's <c>expect_vequal</c>.</summary>
    /// <param name="logic">The gadget layer both vectors were built over.</param>
    /// <param name="actual">The vector under test.</param>
    /// <param name="expected">The expected vector, the same length as <paramref name="actual"/>.</param>
    /// <param name="message">The assertion failure message, suffixed with the failing element index.</param>
    private static void AssertVectorEquals(LongfellowLogic logic, LongfellowBitWire[] actual, LongfellowBitWire[] expected, string message)
    {
        for(int i = 0; i < actual.Length; i++)
        {
            AssertBitEquals(logic, actual[i], expected[i], $"{message} (element {i})");
        }
    }


    /// <summary>Asserts that a bit vector matches an immediate, via <see cref="LongfellowLogic.BitVector(int, ulong)"/>.</summary>
    /// <param name="logic">The gadget layer the vector was built over.</param>
    /// <param name="actual">The vector under test.</param>
    /// <param name="immediate">The expected value, truncated to <paramref name="actual"/>'s width.</param>
    /// <param name="message">The assertion failure message.</param>
    private static void AssertVectorEqualsImmediate(LongfellowLogic logic, LongfellowBitWire[] actual, ulong immediate, string message) =>
        AssertVectorEquals(logic, actual, logic.BitVector(actual.Length, immediate), message);


    /// <summary>Builds the P-256 base field's modulus-minus-one, canonical big-endian, for <see cref="LongfellowLogicFieldOperations.CreateFp256"/>.</summary>
    /// <returns>The canonical <c>p - 1</c>.</returns>
    private static byte[] BuildFp256MinusOne()
    {
        byte[] canonical = new byte[Scalar.SizeBytes];
        byte[] bigEndian = (P256BaseFieldReference.FieldOrder - 1).ToByteArray(isUnsigned: true, isBigEndian: true);
        bigEndian.CopyTo(canonical.AsSpan(Scalar.SizeBytes - bigEndian.Length));

        return canonical;
    }
}
