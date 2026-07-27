using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the bit-adder encoding gadget (<see cref="LongfellowBitAdder"/>), a faithful port of
/// google/longfellow-zk's <c>bit_adder_test.cc</c>: the <c>assert_eqmod</c> latch behavior of both
/// arithmetizations (additive over an odd-prime field, multiplicative alpha powers over
/// characteristic two), plus new coverage of <see cref="LongfellowBitAdder.AsFieldElement"/>'s
/// encoding formula and <see cref="LongfellowBitAdder.Add(int, int)"/>'s combine rule against
/// out-of-circuit oracles built with the raw field delegates rather than the gadget's own state.
/// </summary>
/// <remarks>
/// <para>
/// The reference's <c>test_bit_adder&lt;Field&gt;()</c> template sweeps every <c>(a, b, c, s)</c>
/// quadruple at <c>w = 4</c> and checks <c>ebk.assertion_failed() == (((a + b + c) ^ s) &amp; mask)
/// != 0</c> on a non-panicking backend, over both <c>GF2_128&lt;&gt;</c> and <c>Fp128&lt;&gt;</c>;
/// this port runs the same check over <see cref="Gf2128Field"/> and <see cref="Fp256Field"/> (this
/// stack's wired odd-prime field) at <c>w = 3</c>: <c>assert_eqmod</c>'s carry-check loop is one
/// fixed per-width formula in each arithmetization (the weighted-sum difference, or the alpha-power
/// table), so a narrower exhaustive sweep still exercises the same recurrence in both field
/// arithmetics.
/// </para>
/// <para>
/// <see cref="LongfellowBitAdder.AsFieldElement"/> and <see cref="LongfellowBitAdder.Add(int, int)"/>
/// have no reference test of their own — <c>bit_adder_test.cc</c> only exercises them indirectly
/// through <c>assert_eqmod</c> — so they are checked here against independent oracles: the odd-prime
/// arm against <see cref="LongfellowLogicFieldOperations.OfScalar"/>, and the characteristic-two arm
/// against a product of <see cref="LongfellowLogicFieldOperations.X"/> powers recomputed with the raw
/// <see cref="Gf2k128Backend"/> multiplication delegate, never through the gadget's own cached power
/// table.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowBitAdderTests
{
    /// <summary>
    /// The reference's w = 4; assert_eqmod's carry-check is a single fixed-shape formula per width
    /// (the weighted-sum difference over the odd-prime field, the alpha-power table over
    /// characteristic two), so an exhaustive sweep at a narrower width still pins the same recurrence.
    /// </summary>
    private const int AdderWidth = 3;

    /// <summary>
    /// The reference test's literal <c>assert_eqmod(..., 3)</c> argument: a 3-term sum of w-bit values
    /// is bounded by <c>3*(2^w - 1) &lt; 3*2^w</c>, so 3 candidate carries always suffice regardless of
    /// w; unreduced.
    /// </summary>
    private const int CandidateCarryCount = 3;

    /// <summary>
    /// No reference sweep bounds the AsFieldElement/Add round-trip gates below (<c>assert_eqmod</c> is
    /// the only reference test touching this gadget), so the full byte range is used instead of the
    /// width-3 sweep above, exercising both encoding arms more thoroughly than the latch test needs.
    /// </summary>
    private const int EncodedElementWidth = LongfellowLogic.BitWidth8;

    /// <summary>The P-256 base field's modulus-minus-one, canonical big-endian, used to construct <see cref="Fp256Field"/>.</summary>
    private static ReadOnlyMemory<byte> Fp256MinusOne { get; } = BuildFp256MinusOne();

    /// <summary>The GF(2^128) field bundle gated over by the GF(2^128) tests.</summary>
    private static LongfellowLogicFieldOperations Gf2128Field { get; } = LongfellowLogicFieldOperations.CreateGf2128(
        Gf2k128Backend.GetAdd(),
        Gf2k128Backend.GetSubtract(),
        Gf2k128Backend.GetMultiply(),
        Gf2k128Backend.GetInvert());

    /// <summary>The P-256 base field bundle gated over by the Fp256 tests.</summary>
    private static LongfellowLogicFieldOperations Fp256Field { get; } = LongfellowLogicFieldOperations.CreateFp256(
        P256BaseFieldReference.GetAdd(),
        P256BaseFieldReference.GetSubtract(),
        P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(),
        Fp256MinusOne);

    /// <summary>The raw GF(2^128) field multiplication delegate, used as an independent oracle rather than the gadget's own cached power table.</summary>
    private static ScalarMultiplyDelegate Gf2128Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The raw P-256 base field addition delegate, used as an independent oracle for <see cref="LongfellowBitAdder.Add(int, int)"/>'s odd-prime arm.</summary>
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldReference.GetAdd();


    /// <summary>Pins that AssertEqualModulo's failure latch matches the closed-form three-way carry disagreement over GF(2^128).</summary>
    [TestMethod]
    public void AssertEqualModuloLatchesExactlyWhenTheThreeWaySumDisagreesOverGf2128()
    {
        AssertAssertEqualModuloLatch(Gf2128Field);
    }


    /// <summary>Pins that AssertEqualModulo's failure latch matches the closed-form three-way carry disagreement over the P-256 base field.</summary>
    [TestMethod]
    public void AssertEqualModuloLatchesExactlyWhenTheThreeWaySumDisagreesOverFp256()
    {
        AssertAssertEqualModuloLatch(Fp256Field);
    }


    /// <summary>Pins that AsFieldElement matches OfScalar across every encodable value over the P-256 base field.</summary>
    [TestMethod]
    public void AsFieldElementMatchesOfScalarOverFp256()
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(Fp256Field), Fp256Field);
        var adder = new LongfellowBitAdder(logic, EncodedElementWidth);

        for(int value = 0; value < (1 << EncodedElementWidth); value++)
        {
            LongfellowBitWire[] bits = logic.BitVector(EncodedElementWidth, (ulong)value);
            int wire = adder.AsFieldElement(bits);

            byte[] expected = Fp256Field.OfScalar((ulong)value).ToArray();
            Assert.IsTrue(EvaluatedBytes(logic, wire).AsSpan().SequenceEqual(expected), $"AsFieldElement must match OfScalar for value={value}.");
        }
    }


    /// <summary>Pins that AsFieldElement matches the raw alpha-power product across every encodable value over GF(2^128).</summary>
    [TestMethod]
    public void AsFieldElementMatchesTheAlphaPowerProductOverGf2128()
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(Gf2128Field), Gf2128Field);
        var adder = new LongfellowBitAdder(logic, EncodedElementWidth);

        for(int value = 0; value < (1 << EncodedElementWidth); value++)
        {
            LongfellowBitWire[] bits = logic.BitVector(EncodedElementWidth, (ulong)value);
            int wire = adder.AsFieldElement(bits);

            byte[] expected = AlphaPowerProduct(value);
            Assert.IsTrue(EvaluatedBytes(logic, wire).AsSpan().SequenceEqual(expected), $"AsFieldElement must match the raw alpha-power product for value={value}.");
        }
    }


    /// <summary>Pins that Add of two encoded elements is field addition over the P-256 base field.</summary>
    [TestMethod]
    public void AddOfTwoEncodedElementsIsFieldAdditionOverFp256()
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(Fp256Field), Fp256Field);
        var adder = new LongfellowBitAdder(logic, AdderWidth);

        for(int a = 0; a < (1 << AdderWidth); a++)
        {
            for(int b = 0; b < (1 << AdderWidth); b++)
            {
                int ea = adder.AsFieldElement(logic.BitVector(AdderWidth, (ulong)a));
                int eb = adder.AsFieldElement(logic.BitVector(AdderWidth, (ulong)b));
                int combined = adder.Add(ea, eb);

                var expected = new byte[Scalar.SizeBytes];
                Fp256Add(Fp256Field.OfScalar((ulong)a).Span, Fp256Field.OfScalar((ulong)b).Span, expected, Fp256Field.Compiler.Curve);

                Assert.IsTrue(EvaluatedBytes(logic, combined).AsSpan().SequenceEqual(expected), $"Add(int, int) must be field addition over Fp256 for a={a}, b={b}.");
            }
        }
    }


    /// <summary>Pins that Add of two encoded elements is field multiplication over GF(2^128).</summary>
    [TestMethod]
    public void AddOfTwoEncodedElementsIsFieldMultiplicationOverGf2128()
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(Gf2128Field), Gf2128Field);
        var adder = new LongfellowBitAdder(logic, AdderWidth);

        for(int a = 0; a < (1 << AdderWidth); a++)
        {
            for(int b = 0; b < (1 << AdderWidth); b++)
            {
                int ea = adder.AsFieldElement(logic.BitVector(AdderWidth, (ulong)a));
                int eb = adder.AsFieldElement(logic.BitVector(AdderWidth, (ulong)b));
                int combined = adder.Add(ea, eb);

                var expected = new byte[Scalar.SizeBytes];
                Gf2128Multiply(AlphaPowerProduct(a), AlphaPowerProduct(b), expected, Gf2128Field.Compiler.Curve);

                Assert.IsTrue(EvaluatedBytes(logic, combined).AsSpan().SequenceEqual(expected), $"Add(int, int) must be field multiplication over GF(2^128) for a={a}, b={b}.");
            }
        }
    }


    /// <summary>Runs the reference's <c>test_bit_adder</c> exhaustive <c>(a, b, c, s)</c> sweep over one field bundle, checking the latch against the closed-form carry disagreement.</summary>
    /// <param name="field">The field bundle to gate over.</param>
    private static void AssertAssertEqualModuloLatch(LongfellowLogicFieldOperations field)
    {
        int mask = (1 << AdderWidth) - 1;

        for(int a = 0; a < (1 << AdderWidth); a++)
        {
            for(int b = 0; b < (1 << AdderWidth); b++)
            {
                for(int c = 0; c < (1 << AdderWidth); c++)
                {
                    for(int s = 0; s < (1 << AdderWidth); s++)
                    {
                        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
                        var logic = new LongfellowLogic(backend, field);
                        var adder = new LongfellowBitAdder(logic, AdderWidth);

                        LongfellowBitWire[] ea = logic.BitVector(AdderWidth, (ulong)a);
                        LongfellowBitWire[] eb = logic.BitVector(AdderWidth, (ulong)b);
                        LongfellowBitWire[] ec = logic.BitVector(AdderWidth, (ulong)c);
                        LongfellowBitWire[] es = logic.BitVector(AdderWidth, (ulong)s);

                        adder.AssertEqualModulo(es, adder.Add([ea, eb, ec]), CandidateCarryCount);

                        bool expectedFailure = (((a + b + c) ^ s) & mask) != 0;
                        Assert.AreEqual(expectedFailure, backend.AssertionFailed, $"assert_eqmod's failure latch must match (((a + b + c) ^ s) & mask) != 0 for a={a}, b={b}, c={c}, s={s}.");
                    }
                }
            }
        }
    }


    /// <summary>
    /// Computes <c>Π alpha^(2^i)</c> over the set bits of <paramref name="value"/>, entirely through
    /// the raw <see cref="Gf2128Multiply"/> delegate rather than <see cref="LongfellowBitAdder"/>'s own
    /// cached power table, serving as an independent oracle for
    /// <see cref="LongfellowBitAdder.AsFieldElement"/>'s characteristic-two arm.
    /// </summary>
    /// <param name="value">The packed bit pattern; only its low <see cref="EncodedElementWidth"/> bits are read.</param>
    /// <returns>The product, canonical big-endian.</returns>
    private static byte[] AlphaPowerProduct(int value)
    {
        byte[] product = Gf2128Field.Compiler.One.ToArray();
        byte[] alpha = Gf2128Field.X.ToArray();
        for(int i = 0; i < EncodedElementWidth; i++)
        {
            if(((value >> i) & 1) != 0)
            {
                var next = new byte[Scalar.SizeBytes];
                Gf2128Multiply(product, alpha, next, Gf2128Field.Compiler.Curve);
                product = next;
            }

            var squared = new byte[Scalar.SizeBytes];
            Gf2128Multiply(alpha, alpha, squared, Gf2128Field.Compiler.Curve);
            alpha = squared;
        }

        return product;
    }


    /// <summary>Reads a wire's canonical bytes off its evaluating backend.</summary>
    /// <param name="logic">The gadget layer the wire was built over.</param>
    /// <param name="wire">The wire to read.</param>
    /// <returns>The wire's canonical bytes.</returns>
    private static byte[] EvaluatedBytes(LongfellowLogic logic, int wire) => ((LongfellowEvaluationLogicBackend)logic.Backend).ElementAt(wire).ToArray();


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
