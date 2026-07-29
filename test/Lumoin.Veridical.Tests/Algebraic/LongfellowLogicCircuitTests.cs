using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Compile-path gates for the Logic/BitW gadget layer, the port of the reference's
/// <c>logic_circuit_test.cc</c>: the adder family and the schoolbook multiplier are compiled through
/// the QuadCircuit kernel over GF(2^128) and the compiled circuits are evaluated over every input pair
/// against native integer arithmetic.
/// </summary>
/// <remarks>
/// The reference test emits the gadget results as explicit output wires and reads them back from its
/// prover's <c>eval_circuit</c>. This stack's <see cref="LongfellowSumcheckProver.EvaluateCircuit"/>
/// requires every circuit output to evaluate to zero (the assert-zero convention the ZK pipeline
/// runs on), so these gates compile the assertion form instead: the claimed result enters as extra
/// witness bits and the circuit asserts equality, making "the witness satisfies the circuit" the
/// oracle. A wrong claim must throw, pinning that the assertions are not vacuous. The reference
/// sweeps widths to 8; these gates sweep exhaustively at the reduced widths named below — the
/// arithmetization is width-uniform, so a reduced exhaustive sweep pins the same recurrences.
/// </remarks>
[TestClass]
internal sealed class LongfellowLogicCircuitTests
{
    /// <summary>The field element width in bytes used for every witness column entry.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The compiled circuits carry a single copy, matching the reference tests' <c>nc = 1</c>.</summary>
    private const int CopyCount = 1;

    /// <summary>
    /// The adder gates sweep every width from one to this bound exhaustively (the reference sweeps to
    /// eight; the generate/propagate recurrences are width-uniform).
    /// </summary>
    private const int MaxAdderWidth = 4;

    /// <summary>
    /// The multiplier gate's operand width (the reference sweeps to eight; each row repeats the same
    /// AND-then-ripple-add recurrence).
    /// </summary>
    private const int MultiplierWidth = 3;

    /// <summary>The GF(2^128) field addition delegate.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>
    /// One adder gadget under test: writes the sum bits into <paramref name="sum"/> and returns the
    /// carry-out bit.
    /// </summary>
    /// <param name="logic">The gadget layer compiling the adder.</param>
    /// <param name="sum">Receives the width-wide result bits.</param>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The carry-out bit.</returns>
    private delegate LongfellowBitWire AdderGate(LongfellowLogic logic, Span<LongfellowBitWire> sum, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b);


    /// <summary>Pins that the compiled ripple-carry adder gadget matches native addition across every operand pair and rejects a wrong sum claim.</summary>
    [TestMethod]
    public void TheCompiledRippleCarryAdderMatchesNativeAddition()
    {
        AssertAdderCircuitMatchesNativeArithmetic((logic, sum, a, b) => logic.RippleCarryAdd(sum, a, b), (x, y) => x + y);
    }


    /// <summary>Pins that the compiled ripple-carry subtractor gadget matches native subtraction across every operand pair and rejects a wrong difference claim.</summary>
    [TestMethod]
    public void TheCompiledRippleCarrySubtractorMatchesNativeSubtraction()
    {
        AssertAdderCircuitMatchesNativeArithmetic((logic, sum, a, b) => logic.RippleCarrySubtract(sum, a, b), (x, y) => x - y);
    }


    /// <summary>Pins that the compiled parallel-prefix adder gadget matches native addition across every operand pair and rejects a wrong sum claim.</summary>
    [TestMethod]
    public void TheCompiledParallelPrefixAdderMatchesNativeAddition()
    {
        AssertAdderCircuitMatchesNativeArithmetic((logic, sum, a, b) => logic.ParallelPrefixAdd(sum, a, b), (x, y) => x + y);
    }


    /// <summary>Pins that the compiled parallel-prefix subtractor gadget matches native subtraction across every operand pair and rejects a wrong difference claim.</summary>
    [TestMethod]
    public void TheCompiledParallelPrefixSubtractorMatchesNativeSubtraction()
    {
        AssertAdderCircuitMatchesNativeArithmetic((logic, sum, a, b) => logic.ParallelPrefixSubtract(sum, a, b), (x, y) => x - y);
    }


    /// <summary>Pins that the compiled schoolbook multiplier gadget matches native multiplication across every operand pair — cross-checked against the evaluation backend's own multiplier — and rejects a wrong product claim.</summary>
    [TestMethod]
    public void TheCompiledMultiplierMatchesNativeMultiplication()
    {
        LongfellowSumcheckCircuit circuit = CompileMultiplierCircuit(MultiplierWidth);
        int productWidth = 2 * MultiplierWidth;

        LongfellowLogicFieldOperations evaluationField = LongfellowLogicFieldOperations.CreateGf2128(Add, Subtract, Multiply, Invert);
        var evaluationBackend = new LongfellowEvaluationLogicBackend(evaluationField);
        var evaluationLogic = new LongfellowLogic(evaluationBackend, evaluationField);

        for(ulong x = 0; x < (1UL << MultiplierWidth); x++)
        {
            for(ulong y = 0; y < (1UL << MultiplierWidth); y++)
            {
                byte[] column = BuildBinaryColumn(circuit.InputCount, [(x, MultiplierWidth), (y, MultiplierWidth), (x * y, productWidth)]);
                using LongfellowWireTables tables = LongfellowSumcheckProver.EvaluateCircuit(circuit, column, Multiply, Add, CurveParameterSet.None, BaseMemoryPool.Shared);

                //The evaluation backend's multiplier must agree with the same native product the
                //compiled circuit just accepted, closing the compiled-versus-evaluated cross-check.
                var evaluatedProduct = new LongfellowBitWire[productWidth];
                evaluationLogic.Multiplier(evaluatedProduct, evaluationLogic.BitVector(MultiplierWidth, x), evaluationLogic.BitVector(MultiplierWidth, y));
                for(int bit = 0; bit < productWidth; bit++)
                {
                    ReadOnlyMemory<byte> expectedBit = ((x * y) >> bit & 1UL) == 0UL ? evaluationField.Compiler.Zero : evaluationField.Compiler.One;
                    Assert.IsTrue(evaluationBackend.ElementAt(evaluationLogic.Eval(evaluatedProduct[bit])).Span.SequenceEqual(expectedBit.Span), $"The evaluated multiplier bit {bit} must match the native product for x={x}, y={y}.");
                }
            }
        }

        //A wrong product claim must fail the compiled assertions rather than pass vacuously.
        byte[] wrongColumn = BuildBinaryColumn(circuit.InputCount, [(3UL, MultiplierWidth), (5UL, MultiplierWidth), ((3UL * 5UL) ^ 1UL, productWidth)]);
        Assert.ThrowsExactly<InvalidOperationException>(
            () => LongfellowSumcheckProver.EvaluateCircuit(circuit, wrongColumn, Multiply, Add, CurveParameterSet.None, BaseMemoryPool.Shared).Dispose(),
            "A wrong product claim must be rejected by the compiled circuit.");
    }


    /// <summary>
    /// Compiles one adder circuit per width and evaluates it over every operand pair, then pins the
    /// assertion form with one deliberately wrong claim per width.
    /// </summary>
    /// <param name="gate">The adder gadget under test.</param>
    /// <param name="expected">The native arithmetic operation the gadget must match.</param>
    private static void AssertAdderCircuitMatchesNativeArithmetic(AdderGate gate, Func<ulong, ulong, ulong> expected)
    {
        for(int width = 1; width <= MaxAdderWidth; width++)
        {
            LongfellowSumcheckCircuit circuit = CompileAdderCircuit(gate, width);

            for(ulong x = 0; x < (1UL << width); x++)
            {
                for(ulong y = 0; y < (1UL << width); y++)
                {
                    byte[] column = BuildBinaryColumn(circuit.InputCount, [(x, width), (y, width), (expected(x, y), width + 1)]);
                    using LongfellowWireTables tables = LongfellowSumcheckProver.EvaluateCircuit(circuit, column, Multiply, Add, CurveParameterSet.None, BaseMemoryPool.Shared);
                }
            }

            byte[] wrongColumn = BuildBinaryColumn(circuit.InputCount, [(0UL, width), (0UL, width), (expected(0UL, 0UL) ^ 1UL, width + 1)]);
            Assert.ThrowsExactly<InvalidOperationException>(
                () => LongfellowSumcheckProver.EvaluateCircuit(circuit, wrongColumn, Multiply, Add, CurveParameterSet.None, BaseMemoryPool.Shared).Dispose(),
                $"A wrong claim at width {width} must be rejected by the compiled circuit.");
        }
    }


    /// <summary>
    /// Builds the adder assertion circuit: operands a and b, the gadget's sum and carry, and a claimed
    /// (width + 1)-bit result asserted equal bit for bit.
    /// </summary>
    /// <param name="gate">The adder gadget to compile.</param>
    /// <param name="width">The operand width in bits.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileAdderCircuit(AdderGate gate, int width)
    {
        LongfellowLogic logic = NewCompileLogic(out LongfellowQuadCircuitBuilder builder);

        LongfellowBitWire[] a = logic.InputVector(width);
        LongfellowBitWire[] b = logic.InputVector(width);
        var sum = new LongfellowBitWire[width];
        LongfellowBitWire carry = gate(logic, sum, a, b);
        LongfellowBitWire[] claimed = logic.InputVector(width + 1);
        logic.AssertEqual(LongfellowLogic.Append(sum, [carry]), claimed);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Builds the multiplier assertion circuit: operands a and b, the schoolbook product, and a
    /// claimed double-width result asserted equal bit for bit.
    /// </summary>
    /// <param name="width">The operand width in bits.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileMultiplierCircuit(int width)
    {
        LongfellowLogic logic = NewCompileLogic(out LongfellowQuadCircuitBuilder builder);

        LongfellowBitWire[] a = logic.InputVector(width);
        LongfellowBitWire[] b = logic.InputVector(width);
        var product = new LongfellowBitWire[2 * width];
        logic.Multiplier(product, a, b);
        LongfellowBitWire[] claimed = logic.InputVector(2 * width);
        logic.AssertEqual(product, claimed);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>Builds the GF(2^128) gadget layer and its backing compiler for one circuit compilation.</summary>
    /// <param name="builder">Receives the underlying quad-circuit builder.</param>
    /// <returns>The gadget layer.</returns>
    private static LongfellowLogic NewCompileLogic(out LongfellowQuadCircuitBuilder builder)
    {
        LongfellowLogicFieldOperations field = LongfellowLogicFieldOperations.CreateGf2128(Add, Subtract, Multiply, Invert);
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);

        return new LongfellowLogic(backend, field);
    }


    /// <summary>
    /// Builds the witness column: the constant one, then each value's bits least significant first,
    /// one canonical scalar per bit wire.
    /// </summary>
    /// <param name="inputCount">The compiled circuit's declared input count.</param>
    /// <param name="segments">Each value and its bit width, in declaration order.</param>
    /// <returns>The witness column, one canonical scalar per declared input wire.</returns>
    private static byte[] BuildBinaryColumn(int inputCount, (ulong Value, int Width)[] segments)
    {
        byte[] column = new byte[inputCount * ScalarSize];
        column[ScalarSize - 1] = 0x01;

        int wire = 1;
        foreach((ulong value, int width) in segments)
        {
            for(int bit = 0; bit < width; bit++, wire++)
            {
                column[(wire * ScalarSize) + ScalarSize - 1] = (byte)((value >> bit) & 1UL);
            }
        }

        Assert.AreEqual(inputCount, wire, "The column layout must cover exactly the declared input wires.");

        return column;
    }
}
