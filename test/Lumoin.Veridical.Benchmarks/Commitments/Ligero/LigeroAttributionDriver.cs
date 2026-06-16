using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Diagnostics;
using System.Globalization;

namespace Lumoin.Veridical.Benchmarks.Commitments.Ligero;

/// <summary>
/// One-shot attribution of where a representative Fp256 Ligero proof spends its
/// field arithmetic: it times one Fp256 multiply/invert/add/subtract, counts the
/// add/subtract/multiply/invert calls a full <see cref="LigeroProver"/> proof of a
/// witnessed scalar-multiply ladder makes (split by kind), reconstructs the share
/// of those that come from the Reed–Solomon encoder (from the exact encode shapes
/// the tableau and dot-response paths use), and cross-checks the predicted
/// field-arithmetic time against the measured prove wall time. The output tells us
/// whether the proof is field-bound and how much of that is the encoder — the
/// input to the next perf decision (CRT-FFT encoder vs. faster Fp256 backend vs.
/// cheap constant-factor wins such as batched inversion).
/// </summary>
internal static class LigeroAttributionDriver
{
    private const int ScalarSize = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;
    private static readonly BaseMemoryPool Pool = BaseMemoryPool.Shared;

    private const int LadderWidth = 5;
    private const int LadderScalar = 13;


    public static void Run()
    {
        ScalarAddDelegate add = P256BaseFieldReference.GetAdd();
        ScalarSubtractDelegate subtract = P256BaseFieldReference.GetSubtract();
        ScalarMultiplyDelegate multiply = P256BaseFieldReference.GetMultiply();
        ScalarInvertDelegate invert = P256BaseFieldReference.GetInvert();
        ScalarReduceDelegate reduce = P256BaseFieldReference.GetReduce();

        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "=== Ligero Fp256 attribution ==="));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "Circuit: width-{0} single-scalar ladder (k={1}); InverseRate={2}, OpenedColumns={3}, Block={4}",
            LadderWidth, LadderScalar, LigeroFp256Harness.InverseRate, LigeroFp256Harness.OpenedColumns, LigeroFp256Harness.Block));

        //--- 1. Per-op Fp256 cost (raw delegates) ---
        double mulNs = TimePerOp(() => multiply(OperandA, OperandB, Scratch, Curve), 200_000);
        double invNs = TimePerOp(() => invert(OperandA, Scratch, Curve), 5_000);
        double addNs = TimePerOp(() => add(OperandA, OperandB, Scratch, Curve), 500_000);
        double subNs = TimePerOp(() => subtract(OperandA, OperandB, Scratch, Curve), 500_000);
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "Per-op (ns): multiply={0:F1}  invert={1:F1}  add={2:F1}  subtract={3:F1}  (invert/multiply = {4:F1}x)",
            mulNs, invNs, addNs, subNs, invNs / mulNs));

        //--- 1b. Per-op multiply + invert across the three backends (reliable, warmed) ---
        ScalarMultiplyDelegate montgomeryMultiply = P256BaseFieldMontgomeryBackend.GetMultiply();
        ScalarInvertDelegate montgomeryInvert = P256BaseFieldMontgomeryBackend.GetInvert();
        ScalarMultiplyDelegate solinasMultiply = P256BaseFieldSolinasBackend.GetMultiply();
        ScalarInvertDelegate solinasInvert = P256BaseFieldSolinasBackend.GetInvert();
        double montgomeryMulNs = TimePerOp(() => montgomeryMultiply(OperandA, OperandB, Scratch, Curve), 200_000);
        double montgomeryInvNs = TimePerOp(() => montgomeryInvert(OperandA, Scratch, Curve), 5_000);
        double solinasMulNs = TimePerOp(() => solinasMultiply(OperandA, OperandB, Scratch, Curve), 200_000);
        double solinasInvNs = TimePerOp(() => solinasInvert(OperandA, Scratch, Curve), 5_000);
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "Per-op multiply (ns): BigInteger={0:F1}  Montgomery={1:F1}  Solinas={2:F1}", mulNs, montgomeryMulNs, solinasMulNs));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "Per-op invert   (ns): BigInteger={0:F1}  Montgomery={1:F1}  Solinas={2:F1}", invNs, montgomeryInvNs, solinasInvNs));

        //--- 2. Build the circuit (raw delegates; construction ops are not the prove cost) ---
        LigeroConstraintSystemBuilder builder = LigeroFp256Harness.BuildSingleScalarLadder(LadderWidth, LadderScalar, add, subtract, multiply, invert, reduce);
        LigeroParameters parameters = builder.BuildParameters();
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int blockEncoded = parameters.BlockEncoded;
        int nwq = parameters.WitnessRowCount + (3 * parameters.QuadraticTripleCount);
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "Params: wires={0}, quadratics={1}, rows={2} (witnessRows={3}, quadTriples={4}), block={5}, dblock={6}, blockEncoded={7}",
            parameters.WitnessCount, parameters.QuadraticConstraintCount, parameters.RowCount,
            parameters.WitnessRowCount, parameters.QuadraticTripleCount, block, dblock, blockEncoded));

        //--- 3. Time a full prove (raw delegates) ---
        using(LigeroFp256Harness.Prove(builder, add, subtract, multiply, invert, reduce)) { } //warm up + verify it proves
        Stopwatch proveWatch = Stopwatch.StartNew();
        using(LigeroFp256Harness.Prove(builder, add, subtract, multiply, invert, reduce)) { }
        proveWatch.Stop();
        double proveMs = proveWatch.Elapsed.TotalMilliseconds;

        //--- 4. Count prove field ops by kind (wrapped delegates) ---
        var proveCounter = new CountingField(add, subtract, multiply, invert);
        using(LigeroFp256Harness.Prove(builder, proveCounter.Add, proveCounter.Subtract, proveCounter.Multiply, proveCounter.Invert, reduce)) { }
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "Prove field ops: multiply={0}, invert={1}, add={2}, subtract={3}, total={4}",
            proveCounter.Mul, proveCounter.Inv, proveCounter.Add_, proveCounter.Sub, proveCounter.Total));

        //--- 5. Encoder field ops, reconstructed from the exact encode shapes ---
        (long Mul, long Inv, long Add, long Sub) eTableau = EncodeOps(block, blockEncoded, add, subtract, multiply, invert, reduce);
        (long Mul, long Inv, long Add, long Sub) eBlinding = EncodeOps(dblock, blockEncoded, add, subtract, multiply, invert, reduce);
        (long Mul, long Inv, long Add, long Sub) eResponse = EncodeOps(block, dblock, add, subtract, multiply, invert, reduce);

        //Tableau: 1 ILDT (block->blockEnc) + 2 blinding (dblock->blockEnc) +
        //nwq witness/quadratic rows (block->blockEnc). Responses: nwq (block->dblock).
        long encMul = (eTableau.Mul * (1 + nwq)) + (eBlinding.Mul * 2) + (eResponse.Mul * nwq);
        long encInv = (eTableau.Inv * (1 + nwq)) + (eBlinding.Inv * 2) + (eResponse.Inv * nwq);
        long encAdd = (eTableau.Add * (1 + nwq)) + (eBlinding.Add * 2) + (eResponse.Add * nwq);
        long encSub = (eTableau.Sub * (1 + nwq)) + (eBlinding.Sub * 2) + (eResponse.Sub * nwq);
        long encTotal = encMul + encInv + encAdd + encSub;
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "Encoder field ops: multiply={0}, invert={1}, add={2}, subtract={3}, total={4}",
            encMul, encInv, encAdd, encSub, encTotal));

        //--- 6. Attribution ---
        double encoderOpShare = proveCounter.Total == 0 ? 0 : 100.0 * encTotal / proveCounter.Total;
        double encoderInvShare = proveCounter.Inv == 0 ? 0 : 100.0 * encInv / proveCounter.Inv;
        double predictedFieldMs = ((proveCounter.Mul * mulNs) + (proveCounter.Inv * invNs) + (proveCounter.Add_ * addNs) + (proveCounter.Sub * subNs)) / 1_000_000.0;
        double predictedEncoderMs = ((encMul * mulNs) + (encInv * invNs) + (encAdd * addNs) + (encSub * subNs)) / 1_000_000.0;

        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "--- attribution ---"));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Prove wall time:            {0:F1} ms", proveMs));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Predicted field-arith time: {0:F1} ms ({1:F0}% of wall) -> field-bound check", predictedFieldMs, 100.0 * predictedFieldMs / proveMs));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Encoder share of field ops: {0:F1}%  (of inversions: {1:F1}%)", encoderOpShare, encoderInvShare));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Predicted encoder time:     {0:F1} ms ({1:F0}% of wall)", predictedEncoderMs, 100.0 * predictedEncoderMs / proveMs));

        //--- 7. Prove + verify wall time per backend (same circuit; single-threaded) ---
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "--- backend comparison (prove/verify wall time, same circuit, single-thread) ---"));
        (double referenceProve, double referenceVerify) = TimeProveAndVerify(builder, add, subtract, multiply, invert, reduce);
        (double montgomeryProve, double montgomeryVerify) = TimeProveAndVerify(builder,
            P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract(), P256BaseFieldMontgomeryBackend.GetMultiply(),
            P256BaseFieldMontgomeryBackend.GetInvert(), P256BaseFieldMontgomeryBackend.GetReduce());
        (double solinasProve, double solinasVerify) = TimeProveAndVerify(builder,
            P256BaseFieldSolinasBackend.GetAdd(), P256BaseFieldSolinasBackend.GetSubtract(), P256BaseFieldSolinasBackend.GetMultiply(),
            P256BaseFieldSolinasBackend.GetInvert(), P256BaseFieldSolinasBackend.GetReduce());
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "BigInteger reference: prove={0:F1} ms  verify={1:F1} ms", referenceProve, referenceVerify));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Montgomery:           prove={0:F1} ms  verify={1:F1} ms", montgomeryProve, montgomeryVerify));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Solinas:              prove={0:F1} ms  verify={1:F1} ms", solinasProve, solinasVerify));
    }


    private static (double ProveMs, double VerifyMs) TimeProveAndVerify(
        LigeroConstraintSystemBuilder builder, ScalarAddDelegate add, ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        using(LigeroProof warmup = LigeroFp256Harness.Prove(builder, add, subtract, multiply, invert, reduce))
        {
            LigeroFp256Harness.Verify(builder, warmup, add, subtract, multiply, invert, reduce); //warm up both
        }

        Stopwatch proveWatch = Stopwatch.StartNew();
        using LigeroProof proof = LigeroFp256Harness.Prove(builder, add, subtract, multiply, invert, reduce);
        proveWatch.Stop();

        Stopwatch verifyWatch = Stopwatch.StartNew();
        LigeroFp256Harness.Verify(builder, proof, add, subtract, multiply, invert, reduce);
        verifyWatch.Stop();

        return (proveWatch.Elapsed.TotalMilliseconds, verifyWatch.Elapsed.TotalMilliseconds);
    }


    private static (long Mul, long Inv, long Add, long Sub) EncodeOps(
        int messageLength, int codewordLength, ScalarAddDelegate add, ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        byte[] message = new byte[messageLength * ScalarSize];
        var random = new Random(0x5EED5EED + messageLength);
        Span<byte> raw = stackalloc byte[64];
        for(int i = 0; i < messageLength; i++)
        {
            random.NextBytes(raw);
            reduce(raw, message.AsSpan(i * ScalarSize, ScalarSize), Curve);
        }

        byte[] codeword = new byte[codewordLength * ScalarSize];
        var counter = new CountingField(add, subtract, multiply, invert);
        LigeroReedSolomonEncoder.Encode(message, messageLength, codeword, codewordLength,
            counter.Add, counter.Subtract, counter.Multiply, counter.Invert, Curve, Pool);

        return (counter.Mul, counter.Inv, counter.Add_, counter.Sub);
    }


    private static readonly byte[] OperandA = MakeOperand(1);
    private static readonly byte[] OperandB = MakeOperand(2);
    private static readonly byte[] Scratch = new byte[ScalarSize];


    private static byte[] MakeOperand(int salt)
    {
        byte[] value = new byte[ScalarSize];
        Span<byte> raw = stackalloc byte[64];
        new Random(0x5EED5EED + salt).NextBytes(raw);
        P256BaseFieldReference.GetReduce()(raw, value, Curve);

        return value;
    }


    private static double TimePerOp(Action operation, int iterations)
    {
        for(int i = 0; i < Math.Min(iterations, 1000); i++)
        {
            operation();
        }

        Stopwatch watch = Stopwatch.StartNew();
        for(int i = 0; i < iterations; i++)
        {
            operation();
        }

        watch.Stop();

        return watch.Elapsed.TotalMilliseconds * 1_000_000.0 / iterations;
    }


    //Field delegates that count their calls by kind, forwarding to the raw backend.
    private sealed class CountingField
    {
        private readonly ScalarAddDelegate rawAdd;
        private readonly ScalarSubtractDelegate rawSubtract;
        private readonly ScalarMultiplyDelegate rawMultiply;
        private readonly ScalarInvertDelegate rawInvert;

        public long Mul;
        public long Inv;
        public long Add_;
        public long Sub;

        public CountingField(ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert)
        {
            rawAdd = add;
            rawSubtract = subtract;
            rawMultiply = multiply;
            rawInvert = invert;
        }

        public long Total => Mul + Inv + Add_ + Sub;

        public void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            Add_++;
            rawAdd(a, b, result, curve);
        }

        public void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            Sub++;
            rawSubtract(a, b, result, curve);
        }

        public void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            Mul++;
            rawMultiply(a, b, result, curve);
        }

        public void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
        {
            Inv++;
            rawInvert(a, result, curve);
        }
    }
}
