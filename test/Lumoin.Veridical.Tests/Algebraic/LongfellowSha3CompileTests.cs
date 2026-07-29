using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Buffers;
using System.Collections.Generic;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The compile-half gates for the SHA-3 stack: the kernel-compiled Keccak-f[1600] permutation
/// (witness-free and witnessed) and the SHAKE256 assertion circuit pinned counter for counter
/// against the reference compiler over the sextic extension of the FIPS 204 prime and over
/// GF(2^128), and the ZK end-to-ends over the GF(2^128) and sextic SHAKE256 statements through
/// the shipped stack.
/// </summary>
/// <remarks>
/// <para>
/// Every pinned figure was regenerated from the pinned reference commit by running its own gtests
/// (<c>SHA3_Circuit.*</c>) in the longfellow-ref Docker oracle. The GF(2^128) SHAKE row carries
/// the characteristic-two shape — linear XOR collapses the wires and depth while the quad-term
/// count balloons — and the sextic-extension rows carry the odd-prime shape, so the pair pins
/// both assertion-split branches of the gadget.
/// </para>
/// <para>
/// The sextic-extension rows are compile-pinned here and vector-checked in evaluation
/// (<c>LongfellowSha3CircuitTests</c>). Both ZK end-to-ends below run on the shipped stack: the
/// GF(2^128) statement covers the compiled sponge's proof-system behavior on the
/// characteristic-two branch, and the sextic statement covers the odd-prime branch through the
/// <c>LongfellowFp24SexticEncoding</c> profile (the reference's <c>ReedSolomonExtensionFactory</c>
/// analogue).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowSha3CompileTests
{
    /// <summary>The field element width in bytes used for every witness column entry.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>One lane's bit width.</summary>
    private const int LaneBits = 64;

    /// <summary>The GF(2^128) subfield width selecting the four-way assertion split.</summary>
    private const int GfSubfieldBits = 16;

    /// <summary>The sextic extension's subfield width (the base field's bit count), selecting the three-way assertion split.</summary>
    private const int SexticSubfieldBits = 32;

    /// <summary>The reference's <c>CircuitSizeShake256</c> seed length in bytes.</summary>
    private const int PinnedSeedLength = 32;

    /// <summary>The reference's <c>CircuitSizeShake256</c> output length in bytes.</summary>
    private const int PinnedOutputLength = 64;

    /// <summary>The reference's ZK round-trip seed length (vector 1's <c>abc</c>).</summary>
    private const int ZkSeedLength = 3;

    /// <summary>The reference's ZK round-trip output length.</summary>
    private const int ZkOutputLength = 33;

    /// <summary>The witness-free Keccak circuit's reference depth upper bound (Docker oracle, <c>SHA3_Circuit</c>, Fp24_6).</summary>
    private const int KeccakDepth = 145;

    /// <summary>The witness-free Keccak circuit's reference wire count.</summary>
    private const int KeccakWireCount = 312144;

    /// <summary>The witness-free Keccak circuit's reference input count.</summary>
    private const int KeccakInputCount = 1601;

    /// <summary>The witness-free Keccak circuit's reference output count.</summary>
    private const int KeccakOutputCount = 1600;

    /// <summary>The witness-free Keccak circuit's reference copy-wire overhead count.</summary>
    private const int KeccakCopyOverheadCount = 115343;

    /// <summary>The witness-free Keccak circuit's reference quad-term count.</summary>
    private const int KeccakQuadTermCount = 471823;

    /// <summary>The witness-free Keccak circuit's reference eliminated-subexpression count.</summary>
    private const int KeccakEliminatedSubexpressionCount = 0;

    /// <summary>The witness-free Keccak circuit's reference not-needed count.</summary>
    private const int KeccakNotNeededCount = 283204;

    /// <summary>The witnessed Keccak circuit's reference depth upper bound.</summary>
    private const int WitnessedKeccakDepth = 38;

    /// <summary>The witnessed Keccak circuit's reference wire count.</summary>
    private const int WitnessedKeccakWireCount = 401537;

    /// <summary>The witnessed Keccak circuit's reference input count.</summary>
    private const int WitnessedKeccakInputCount = 8001;

    /// <summary>The witnessed Keccak circuit's reference output count.</summary>
    private const int WitnessedKeccakOutputCount = 1900;

    /// <summary>The witnessed Keccak circuit's reference copy-wire overhead count.</summary>
    private const int WitnessedKeccakCopyOverheadCount = 184936;

    /// <summary>The witnessed Keccak circuit's reference quad-term count.</summary>
    private const int WitnessedKeccakQuadTermCount = 591956;

    /// <summary>The witnessed Keccak circuit's reference eliminated-subexpression count.</summary>
    private const int WitnessedKeccakEliminatedSubexpressionCount = 599;

    /// <summary>The witnessed Keccak circuit's reference not-needed count.</summary>
    private const int WitnessedKeccakNotNeededCount = 356505;

    /// <summary>The sextic-extension SHAKE circuit's reference depth upper bound (<c>CircuitSizeShake256</c>).</summary>
    private const int ShakeDepth = 38;

    /// <summary>The sextic-extension SHAKE circuit's reference wire count.</summary>
    private const int ShakeWireCount = 334070;

    /// <summary>The sextic-extension SHAKE circuit's reference input count.</summary>
    private const int ShakeInputCount = 7169;

    /// <summary>The sextic-extension SHAKE circuit's reference output count.</summary>
    private const int ShakeOutputCount = 225;

    /// <summary>The sextic-extension SHAKE circuit's reference copy-wire overhead count.</summary>
    private const int ShakeCopyOverheadCount = 123218;

    /// <summary>The sextic-extension SHAKE circuit's reference quad-term count.</summary>
    private const int ShakeQuadTermCount = 522121;

    /// <summary>The sextic-extension SHAKE circuit's reference eliminated-subexpression count.</summary>
    private const int ShakeEliminatedSubexpressionCount = 599;

    /// <summary>The sextic-extension SHAKE circuit's reference not-needed count.</summary>
    private const int ShakeNotNeededCount = 349893;

    /// <summary>The GF(2^128) SHAKE circuit's reference depth upper bound (<c>ZkProverAndVerifierTest_GF2_128</c>'s shape).</summary>
    private const int GfShakeDepth = 9;

    /// <summary>The GF(2^128) SHAKE circuit's reference wire count.</summary>
    private const int GfShakeWireCount = 66231;

    /// <summary>The GF(2^128) SHAKE circuit's reference input count.</summary>
    private const int GfShakeInputCount = 6689;

    /// <summary>The GF(2^128) SHAKE circuit's reference output count.</summary>
    private const int GfShakeOutputCount = 300;

    /// <summary>The GF(2^128) SHAKE circuit's reference copy-wire overhead count.</summary>
    private const int GfShakeCopyOverheadCount = 2325;

    /// <summary>The GF(2^128) SHAKE circuit's reference quad-term count.</summary>
    private const int GfShakeQuadTermCount = 1115093;

    /// <summary>The GF(2^128) SHAKE circuit's reference eliminated-subexpression count.</summary>
    private const int GfShakeEliminatedSubexpressionCount = 1542;

    /// <summary>The GF(2^128) SHAKE circuit's reference not-needed count.</summary>
    private const int GfShakeNotNeededCount = 249289;

    /// <summary>The Fiat-Shamir transcript seed for the GF(2^128) end-to-end gate.</summary>
    private static byte[] GfShakeTranscriptSeed { get; } = System.Text.Encoding.ASCII.GetBytes("sha3-shake-gf-e2e");

    /// <summary>The sextic SHAKE end-to-end gate's Fiat-Shamir seed.</summary>
    private static byte[] SexticShakeTranscriptSeed { get; } = System.Text.Encoding.ASCII.GetBytes("sha3-shake-sextic-e2e");


    /// <summary>Pins the kernel-compiled witness-free Keccak-f[1600] circuit's telemetry against the reference compiler's, over the sextic extension.</summary>
    [TestMethod]
    public void TheKeccakCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileKeccakCircuit(NewFp24SexticBundle(), witnessed: false, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(KeccakDepth, builder.DepthUpperBound, "The Keccak circuit's depth must match the reference compiler's.");
        Assert.AreEqual(KeccakWireCount, builder.WireCount, "The Keccak circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(KeccakInputCount, builder.InputCount, "The Keccak circuit's input count must match the reference compiler's.");
        Assert.AreEqual(KeccakOutputCount, builder.OutputCount, "The Keccak circuit's output count must match the reference compiler's.");
        Assert.AreEqual(KeccakCopyOverheadCount, builder.CopyWireOverheadCount, "The Keccak circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(KeccakQuadTermCount, builder.QuadTermCount, "The Keccak circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(KeccakEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The Keccak circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(KeccakNotNeededCount, builder.NotNeededCount, "The Keccak circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled witnessed Keccak-f[1600] circuit's telemetry against the reference compiler's, over the sextic extension.</summary>
    [TestMethod]
    public void TheWitnessedKeccakCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileKeccakCircuit(NewFp24SexticBundle(), witnessed: true, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(WitnessedKeccakDepth, builder.DepthUpperBound, "The witnessed Keccak circuit's depth must match the reference compiler's.");
        Assert.AreEqual(WitnessedKeccakWireCount, builder.WireCount, "The witnessed Keccak circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(WitnessedKeccakInputCount, builder.InputCount, "The witnessed Keccak circuit's input count must match the reference compiler's.");
        Assert.AreEqual(WitnessedKeccakOutputCount, builder.OutputCount, "The witnessed Keccak circuit's output count must match the reference compiler's.");
        Assert.AreEqual(WitnessedKeccakCopyOverheadCount, builder.CopyWireOverheadCount, "The witnessed Keccak circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(WitnessedKeccakQuadTermCount, builder.QuadTermCount, "The witnessed Keccak circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(WitnessedKeccakEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The witnessed Keccak circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(WitnessedKeccakNotNeededCount, builder.NotNeededCount, "The witnessed Keccak circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled SHAKE256 assertion circuit's telemetry against the reference compiler's, over the sextic extension at the reference's 32-byte-seed shape.</summary>
    [TestMethod]
    public void TheShakeCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileShakeCircuit(NewFp24SexticBundle(), SexticSubfieldBits, PinnedSeedLength, PinnedOutputLength, privateWitness: false, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(ShakeDepth, builder.DepthUpperBound, "The SHAKE circuit's depth must match the reference compiler's.");
        Assert.AreEqual(ShakeWireCount, builder.WireCount, "The SHAKE circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(ShakeInputCount, builder.InputCount, "The SHAKE circuit's input count must match the reference compiler's.");
        Assert.AreEqual(ShakeOutputCount, builder.OutputCount, "The SHAKE circuit's output count must match the reference compiler's.");
        Assert.AreEqual(ShakeCopyOverheadCount, builder.CopyWireOverheadCount, "The SHAKE circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(ShakeQuadTermCount, builder.QuadTermCount, "The SHAKE circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(ShakeEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The SHAKE circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(ShakeNotNeededCount, builder.NotNeededCount, "The SHAKE circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled SHAKE256 assertion circuit's telemetry against the reference compiler's, over GF(2^128) at the reference's ZK round-trip shape.</summary>
    [TestMethod]
    public void TheGfShakeCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileShakeCircuit(NewGfBundle(), GfSubfieldBits, ZkSeedLength, ZkOutputLength, privateWitness: false, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(GfShakeDepth, builder.DepthUpperBound, "The GF SHAKE circuit's depth must match the reference compiler's.");
        Assert.AreEqual(GfShakeWireCount, builder.WireCount, "The GF SHAKE circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(GfShakeInputCount, builder.InputCount, "The GF SHAKE circuit's input count must match the reference compiler's.");
        Assert.AreEqual(GfShakeOutputCount, builder.OutputCount, "The GF SHAKE circuit's output count must match the reference compiler's.");
        Assert.AreEqual(GfShakeCopyOverheadCount, builder.CopyWireOverheadCount, "The GF SHAKE circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(GfShakeQuadTermCount, builder.QuadTermCount, "The GF SHAKE circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(GfShakeEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The GF SHAKE circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(GfShakeNotNeededCount, builder.NotNeededCount, "The GF SHAKE circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins that the kernel-compiled GF(2^128) SHAKE256 statement proves and verifies the reference's <c>abc</c> vector end to end through the shipped stack, that a tampered proof rejects, and that a flipped witness bit is unprovable.</summary>
    [TestMethod]
    public void TheGfShakeStatementProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewGfBundle();
        LongfellowSumcheckCircuit circuit = CompileShakeCircuit(field, GfSubfieldBits, ZkSeedLength, ZkOutputLength, privateWitness: true, out _);

        int columnBytes = circuit.InputCount * ScalarSize;
        using IMemoryOwner<byte> witnessOwner = BuildShakeWitnessColumn(field, circuit, out int witnessStartWire);
        Span<byte> witnessColumn = witnessOwner.Memory.Span[..columnBytes];

        using LongfellowZkProofEnvelope proof = ProduceGfProof(circuit, witnessColumn, GfShakeTranscriptSeed);
        byte[] publicInputs = GfPublicInputBytes(circuit, witnessColumn);
        AssertGfVerifies(circuit, proof.Bytes, publicInputs, GfShakeTranscriptSeed, expectedAccept: true);

        using IMemoryOwner<byte> tamperedOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[^1] ^= 0x01;
        AssertGfVerifies(circuit, tamperedProof, publicInputs, GfShakeTranscriptSeed, expectedAccept: false);

        //Flipping the first witnessed lane bit in place breaks the round-five re-anchoring assertion;
        //the accepting proof and the public inputs were already derived, so the column is free to mutate.
        Span<byte> witnessElement = witnessColumn.Slice(witnessStartWire * ScalarSize, ScalarSize);
        ReadOnlyMemory<byte> flipped = LongfellowCompilerFieldOperations.ElementIsZero(witnessElement) ? field.Compiler.One : field.Compiler.Zero;
        flipped.Span.CopyTo(witnessElement);
        Memory<byte> corrupted = witnessOwner.Memory[..columnBytes];
        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProduceGfProof(circuit, corrupted.Span, GfShakeTranscriptSeed),
            "A flipped SHAKE witness bit must be unprovable.");
        witnessColumn.Clear();
    }


    /// <summary>
    /// Pins that the kernel-compiled SHAKE256 statement over the FIPS 204 sextic circuit field proves
    /// and verifies the reference's <c>abc</c> vector end to end through the shipped stack — the
    /// sextic analogue of the reference's <c>ZkProverAndVerifierTest_Fp24_6</c>, run at the harness's
    /// shared test shape (the reference test uses its rate-7/132-column harness constants; the code
    /// path is identical) — that a tampered proof rejects, and that a flipped witness bit is
    /// unprovable.
    /// </summary>
    [TestMethod]
    public void TheSexticShakeStatementProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        LongfellowSumcheckCircuit circuit = CompileShakeCircuit(field, SexticSubfieldBits, ZkSeedLength, ZkOutputLength, privateWitness: true, out _);

        int columnBytes = circuit.InputCount * ScalarSize;
        using IMemoryOwner<byte> witnessOwner = BuildShakeWitnessColumn(field, circuit, out int witnessStartWire);
        Span<byte> witnessColumn = witnessOwner.Memory.Span[..columnBytes];

        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp24SexticElementBytes, Fp24SexticSubFieldBytes);
        using LongfellowZkProofEnvelope proof = ProduceFp24SexticProof(circuit, parameters, witnessColumn, SexticShakeTranscriptSeed);

        int publicInputBytes = circuit.PublicInputCount * Fp24SexticElementBytes;
        using IMemoryOwner<byte> publicOwner = BaseMemoryPool.Shared.Rent(publicInputBytes);
        Span<byte> publicInputs = publicOwner.Memory.Span[..publicInputBytes];
        FillFp24SexticPublicInputs(circuit, witnessColumn, publicInputs);
        AssertFp24SexticVerifies(circuit, parameters, proof.Bytes, publicInputs, SexticShakeTranscriptSeed, expectedAccept: true);

        using IMemoryOwner<byte> tamperedOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[^1] ^= 0x01;
        AssertFp24SexticVerifies(circuit, parameters, tamperedProof, publicInputs, SexticShakeTranscriptSeed, expectedAccept: false);

        //A corrupted first opened-columns run length drives the sextic run-length reader's
        //untrusted-length guard: the parse must fail gracefully, never over-read.
        proof.Bytes.CopyTo(tamperedProof);
        TamperFirstOpenedColumnsRunLength(circuit, parameters, tamperedProof);
        AssertFp24SexticVerifies(circuit, parameters, tamperedProof, publicInputs, SexticShakeTranscriptSeed, expectedAccept: false);

        //Flipping the first witnessed lane bit in place breaks the round-five re-anchoring assertion;
        //the accepting proof and the public inputs were already derived, so the column is free to mutate.
        Span<byte> witnessElement = witnessColumn.Slice(witnessStartWire * ScalarSize, ScalarSize);
        ReadOnlyMemory<byte> flipped = LongfellowCompilerFieldOperations.ElementIsZero(witnessElement) ? field.Compiler.One : field.Compiler.Zero;
        flipped.Span.CopyTo(witnessElement);
        Memory<byte> corrupted = witnessOwner.Memory[..columnBytes];
        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProduceFp24SexticProof(circuit, parameters, corrupted.Span, SexticShakeTranscriptSeed),
            "A flipped SHAKE witness bit must be unprovable over the sextic field.");
        witnessColumn.Clear();
    }


    /// <summary>
    /// Compiles the reference's <c>mk_keccak_circuit</c>/<c>mk_keccak_witness_circuit</c> shape:
    /// the 25 lane inputs, optionally the sliced-round witness declaration, the permutation, and
    /// the lane outputs at the reference's offsets.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="witnessed">Whether the witnessed permutation is compiled.</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileKeccakCircuit(LongfellowLogicFieldOperations field, bool witnessed, out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowSha3Circuit(logic, SexticSubfieldBits);

        var state = new LongfellowBitWire[GridSize][][];
        for(int x = 0; x < GridSize; x++)
        {
            state[x] = new LongfellowBitWire[GridSize][];
            for(int y = 0; y < GridSize; y++)
            {
                state[x][y] = logic.InputVector(LaneBits);
            }
        }

        if(witnessed)
        {
            var blockWitness = new LongfellowSha3BlockWitnessWires();
            blockWitness.Input(logic);
            circuit.KeccakF1600(state, blockWitness);
        }
        else
        {
            circuit.KeccakF1600(state);
        }

        for(int x = 0; x < GridSize; x++)
        {
            for(int y = 0; y < GridSize; y++)
            {
                logic.OutputVector(state[x][y], LaneBits * (y + (GridSize * x)));
            }
        }

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Compiles the reference's <c>make_shake256_circuit</c> shape: the seed and expected-output
    /// bytes as inputs, one block-witness declaration, the SHAKE256 assertion, and the per-byte
    /// equality of the squeezed output against the expectation.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="subfieldBits">The field's subfield width for the re-anchoring assertion split.</param>
    /// <param name="seedLength">The seed length in bytes.</param>
    /// <param name="outputLength">The output length in bytes.</param>
    /// <param name="privateWitness">Whether the block witness is declared private (the end-to-end gates) or public (the reference's all-public telemetry shape).</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileShakeCircuit(
        LongfellowLogicFieldOperations field,
        int subfieldBits,
        int seedLength,
        int outputLength,
        bool privateWitness,
        out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowSha3Circuit(logic, subfieldBits);

        var seed = new LongfellowBitWire[seedLength][];
        for(int i = 0; i < seedLength; i++)
        {
            seed[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }

        var want = new LongfellowBitWire[outputLength][];
        for(int i = 0; i < outputLength; i++)
        {
            want[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }

        if(privateWitness)
        {
            builder.PrivateInput();
        }

        var blockWitnesses = new LongfellowSha3BlockWitnessWires[1];
        blockWitnesses[0] = new LongfellowSha3BlockWitnessWires();
        blockWitnesses[0].Input(logic);

        LongfellowBitWire[][] output = circuit.AssertShake256(seed, outputLength, blockWitnesses);

        Assert.HasCount(outputLength, output, "The squeezed output must cover the requested length.");
        for(int i = 0; i < outputLength; i++)
        {
            logic.AssertEqual(want[i], output[i]);
        }

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Builds the GF(2^128) SHAKE statement's witness column for the reference's <c>abc</c>
    /// vector: the constant one, the public seed and expectation bits, then the private
    /// sliced-round witness lanes.
    /// </summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="circuit">The compiled circuit declaring the input count.</param>
    /// <param name="witnessStartWire">Receives the witness region's first wire, for the unprovability probe.</param>
    /// <returns>The pooled witness column, one canonical scalar per declared input wire; the caller disposes it.</returns>
    private static IMemoryOwner<byte> BuildShakeWitnessColumn(LongfellowLogicFieldOperations field, LongfellowSumcheckCircuit circuit, out int witnessStartWire)
    {
        LongfellowSha3TestVectors.ShakeVector vector = LongfellowSha3TestVectors.Shake256Vectors[1];
        byte[] seed = Convert.FromHexString(vector.Input);
        byte[] want = Convert.FromHexString(vector.Output);
        Assert.HasCount(ZkSeedLength, seed, "The ZK vector's seed must be the reference's three bytes.");
        Assert.HasCount(ZkOutputLength, want, "The ZK vector's output must be the reference's 33 bytes.");

        IMemoryOwner<byte> columnOwner = BaseMemoryPool.Shared.Rent(circuit.InputCount * ScalarSize);
        Span<byte> column = columnOwner.Memory.Span[..(circuit.InputCount * ScalarSize)];
        column.Clear();
        field.Compiler.One.Span.CopyTo(column[..ScalarSize]);
        int cursor = 1;
        WriteByteBits(field, column, ref cursor, seed);
        WriteByteBits(field, column, ref cursor, want);

        witnessStartWire = cursor;
        IReadOnlyList<LongfellowSha3BlockWitness> witnesses = LongfellowSha3Witness.ComputeWitnessShake256(seed, want.Length);
        LongfellowSha3Witness.FillWitness(field, witnesses, column, ref cursor);
        Assert.AreEqual(circuit.InputCount, cursor, "The column layout must cover exactly the declared input wires.");

        return columnOwner;
    }


    /// <summary>Writes bytes into the column as bit elements, least significant first.</summary>
    /// <param name="field">The field bundle supplying the bit elements.</param>
    /// <param name="column">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="bytes">The bytes to write.</param>
    private static void WriteByteBits(LongfellowLogicFieldOperations field, Span<byte> column, ref int cursor, ReadOnlySpan<byte> bytes)
    {
        for(int i = 0; i < bytes.Length; i++)
        {
            for(int bit = 0; bit < LongfellowLogic.BitWidth8; bit++)
            {
                ReadOnlyMemory<byte> element = ((bytes[i] >> bit) & 1) != 0 ? field.Compiler.One : field.Compiler.Zero;
                element.Span.CopyTo(column.Slice(cursor * ScalarSize, ScalarSize));
                cursor++;
            }
        }
    }


}
