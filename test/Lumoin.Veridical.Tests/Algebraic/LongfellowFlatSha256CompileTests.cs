using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The compile-half gates for the flat SHA-256 gadget: the kernel-compiled block circuit's telemetry
/// pinned against the reference compiler's published size statistics, and the full ZK end-to-end over
/// kernel-compiled SHA-256 block circuits in both wired fields.
/// </summary>
/// <remarks>
/// <para>
/// The telemetry pins carry the reference compiler's size statistics for
/// <c>assert_transform_block</c> (unpacked) and the all-packed pack-two shape, regenerated from the
/// pinned reference commit by running its own <c>block_size_p256</c>/<c>block_size_p256_2</c> tests
/// in the longfellow-ref Docker oracle (the figures in <c>flatsha256_circuit.h</c>'s header comment
/// are stale): depth, wire, input, output, copy-overhead, quad-term, eliminated-subexpression and
/// not-needed counts. Matching every counter pins the entire Logic-to-scheduler pipeline — gate
/// arithmetization, fold association trees, common-subexpression structure, dead-node elimination
/// and copy-wire placement — against the reference compiler without a circuit blob. The input
/// declaration order replicates the reference's <c>test_block_circuit_size</c> exactly (the message
/// words, then the interleaved initial/final state per word, then the schedule, then the
/// interleaved per-round registers).
/// </para>
/// <para>
/// The end-to-end gates prove and verify a genuine single-block statement (the padded message
/// <c>"abc"</c> under the standard initial context) through the shipped ZK prover and verifier: over
/// GF(2^128) in the all-packed pack-two shape production statements use, and over the P-256 base
/// field in the unpacked shape. Tampered proof bytes must reject and an unsatisfying witness must be
/// unprovable.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowFlatSha256CompileTests
{
    /// <summary>The number of 32-bit message words in one SHA-256 block.</summary>
    private const int InputWordCount = 16;

    /// <summary>The number of 32-bit words in the SHA-256 compression state.</summary>
    private const int StateWordCount = 8;

    /// <summary>The number of extended message schedule words in one SHA-256 block.</summary>
    private const int ScheduleWordCount = 48;

    /// <summary>The number of compression rounds in one SHA-256 block.</summary>
    private const int RoundCount = 64;

    /// <summary>The bit width of one SHA-256 word.</summary>
    private const int WordWidth = 32;

    /// <summary>
    /// The unpacked block circuit's reference depth upper bound, regenerated from the pinned
    /// reference (3dfaac7) by running <c>FlatSHA256_Circuit.block_size_p256</c> in the
    /// longfellow-ref Docker oracle; the figure in <c>flatsha256_circuit.h</c>'s header comment is
    /// stale and does not reproduce at the pinned commit even in the reference itself.
    /// </summary>
    private const int UnpackedDepth = 7;

    /// <summary>The unpacked block circuit's reference wire count, regenerated the same way as <see cref="UnpackedDepth"/>.</summary>
    private const int UnpackedWireCount = 51334;

    /// <summary>The unpacked block circuit's reference input count, regenerated the same way as <see cref="UnpackedDepth"/>.</summary>
    private const int UnpackedInputCount = 6657;

    /// <summary>The unpacked block circuit's reference output count, regenerated the same way as <see cref="UnpackedDepth"/>.</summary>
    private const int UnpackedOutputCount = 128;

    /// <summary>The unpacked block circuit's reference copy-wire overhead count, regenerated the same way as <see cref="UnpackedDepth"/>.</summary>
    private const int UnpackedCopyOverheadCount = 7020;

    /// <summary>The unpacked block circuit's reference quad-term count, regenerated the same way as <see cref="UnpackedDepth"/>.</summary>
    private const int UnpackedQuadTermCount = 187316;

    /// <summary>The unpacked block circuit's reference eliminated-subexpression count, regenerated the same way as <see cref="UnpackedDepth"/>.</summary>
    private const int UnpackedEliminatedSubexpressionCount = 11815;

    /// <summary>The unpacked block circuit's reference not-needed count, regenerated the same way as <see cref="UnpackedDepth"/>.</summary>
    private const int UnpackedNotNeededCount = 132324;

    /// <summary>
    /// The all-packed pack-two block circuit's reference depth upper bound, regenerated the same way
    /// as <see cref="UnpackedDepth"/> by running <c>FlatSHA256_Circuit.block_size_p256_2</c> in the
    /// longfellow-ref Docker oracle.
    /// </summary>
    private const int AllPackedDepth = 9;

    /// <summary>The all-packed pack-two block circuit's reference wire count, regenerated the same way as <see cref="AllPackedDepth"/>.</summary>
    private const int AllPackedWireCount = 66760;

    /// <summary>The all-packed pack-two block circuit's reference input count, regenerated the same way as <see cref="AllPackedDepth"/>.</summary>
    private const int AllPackedInputCount = 3585;

    /// <summary>The all-packed pack-two block circuit's reference output count, regenerated the same way as <see cref="AllPackedDepth"/>.</summary>
    private const int AllPackedOutputCount = 128;

    /// <summary>The all-packed pack-two block circuit's reference copy-wire overhead count, regenerated the same way as <see cref="AllPackedDepth"/>.</summary>
    private const int AllPackedCopyOverheadCount = 10147;

    /// <summary>The all-packed pack-two block circuit's reference quad-term count, regenerated the same way as <see cref="AllPackedDepth"/>.</summary>
    private const int AllPackedQuadTermCount = 217040;

    /// <summary>The all-packed pack-two block circuit's reference eliminated-subexpression count, regenerated the same way as <see cref="AllPackedDepth"/>.</summary>
    private const int AllPackedEliminatedSubexpressionCount = 30247;

    /// <summary>The all-packed pack-two block circuit's reference not-needed count, regenerated the same way as <see cref="AllPackedDepth"/>.</summary>
    private const int AllPackedNotNeededCount = 153828;

    /// <summary>
    /// The unused-but-constructed plucker log-point count in the unpacked shape, matching the
    /// reference's <c>BitPlucker&lt;Logic, 1&gt;</c> instantiation at <c>plucker_size 1</c>.
    /// </summary>
    private const int UnpackedPluckerLogPointCount = 1;

    /// <summary>The Fiat-Shamir transcript seed for the GF(2^128) end-to-end gate.</summary>
    private static byte[] GfTranscriptSeed { get; } = Encoding.ASCII.GetBytes("sha256-gf-kernel-e2e");

    /// <summary>The Fiat-Shamir transcript seed for the P-256 base field end-to-end gate.</summary>
    private static byte[] Fp256TranscriptSeed { get; } = Encoding.ASCII.GetBytes("sha256-fp256-kernel-e2e");

    /// <summary>The three-byte ASCII message <c>"abc"</c> proved and verified by the end-to-end gates.</summary>
    private static byte[] MessageBytes { get; } = Encoding.ASCII.GetBytes("abc");


    /// <summary>Pins the kernel-compiled unpacked block circuit's telemetry against the reference compiler's published size statistics.</summary>
    [TestMethod]
    public void TheUnpackedBlockCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileUnpackedBlockCircuit(NewFp256Bundle(), privateWitness: false, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(UnpackedDepth, builder.DepthUpperBound, "The unpacked block circuit's depth must match the reference compiler's.");
        Assert.AreEqual(UnpackedWireCount, builder.WireCount, "The unpacked block circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(UnpackedInputCount, builder.InputCount, "The unpacked block circuit's input count must match the reference compiler's.");
        Assert.AreEqual(UnpackedOutputCount, builder.OutputCount, "The unpacked block circuit's output count must match the reference compiler's.");
        Assert.AreEqual(UnpackedCopyOverheadCount, builder.CopyWireOverheadCount, "The unpacked block circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(UnpackedQuadTermCount, builder.QuadTermCount, "The unpacked block circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(UnpackedEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The unpacked block circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(UnpackedNotNeededCount, builder.NotNeededCount, "The unpacked block circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled all-packed pack-two block circuit's telemetry against the reference compiler's published size statistics.</summary>
    [TestMethod]
    public void TheAllPackedBlockCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileAllPackedBlockCircuit(NewFp256Bundle(), privateWitness: false, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(AllPackedDepth, builder.DepthUpperBound, "The all-packed block circuit's depth must match the reference compiler's.");
        Assert.AreEqual(AllPackedWireCount, builder.WireCount, "The all-packed block circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(AllPackedInputCount, builder.InputCount, "The all-packed block circuit's input count must match the reference compiler's.");
        Assert.AreEqual(AllPackedOutputCount, builder.OutputCount, "The all-packed block circuit's output count must match the reference compiler's.");
        Assert.AreEqual(AllPackedCopyOverheadCount, builder.CopyWireOverheadCount, "The all-packed block circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(AllPackedQuadTermCount, builder.QuadTermCount, "The all-packed block circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(AllPackedEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The all-packed block circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(AllPackedNotNeededCount, builder.NotNeededCount, "The all-packed block circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins that the kernel-compiled all-packed SHA-256 block circuit proves and verifies the padded <c>"abc"</c> statement end to end over GF(2^128), and that a tampered proof is rejected.</summary>
    [TestMethod]
    public void ThePackedBlockWitnessDeclaresItsWiresInTheReferenceOrder()
    {
        LongfellowLogicFieldOperations field = NewGfBundle();
        var builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        var witness = new LongfellowFlatSha256PackedBlockWitness();
        witness.Input(circuit);

        //On a fresh builder the constant-one input occupies wire zero and the witness declarations
        //follow consecutively, so the group start positions pin the reference's declaration order:
        //the schedule extension, then the per-round registers interleaved, then the final state.
        int elementsPerWord = plucker.PackedV32ElementCount;
        const int ConstantOneWireCount = 1;
        int scheduleStart = ConstantOneWireCount;
        int registerStart = scheduleStart + (ScheduleWordCount * elementsPerWord);
        int finalStateStart = registerStart + (2 * RoundCount * elementsPerWord);

        Assert.AreEqual(scheduleStart, witness.ScheduleExtension[0][0], "The schedule extension must be declared first.");
        Assert.AreEqual(registerStart, witness.RegisterEWitness[0][0], "Register e of round zero must follow the schedule extension.");
        Assert.AreEqual(registerStart + elementsPerWord, witness.RegisterAWitness[0][0], "Register a of round zero must interleave directly after register e.");
        Assert.AreEqual(finalStateStart, witness.FinalState[0][0], "The final state must follow the interleaved registers.");
        Assert.AreEqual(finalStateStart + (StateWordCount * elementsPerWord), builder.InputCount, "The declaration must cover exactly the packed block witness's wires.");
    }


    [TestMethod]
    public void TheGfShaBlockCircuitProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewGfBundle();
        LongfellowSumcheckCircuit circuit = CompileAllPackedBlockCircuit(field, privateWitness: true, out _);
        byte[] witnessColumn = BuildAllPackedWitnessColumn(field, circuit.InputCount);

        using LongfellowZkProofEnvelope proof = ProduceGfProof(circuit, witnessColumn, GfTranscriptSeed);
        byte[] publicInputs = GfPublicInputBytes(circuit, witnessColumn);
        AssertGfVerifies(circuit, proof.Bytes, publicInputs, GfTranscriptSeed, expectedAccept: true);

        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[^1] ^= 0x01;
        AssertGfVerifies(circuit, tamperedProof, publicInputs, GfTranscriptSeed, expectedAccept: false);
    }


    /// <summary>Pins that flipping a bit of the final-state witness breaks the compression recurrence and makes the GF(2^128) SHA-256 block circuit unprovable.</summary>
    [TestMethod]
    public void AnUnsatisfyingWitnessIsUnprovableOverTheGfShaBlockCircuit()
    {
        LongfellowLogicFieldOperations field = NewGfBundle();
        LongfellowSumcheckCircuit circuit = CompileAllPackedBlockCircuit(field, privateWitness: true, out _);
        byte[] witnessColumn = BuildAllPackedWitnessColumn(field, circuit.InputCount);

        //Re-encode the first packed element of the final state's first word from a flipped value:
        //the compression recurrence no longer holds and the prover must refuse.
        var encoder = new LongfellowBitPluckerEncoder(field, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        ComputeBlockWitness(out _, out LongfellowFlatSha256BlockWitness blockWitness);
        int finalStateFirstElementWire = 1 + (InputWordCount * WordWidth) + (StateWordCount * encoder.PackedV32ElementCount);
        encoder.MakePackedV32(blockWitness.FinalState[0] ^ 1U)[0].Span.CopyTo(witnessColumn.AsSpan(finalStateFirstElementWire * ScalarSize, ScalarSize));

        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProduceGfProof(circuit, witnessColumn, GfTranscriptSeed),
            "An unsatisfying SHA-256 witness must be unprovable.");
    }


    /// <summary>Pins that the kernel-compiled unpacked SHA-256 block circuit proves and verifies the padded <c>"abc"</c> statement end to end over the P-256 base field, and that a tampered proof is rejected.</summary>
    [TestMethod]
    public void TheFp256ShaBlockCircuitProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        LongfellowSumcheckCircuit circuit = CompileUnpackedBlockCircuit(field, privateWitness: true, out _);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, Production16SubFieldBytes);

        byte[] witnessColumn = BuildUnpackedWitnessColumn(circuit.InputCount);

        using LongfellowZkProofEnvelope proof = ProduceFp256Proof(circuit, parameters, witnessColumn, Fp256TranscriptSeed);
        byte[] publicInputs = Fp256PublicInputBytes(circuit, witnessColumn);
        AssertFp256Verifies(circuit, parameters, proof.Bytes, publicInputs, Fp256TranscriptSeed, expectedAccept: true);

        //A flipped byte inside the sumcheck segment diverges the challenge stream.
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[DigestSize + 8] ^= 0x01;
        AssertFp256Verifies(circuit, parameters, tamperedProof, publicInputs, Fp256TranscriptSeed, expectedAccept: false);
    }


    /// <summary>
    /// Compiles the reference's unpacked <c>test_block_circuit_size</c> shape: the message words,
    /// then the interleaved initial/final state per word, then the schedule, then the interleaved
    /// per-round registers, all as bit inputs. The private split (used by the end-to-end gates)
    /// declares everything after the message words as private witness; the telemetry gates keep
    /// every input public, matching the reference's all-public shape.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="privateWitness">Whether the witness inputs after the message words are declared private.</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileUnpackedBlockCircuit(LongfellowLogicFieldOperations field, bool privateWitness, out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var plucker = new LongfellowBitPlucker(logic, UnpackedPluckerLogPointCount);
        var sha = new LongfellowFlatSha256Circuit(logic, plucker);

        var blockWords = new LongfellowBitWire[InputWordCount][];
        for(int i = 0; i < InputWordCount; i++)
        {
            blockWords[i] = logic.InputVector(WordWidth);
        }

        if(privateWitness)
        {
            builder.PrivateInput();
        }

        var initialState = new LongfellowBitWire[StateWordCount][];
        var finalState = new LongfellowBitWire[StateWordCount][];
        for(int i = 0; i < StateWordCount; i++)
        {
            initialState[i] = logic.InputVector(WordWidth);
            finalState[i] = logic.InputVector(WordWidth);
        }

        var scheduleExtension = new LongfellowBitWire[ScheduleWordCount][];
        for(int i = 0; i < ScheduleWordCount; i++)
        {
            scheduleExtension[i] = logic.InputVector(WordWidth);
        }

        var registerEWitness = new LongfellowBitWire[RoundCount][];
        var registerAWitness = new LongfellowBitWire[RoundCount][];
        for(int i = 0; i < RoundCount; i++)
        {
            registerEWitness[i] = logic.InputVector(WordWidth);
            registerAWitness[i] = logic.InputVector(WordWidth);
        }

        sha.AssertTransformBlock(blockWords, initialState, scheduleExtension, registerEWitness, registerAWitness, finalState);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Compiles the reference's all-packed <c>test_block_circuit_size</c> shape at pack size two: the
    /// message words as bits, then every state, schedule and register word as packed inputs in the
    /// reference's interleaved order.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="privateWitness">Whether the witness inputs after the message words are declared private.</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileAllPackedBlockCircuit(LongfellowLogicFieldOperations field, bool privateWitness, out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var sha = new LongfellowFlatSha256Circuit(logic, plucker);

        var blockWords = new LongfellowBitWire[InputWordCount][];
        for(int i = 0; i < InputWordCount; i++)
        {
            blockWords[i] = logic.InputVector(WordWidth);
        }

        if(privateWitness)
        {
            builder.PrivateInput();
        }

        var packedInitialState = new int[StateWordCount][];
        var packedFinalState = new int[StateWordCount][];
        for(int i = 0; i < StateWordCount; i++)
        {
            packedInitialState[i] = sha.PackedInputV32();
            packedFinalState[i] = sha.PackedInputV32();
        }

        var packedSchedule = new int[ScheduleWordCount][];
        for(int i = 0; i < ScheduleWordCount; i++)
        {
            packedSchedule[i] = sha.PackedInputV32();
        }

        var packedRegisterE = new int[RoundCount][];
        var packedRegisterA = new int[RoundCount][];
        for(int i = 0; i < RoundCount; i++)
        {
            packedRegisterE[i] = sha.PackedInputV32();
            packedRegisterA[i] = sha.PackedInputV32();
        }

        sha.AssertTransformBlock(blockWords, packedInitialState, packedSchedule, packedRegisterE, packedRegisterA, packedFinalState);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Computes the single-block witness for the <c>"abc"</c> statement: the padded block's words
    /// plus the reference witness generator's intermediate values under the standard initial context.
    /// </summary>
    /// <param name="blockWords">Receives the padded message block's 32-bit words.</param>
    /// <param name="blockWitness">Receives the reference witness generator's intermediate values.</param>
    private static void ComputeBlockWitness(out uint[] blockWords, out LongfellowFlatSha256BlockWitness blockWitness)
    {
        const int SingleBlock = 1;
        const int BytesPerBlock = 64;
        const int BytesPerWord = 4;

        Span<byte> padded = stackalloc byte[BytesPerBlock];
        var witnesses = new LongfellowFlatSha256BlockWitness[SingleBlock];
        LongfellowFlatSha256Witness.TransformAndWitnessMessage(MessageBytes, SingleBlock, out byte occupiedBlockCount, padded, witnesses);
        Assert.AreEqual((byte)SingleBlock, occupiedBlockCount, "The three-byte message must occupy exactly one block.");

        blockWords = new uint[InputWordCount];
        for(int i = 0; i < InputWordCount; i++)
        {
            blockWords[i] = LongfellowFlatSha256Witness.ReadUInt32BigEndian(padded.Slice(i * BytesPerWord, BytesPerWord));
        }

        blockWitness = witnesses[0];

        //Independent oracle: the block's final state must be the message's SHA-256 hash.
        byte[] expectedHash = SHA256.HashData(MessageBytes);
        for(int i = 0; i < StateWordCount; i++)
        {
            Assert.AreEqual(LongfellowFlatSha256Witness.ReadUInt32BigEndian(expectedHash.AsSpan(i * BytesPerWord, BytesPerWord)), blockWitness.FinalState[i], $"Final state word {i} must match the platform SHA-256.");
        }
    }


    /// <summary>
    /// Builds the all-packed witness column: the constant one, the message word bits, then every
    /// packed word in declaration order (interleaved initial/final state, schedule, interleaved
    /// registers).
    /// </summary>
    /// <param name="field">The field bundle the packed encoder must match.</param>
    /// <param name="inputCount">The compiled circuit's declared input count.</param>
    /// <returns>The witness column, one canonical scalar per declared input wire.</returns>
    private static byte[] BuildAllPackedWitnessColumn(LongfellowLogicFieldOperations field, int inputCount)
    {
        ComputeBlockWitness(out uint[] blockWords, out LongfellowFlatSha256BlockWitness blockWitness);
        var encoder = new LongfellowBitPluckerEncoder(field, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);

        byte[] column = new byte[inputCount * ScalarSize];
        column[ScalarSize - 1] = 0x01;
        int wire = 1;

        foreach(uint word in blockWords)
        {
            WriteWordBits(column, ref wire, word);
        }

        for(int i = 0; i < StateWordCount; i++)
        {
            WritePackedWord(column, ref wire, encoder, LongfellowSha256Constants.InitialHash[i]);
            WritePackedWord(column, ref wire, encoder, blockWitness.FinalState[i]);
        }

        for(int i = 0; i < ScheduleWordCount; i++)
        {
            WritePackedWord(column, ref wire, encoder, blockWitness.ScheduleExtension[i]);
        }

        for(int i = 0; i < RoundCount; i++)
        {
            WritePackedWord(column, ref wire, encoder, blockWitness.RegisterEWitness[i]);
            WritePackedWord(column, ref wire, encoder, blockWitness.RegisterAWitness[i]);
        }

        Assert.AreEqual(inputCount, wire, "The packed column layout must cover exactly the declared input wires.");

        return column;
    }


    /// <summary>Builds the unpacked witness column: the constant one, then every word as raw bits in declaration order.</summary>
    /// <param name="inputCount">The compiled circuit's declared input count.</param>
    /// <returns>The witness column, one canonical scalar per declared input wire.</returns>
    private static byte[] BuildUnpackedWitnessColumn(int inputCount)
    {
        ComputeBlockWitness(out uint[] blockWords, out LongfellowFlatSha256BlockWitness blockWitness);

        byte[] column = new byte[inputCount * ScalarSize];
        column[ScalarSize - 1] = 0x01;
        int wire = 1;

        foreach(uint word in blockWords)
        {
            WriteWordBits(column, ref wire, word);
        }

        for(int i = 0; i < StateWordCount; i++)
        {
            WriteWordBits(column, ref wire, LongfellowSha256Constants.InitialHash[i]);
            WriteWordBits(column, ref wire, blockWitness.FinalState[i]);
        }

        for(int i = 0; i < ScheduleWordCount; i++)
        {
            WriteWordBits(column, ref wire, blockWitness.ScheduleExtension[i]);
        }

        for(int i = 0; i < RoundCount; i++)
        {
            WriteWordBits(column, ref wire, blockWitness.RegisterEWitness[i]);
            WriteWordBits(column, ref wire, blockWitness.RegisterAWitness[i]);
        }

        Assert.AreEqual(inputCount, wire, "The unpacked column layout must cover exactly the declared input wires.");

        return column;
    }


    /// <summary>Writes one 32-bit word's bits into the witness column, least significant bit first, advancing the wire cursor.</summary>
    /// <param name="column">The witness column being filled.</param>
    /// <param name="wire">The wire cursor; advanced by <see cref="WordWidth"/>.</param>
    /// <param name="word">The word whose bits are written.</param>
    private static void WriteWordBits(byte[] column, ref int wire, uint word)
    {
        for(int bit = 0; bit < WordWidth; bit++, wire++)
        {
            column[(wire * ScalarSize) + ScalarSize - 1] = (byte)((word >> bit) & 1U);
        }
    }


    /// <summary>Encodes one word through the bit-plucker encoder and writes its packed elements into the witness column, advancing the wire cursor.</summary>
    /// <param name="column">The witness column being filled.</param>
    /// <param name="wire">The wire cursor; advanced by the encoder's packed element count.</param>
    /// <param name="encoder">The bit-plucker encoder producing the packed elements.</param>
    /// <param name="word">The word to encode.</param>
    private static void WritePackedWord(byte[] column, ref int wire, LongfellowBitPluckerEncoder encoder, uint word)
    {
        ReadOnlyMemory<byte>[] packed = encoder.MakePackedV32(word);
        foreach(ReadOnlyMemory<byte> element in packed)
        {
            element.Span.CopyTo(column.AsSpan(wire * ScalarSize, ScalarSize));
            wire++;
        }
    }
}
