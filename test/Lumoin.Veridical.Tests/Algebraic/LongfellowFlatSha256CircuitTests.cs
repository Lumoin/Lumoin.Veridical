using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the flattened SHA-256 gadget (<see cref="LongfellowFlatSha256Circuit"/>) and its
/// witness generator (<see cref="LongfellowFlatSha256Witness"/>), the evaluation-half port of
/// google/longfellow-zk's <c>flatsha256_circuit_test.cc</c>: the plain-<see cref="uint"/> block
/// transform against the reference's <c>kSha_bt_</c> vectors (<c>sha256_test_values.h</c>), the
/// unpacked and all-packed <c>assert_transform_block</c> evaluation tests (<c>p256_assert_block</c>,
/// <c>assert_block_packed</c>), a reduced <c>assert_message</c>/<c>assert_message_hash</c> and
/// <c>find_len</c> over a single message, plus one independent oracle the reference itself has no
/// equivalent for: <see cref="LongfellowFlatSha256Witness.TransformAndWitnessMessage"/> checked
/// against <see cref="SHA256.HashData(ReadOnlySpan{byte})"/> across the SHA-256 padding boundary
/// lengths.
/// </summary>
/// <remarks>
/// <para>
/// This file covers only the reference's evaluation-backend tests. The reference's compiler-backend
/// tests (<c>test_block_circuit_size</c>, <c>block_size_p256*</c>, <c>block_size_gf2_128*</c>) drive
/// <c>QuadCircuit</c>/<c>CompilerBackend</c> to measure compiled circuit size and are out of scope
/// here, as is the benchmark section — neither exercises the witness generator or the evaluation
/// backend this file gates.
/// </para>
/// <para>
/// <c>kSha_bt_</c>'s three vectors are transcribed verbatim from <c>sha256_test_values.h</c>, no
/// reduction. The message-length sweep is new: it replaces the reference's fixed <c>SHA256_TV</c>
/// table (which needs its own transcribed hash constants and a <c>maxBlocks = 32</c> capacity) with
/// an independent <see cref="SHA256"/> oracle over the boundary lengths that actually exercise the
/// padding branches (0, 1, 3, the 55/56/57 marker-byte/length-field boundary, the 63/64/65 block
/// boundary, and the 119/120/127 two-block boundary), at <c>maxBlocks = 3</c> — wide enough for
/// every swept length's padding, narrower than the reference's capacity. The unpacked and
/// all-packed circuit-evaluation gates run over a single vector (<c>kSha_bt_[0]</c>) rather than a
/// sweep of all three, since <c>assert_transform_block</c>'s shape does not depend on which round
/// values it is asserting against — the raw witness generator (test 1) already sweeps every vector
/// exhaustively. The Gf(2^128) unpacked-evaluation gate is new too: the reference only ever compiles
/// (never evaluates) <c>FlatSHA256Circuit</c> over <c>GF2_128&lt;&gt;</c>, via <c>block_size_gf2_128_*</c>'s
/// <c>CompilerBackend</c>, so this is the first direct evaluation of the char-two
/// <see cref="LongfellowBitAdder"/> arm this gadget takes. <c>assert_message</c>/<c>assert_message_hash</c>
/// and <c>find_len</c> are reduced from the reference's <c>maxBlocks = 32</c> sweep over every
/// <c>SHA256_TV</c> entry to <c>maxBlocks = 2</c> over the single "abc" message: block-chaining and
/// zero-padding do not depend on which message occupies the blocks, and the block-transform
/// recurrence itself is already pinned by the other five test groups.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowFlatSha256CircuitTests
{
    /// <summary>The reference's <c>outw[48]</c>: the witnessed schedule extension <c>w[16..63]</c>.</summary>
    private const int ScheduleWordCount = 48;

    /// <summary>The reference's <c>oute[64]</c>/<c>outa[64]</c>: one witnessed register value per compression round.</summary>
    private const int RoundCount = 64;

    /// <summary>The reference's <c>H0</c>/<c>H1</c>: eight 32-bit hash-state words.</summary>
    private const int StateWordCount = 8;

    /// <summary>One SHA-256 block's byte width (FIPS 180-4 section 5.1).</summary>
    private const int BytesPerBlock = 64;

    /// <summary>One 32-bit word's byte width.</summary>
    private const int BytesPerWord = 4;

    /// <summary>The reference's <c>v256</c>: the assembled hash target's bit width.</summary>
    private const int HashBitWidth = 256;

    /// <summary>The reference's <c>ceildiv(n + 9, 64)</c>: one 0x80 marker byte plus the 8-byte big-endian bit-length field.</summary>
    private const int PaddingOverheadBytes = 9;

    /// <summary>127, the sweep's longest message, needs <c>ceil((127 + 9) / 64) = 3</c> occupied blocks.</summary>
    private const int MessageLengthSweepMaxBlocks = 3;

    /// <summary><c>"abc"</c> is 3 bytes long, well within one block once padded.</summary>
    private const int AbcMessageMaxBlocks = 2;

    /// <summary><c>"abc"</c> is 3 bytes = 24 bits, the value <c>find_len</c> must recover.</summary>
    private const ulong AbcMessageBitLength = 24;

    /// <summary>The witnessed first <c>kSha_bt_</c> vector, the single instance the circuit-evaluation gates run over.</summary>
    private const int VectorIndexForCircuitGates = 0;

    /// <summary>Flips the schedule word's least significant bit; any single-bit flip suffices to break <c>assert_eqmod</c>.</summary>
    private const uint ScheduleTamperMask = 0x1;

    /// <summary>The first target bit; any single flipped bit suffices to break the final <c>vassert_eq</c>.</summary>
    private const int TargetTamperIndex = 0;

    /// <summary>
    /// The reference's boundary-length message set: the 0x80 marker/length-field boundary (55/56/57),
    /// the block boundary (63/64/65), the two-block boundary (119/120/127), plus the empty and
    /// smallest nonempty messages.
    /// </summary>
    private static int[] MessageLengthSweep { get; } = [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127];

    /// <summary>The reference's <c>kSha_bt_[t].input</c>, transcribed verbatim from <c>sha256_test_values.h</c>.</summary>
    private static uint[][] KShaBtInputs { get; } =
    [
        [
            0, 0xdeadbeef, 0xbd5b7dde, 0x9c093ccd, 0x7ab6fbbc, 0x5964baab, 0x3812799a, 0x16c03889,
            0xf56df778, 0xd41bb667, 0xb2c97556, 0x91773445, 0x7024f334, 0x4ed2b223, 0x2d807112, 0xc2e3001
        ],
        [
            0x7, 0xe, 0x15, 0x1c, 0x23, 0x2a, 0x31, 0x38,
            0x3f, 0x46, 0x4d, 0x54, 0x5b, 0x62, 0x69, 0x70
        ],
        [
            0xf0cee5d1, 0x615dfa6a, 0xbda82adf, 0xcb66fb25, 0x30d60637, 0xb1018af9, 0x2c5c0e06, 0xb0556e74,
            0xf8e2da1f, 0xf05b699b, 0xabbf6d16, 0x3377e5ad, 0x46d8cd9e, 0xcc01d8dd, 0x5532a535, 0x34e928ea
        ]
    ];

    /// <summary>The reference's <c>kSha_bt_[t].h</c>, transcribed verbatim from <c>sha256_test_values.h</c>.</summary>
    private static uint[][] KShaBtInitialStates { get; } =
    [
        [0, 0xabadcafe, 0x575b95fc, 0x30960fa, 0xaeb72bf8, 0x5a64f6f6, 0x612c1f4, 0xb1c08cf2],
        [0x0, 0x13, 0x26, 0x39, 0x4c, 0x5f, 0x72, 0x85],
        [0x515f007c, 0x5bd062c2, 0x12200854, 0x4db127f8, 0x216231b, 0x1f16e9e8, 0x1190cde7, 0x66ef438d]
    ];

    /// <summary>The reference's <c>kSha_bt_[t].want</c>, transcribed verbatim from <c>sha256_test_values.h</c>.</summary>
    private static uint[][] KShaBtWantFinalStates { get; } =
    [
        [0x656f967b, 0x508cb605, 0x109902c5, 0xbe9909c, 0x30ed1bc6, 0x8d3bb28c, 0x836c99a8, 0x30731a12],
        [0x95ddd507, 0x1a7a4b1f, 0xf5951676, 0x105a25a3, 0x511cee03, 0xd0972a96, 0xb1cb76d7, 0xf9f46d72],
        [0x3a3995a, 0xb55e568e, 0x5fb4b933, 0x97c9e9c0, 0xaea7d67c, 0xaee17ae4, 0xcfffacb8, 0x91d6ab5e]
    ];

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


    /// <summary>Pins that TransformAndWitnessBlock reproduces the reference's kSha_bt_ block-transform vectors' final state.</summary>
    [TestMethod]
    public void TransformAndWitnessBlockReproducesTheReferenceBlockTransformVectors()
    {
        //Reused across every vector below: transform_and_witness_block overwrites every entry of all
        //four destinations unconditionally, so a fresh witness never observes a stale value left by
        //an earlier vector.
        Span<uint> scheduleExtension = stackalloc uint[ScheduleWordCount];
        Span<uint> registerE = stackalloc uint[RoundCount];
        Span<uint> registerA = stackalloc uint[RoundCount];
        Span<uint> finalState = stackalloc uint[StateWordCount];

        for(int vector = 0; vector < KShaBtInputs.Length; vector++)
        {
            LongfellowFlatSha256Witness.TransformAndWitnessBlock(KShaBtInputs[vector], KShaBtInitialStates[vector], scheduleExtension, registerE, registerA, finalState);

            uint[] want = KShaBtWantFinalStates[vector];
            for(int i = 0; i < StateWordCount; i++)
            {
                Assert.AreEqual(want[i], finalState[i], $"kSha_bt_ vector {vector}'s final state word {i} must match the reference's want[].");
            }
        }
    }


    /// <summary>Pins that TransformAndWitnessMessage's occupied block count, final hash and zero-padding match SHA256.HashData across every padding-boundary message length.</summary>
    [TestMethod]
    public void TransformAndWitnessMessageMatchesSha256HashDataAcrossBoundaryLengths()
    {
        foreach(int length in MessageLengthSweep)
        {
            byte[] message = BuildRepeatedMessage(length);
            var paddedMessage = new byte[BytesPerBlock * MessageLengthSweepMaxBlocks];
            var witnesses = new LongfellowFlatSha256BlockWitness[MessageLengthSweepMaxBlocks];

            LongfellowFlatSha256Witness.TransformAndWitnessMessage(message, MessageLengthSweepMaxBlocks, out byte occupiedBlockCount, paddedMessage, witnesses);

            int expectedOccupiedBlockCount = (length + PaddingOverheadBytes + (BytesPerBlock - 1)) / BytesPerBlock;
            Assert.AreEqual(expectedOccupiedBlockCount, (int)occupiedBlockCount, $"The occupied block count for a {length}-byte message must equal ceil((length + 9) / 64).");

            byte[] expectedHash = SHA256.HashData(message);
            byte[] actualHash = ConvertFinalStateWordsToHashBytes(witnesses[occupiedBlockCount - 1].FinalState);
            Assert.IsTrue(actualHash.AsSpan().SequenceEqual(expectedHash), $"The last occupied block's final state for a {length}-byte message must equal SHA256.HashData's digest.");

            for(int i = occupiedBlockCount * BytesPerBlock; i < paddedMessage.Length; i++)
            {
                Assert.AreEqual((byte)0, paddedMessage[i], $"Byte {i} beyond the occupied blocks must be zero for a {length}-byte message.");
            }
        }
    }


    /// <summary>Pins that the unpacked AssertTransformBlock accepts the witnessed first kSha_bt_ vector over the P-256 base field.</summary>
    [TestMethod]
    public void AssertTransformBlockUnpackedAcceptsTheWitnessedFirstVectorOverFp256()
    {
        AssertUnpackedTransformBlockAcceptsVectorZero(Fp256Field);
    }


    /// <summary>Pins that the unpacked AssertTransformBlock accepts the witnessed first kSha_bt_ vector over GF(2^128).</summary>
    [TestMethod]
    public void AssertTransformBlockUnpackedAcceptsTheWitnessedFirstVectorOverGf2128()
    {
        AssertUnpackedTransformBlockAcceptsVectorZero(Gf2128Field);
    }


    /// <summary>Pins that the unpacked AssertTransformBlock latches a failure when a witnessed schedule word is tampered.</summary>
    [TestMethod]
    public void AssertTransformBlockUnpackedLatchesWhenAWitnessedScheduleWordIsTampered()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        Span<uint> scheduleExtension = stackalloc uint[ScheduleWordCount];
        Span<uint> registerE = stackalloc uint[RoundCount];
        Span<uint> registerA = stackalloc uint[RoundCount];
        Span<uint> finalState = stackalloc uint[StateWordCount];
        LongfellowFlatSha256Witness.TransformAndWitnessBlock(KShaBtInputs[VectorIndexForCircuitGates], KShaBtInitialStates[VectorIndexForCircuitGates], scheduleExtension, registerE, registerA, finalState);

        scheduleExtension[0] ^= ScheduleTamperMask;

        LongfellowBitWire[][] blockWords = BuildWordVectors(logic, KShaBtInputs[VectorIndexForCircuitGates]);
        LongfellowBitWire[][] initialState = BuildWordVectors(logic, KShaBtInitialStates[VectorIndexForCircuitGates]);
        LongfellowBitWire[][] scheduleWires = BuildWordVectors(logic, scheduleExtension);
        LongfellowBitWire[][] registerEWires = BuildWordVectors(logic, registerE);
        LongfellowBitWire[][] registerAWires = BuildWordVectors(logic, registerA);
        LongfellowBitWire[][] finalStateWires = BuildWordVectors(logic, finalState);

        circuit.AssertTransformBlock(blockWords, initialState, scheduleWires, registerEWires, registerAWires, finalStateWires);

        Assert.IsTrue(backend.AssertionFailed, "Flipping one bit of a witnessed schedule word must latch an AssertEqualModulo failure.");
    }


    /// <summary>Pins that the all-packed AssertTransformBlock accepts the witnessed first kSha_bt_ vector over the P-256 base field.</summary>
    [TestMethod]
    public void AssertTransformBlockAllPackedAcceptsTheWitnessedFirstVectorOverFp256()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var encoder = new LongfellowBitPluckerEncoder(Fp256Field, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        Span<uint> scheduleExtension = stackalloc uint[ScheduleWordCount];
        Span<uint> registerE = stackalloc uint[RoundCount];
        Span<uint> registerA = stackalloc uint[RoundCount];
        Span<uint> finalState = stackalloc uint[StateWordCount];
        LongfellowFlatSha256Witness.TransformAndWitnessBlock(KShaBtInputs[VectorIndexForCircuitGates], KShaBtInitialStates[VectorIndexForCircuitGates], scheduleExtension, registerE, registerA, finalState);

        LongfellowBitWire[][] blockWords = BuildWordVectors(logic, KShaBtInputs[VectorIndexForCircuitGates]);
        int[][] packedInitialState = BuildPackedWords(backend, encoder, KShaBtInitialStates[VectorIndexForCircuitGates]);
        int[][] packedSchedule = BuildPackedWords(backend, encoder, scheduleExtension);
        int[][] packedRegisterE = BuildPackedWords(backend, encoder, registerE);
        int[][] packedRegisterA = BuildPackedWords(backend, encoder, registerA);
        int[][] packedFinalState = BuildPackedWords(backend, encoder, finalState);

        circuit.AssertTransformBlock(blockWords, packedInitialState, packedSchedule, packedRegisterE, packedRegisterA, packedFinalState);

        Assert.IsFalse(backend.AssertionFailed, "Reaching this line without an exception is the pass for the all-packed overload: the panicking backend never latches, so this documents that assert_transform_block's internal recurrence checks all evaluated to zero for the witnessed vector.");
    }


    /// <summary>Pins that AssertMessageHash accepts the genuine padded <c>"abc"</c> message witness over the P-256 base field.</summary>
    [TestMethod]
    public void AssertMessageHashAcceptsTheAbcMessageOverFp256()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var encoder = new LongfellowBitPluckerEncoder(Fp256Field, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        (byte[] paddedMessage, LongfellowFlatSha256BlockWitness[] plainWitnesses, byte occupiedBlockCount) = BuildAbcMessageWitness();

        LongfellowBitWire[][] messageBytes = BuildByteVectors(logic, paddedMessage);
        LongfellowBitWire[] blockCount = logic.BitVector(LongfellowLogic.BitWidth8, occupiedBlockCount);
        LongfellowFlatSha256PackedBlockWitness[] packedWitnesses = BuildPackedBlockWitnesses(backend, encoder, plainWitnesses);

        byte[] hash = SHA256.HashData("abc"u8);
        LongfellowBitWire[] target = BuildTargetBits(logic, hash);

        circuit.AssertMessageHash(AbcMessageMaxBlocks, blockCount, messageBytes, target, packedWitnesses);

        Assert.IsFalse(backend.AssertionFailed, "Reaching this line without an exception is the pass: the panicking backend never latches, so this documents that assert_message_hash accepted the genuine abc witness.");
    }


    /// <summary>Pins that AssertMessageHash latches a failure when the target hash is wrong.</summary>
    [TestMethod]
    public void AssertMessageHashLatchesWhenTheTargetHashIsWrong()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var encoder = new LongfellowBitPluckerEncoder(Fp256Field, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        (byte[] paddedMessage, LongfellowFlatSha256BlockWitness[] plainWitnesses, byte occupiedBlockCount) = BuildAbcMessageWitness();

        LongfellowBitWire[][] messageBytes = BuildByteVectors(logic, paddedMessage);
        LongfellowBitWire[] blockCount = logic.BitVector(LongfellowLogic.BitWidth8, occupiedBlockCount);
        LongfellowFlatSha256PackedBlockWitness[] packedWitnesses = BuildPackedBlockWitnesses(backend, encoder, plainWitnesses);

        byte[] hash = SHA256.HashData("abc"u8);
        LongfellowBitWire[] target = BuildTargetBits(logic, hash);
        target[TargetTamperIndex] = logic.Not(target[TargetTamperIndex]);

        circuit.AssertMessageHash(AbcMessageMaxBlocks, blockCount, messageBytes, target, packedWitnesses);

        Assert.IsTrue(backend.AssertionFailed, "AssertMessageHash must latch a failure when the target hash's bit 0 is wrong.");
    }


    /// <summary>Pins that AssertZeroPadding latches a failure when a byte beyond the occupied blocks is nonzero.</summary>
    [TestMethod]
    public void AssertZeroPaddingLatchesWhenAByteBeyondTheOccupiedBlocksIsNonzero()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        (byte[] paddedMessage, _, byte occupiedBlockCount) = BuildAbcMessageWitness();

        //The first byte of the second block sits beyond the single occupied block, where the
        //zero-padding assertion demands zero.
        paddedMessage[BytesPerBlock] = 0x01;

        LongfellowBitWire[][] messageBytes = BuildByteVectors(logic, paddedMessage);
        LongfellowBitWire[] blockCount = logic.BitVector(LongfellowLogic.BitWidth8, occupiedBlockCount);

        circuit.AssertZeroPadding(AbcMessageMaxBlocks, blockCount, messageBytes);

        Assert.IsTrue(backend.AssertionFailed, "AssertZeroPadding must latch a failure when a byte beyond the occupied blocks is nonzero.");
    }


    /// <summary>Pins that the all-packed AssertTransformBlock latches a failure when a packed final-state word is tampered.</summary>
    [TestMethod]
    public void AssertTransformBlockAllPackedLatchesWhenAPackedFinalStateWordIsTampered()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var encoder = new LongfellowBitPluckerEncoder(Fp256Field, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        Span<uint> scheduleExtension = stackalloc uint[ScheduleWordCount];
        Span<uint> registerE = stackalloc uint[RoundCount];
        Span<uint> registerA = stackalloc uint[RoundCount];
        Span<uint> finalState = stackalloc uint[StateWordCount];
        LongfellowFlatSha256Witness.TransformAndWitnessBlock(KShaBtInputs[VectorIndexForCircuitGates], KShaBtInitialStates[VectorIndexForCircuitGates], scheduleExtension, registerE, registerA, finalState);

        //A single flipped bit in the first final-state word breaks the slack-two closing assertion.
        finalState[0] ^= ScheduleTamperMask;

        LongfellowBitWire[][] blockWords = BuildWordVectors(logic, KShaBtInputs[VectorIndexForCircuitGates]);
        int[][] packedInitialState = BuildPackedWords(backend, encoder, KShaBtInitialStates[VectorIndexForCircuitGates]);
        int[][] packedSchedule = BuildPackedWords(backend, encoder, scheduleExtension);
        int[][] packedRegisterE = BuildPackedWords(backend, encoder, registerE);
        int[][] packedRegisterA = BuildPackedWords(backend, encoder, registerA);
        int[][] packedFinalState = BuildPackedWords(backend, encoder, finalState);

        circuit.AssertTransformBlock(blockWords, packedInitialState, packedSchedule, packedRegisterE, packedRegisterA, packedFinalState);

        Assert.IsTrue(backend.AssertionFailed, "The all-packed overload must latch a failure when a packed final-state word is tampered.");
    }


    /// <summary>Pins that FindLength recovers the padded <c>"abc"</c> message's bit length as constant bits.</summary>
    [TestMethod]
    public void FindLengthRecoversTheAbcMessageBitLengthAsConstantBits()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        (byte[] paddedMessage, _, byte occupiedBlockCount) = BuildAbcMessageWitness();

        LongfellowBitWire[][] messageBytes = BuildByteVectors(logic, paddedMessage);
        LongfellowBitWire[] blockCount = logic.BitVector(LongfellowLogic.BitWidth8, occupiedBlockCount);

        LongfellowBitWire[] length = circuit.FindLength(AbcMessageMaxBlocks, messageBytes, blockCount);

        Assert.HasCount(LongfellowLogic.BitWidth64, length, "FindLength must return exactly 64 bits.");
        for(int i = 0; i < LongfellowLogic.BitWidth64; i++)
        {
            int expectedBit = (int)((AbcMessageBitLength >> i) & 1UL);
            byte[] expected = (expectedBit == 0 ? Fp256Field.Compiler.Zero : Fp256Field.Compiler.One).ToArray();

            Assert.IsTrue(EvaluatedBytes(logic, logic.Eval(length[i])).AsSpan().SequenceEqual(expected), $"FindLength bit {i} must equal the little-endian bit {i} of 24.");
        }
    }


    /// <summary>Runs the reference's <c>p256_assert_block</c> unpacked evaluation gate over one field bundle: witnesses <see cref="VectorIndexForCircuitGates"/>, builds every input as an unpacked bit vector, and asserts that the compiled recurrence accepts it without an exception.</summary>
    /// <param name="field">The field bundle to gate over.</param>
    private static void AssertUnpackedTransformBlockAcceptsVectorZero(LongfellowLogicFieldOperations field)
    {
        var backend = new LongfellowEvaluationLogicBackend(field);
        var logic = new LongfellowLogic(backend, field);
        var plucker = new LongfellowBitPlucker(logic, LongfellowFlatSha256Circuit.SchedulePluckerLogPointCount);
        var circuit = new LongfellowFlatSha256Circuit(logic, plucker);

        Span<uint> scheduleExtension = stackalloc uint[ScheduleWordCount];
        Span<uint> registerE = stackalloc uint[RoundCount];
        Span<uint> registerA = stackalloc uint[RoundCount];
        Span<uint> finalState = stackalloc uint[StateWordCount];
        LongfellowFlatSha256Witness.TransformAndWitnessBlock(KShaBtInputs[VectorIndexForCircuitGates], KShaBtInitialStates[VectorIndexForCircuitGates], scheduleExtension, registerE, registerA, finalState);

        LongfellowBitWire[][] blockWords = BuildWordVectors(logic, KShaBtInputs[VectorIndexForCircuitGates]);
        LongfellowBitWire[][] initialState = BuildWordVectors(logic, KShaBtInitialStates[VectorIndexForCircuitGates]);
        LongfellowBitWire[][] scheduleWires = BuildWordVectors(logic, scheduleExtension);
        LongfellowBitWire[][] registerEWires = BuildWordVectors(logic, registerE);
        LongfellowBitWire[][] registerAWires = BuildWordVectors(logic, registerA);
        LongfellowBitWire[][] finalStateWires = BuildWordVectors(logic, finalState);

        circuit.AssertTransformBlock(blockWords, initialState, scheduleWires, registerEWires, registerAWires, finalStateWires);

        Assert.IsFalse(backend.AssertionFailed, "Reaching this line without an exception is the pass: the panicking backend never latches, so this documents that assert_transform_block's internal recurrence checks all evaluated to zero for the witnessed vector.");
    }


    /// <summary>Builds a deterministic message of repeated content, for the padding-boundary sweep.</summary>
    /// <param name="length">The message length in bytes.</param>
    /// <returns>The message.</returns>
    private static byte[] BuildRepeatedMessage(int length)
    {
        const byte RepeatedContentByte = (byte)'a'; //Deterministic content; only the padding/chaining logic under test depends on the length, not the byte value.

        var message = new byte[length];
        Array.Fill(message, RepeatedContentByte);

        return message;
    }


    /// <summary>Writes the eight final-state words big-endian, the reference's <c>H1</c> read as a 32-byte digest.</summary>
    /// <param name="finalState">The eight final-state words.</param>
    /// <returns>The 32-byte digest.</returns>
    private static byte[] ConvertFinalStateWordsToHashBytes(ReadOnlySpan<uint> finalState)
    {
        var hash = new byte[StateWordCount * BytesPerWord];
        for(int i = 0; i < StateWordCount; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(hash.AsSpan(i * BytesPerWord, BytesPerWord), finalState[i]);
        }

        return hash;
    }


    /// <summary>Witnesses the padded three-byte "abc" message at <see cref="AbcMessageMaxBlocks"/>, the shared setup for the message-level and find_len gates.</summary>
    /// <returns>The padded message, the per-block witnesses, and the occupied block count.</returns>
    private static (byte[] PaddedMessage, LongfellowFlatSha256BlockWitness[] Witnesses, byte OccupiedBlockCount) BuildAbcMessageWitness()
    {
        var paddedMessage = new byte[BytesPerBlock * AbcMessageMaxBlocks];
        var witnesses = new LongfellowFlatSha256BlockWitness[AbcMessageMaxBlocks];

        LongfellowFlatSha256Witness.TransformAndWitnessMessage("abc"u8, AbcMessageMaxBlocks, out byte occupiedBlockCount, paddedMessage, witnesses);

        return (paddedMessage, witnesses, occupiedBlockCount);
    }


    /// <summary>Builds one unpacked 32-bit bit-vector wire per word (the reference's <c>vbit32</c> over an array), least significant bit first.</summary>
    /// <param name="logic">The gadget layer to build wires over.</param>
    /// <param name="words">The words to convert.</param>
    /// <returns>One bit vector per word.</returns>
    private static LongfellowBitWire[][] BuildWordVectors(LongfellowLogic logic, ReadOnlySpan<uint> words)
    {
        var result = new LongfellowBitWire[words.Length][];
        for(int i = 0; i < words.Length; i++)
        {
            result[i] = logic.BitVector(LongfellowLogic.BitWidth32, words[i]);
        }

        return result;
    }


    /// <summary>Builds one unpacked 8-bit bit-vector wire per byte (the reference's <c>vbit8</c> over an array), least significant bit first.</summary>
    /// <param name="logic">The gadget layer to build wires over.</param>
    /// <param name="bytes">The bytes to convert.</param>
    /// <returns>One bit vector per byte.</returns>
    private static LongfellowBitWire[][] BuildByteVectors(LongfellowLogic logic, ReadOnlySpan<byte> bytes)
    {
        var result = new LongfellowBitWire[bytes.Length][];
        for(int i = 0; i < bytes.Length; i++)
        {
            result[i] = logic.BitVector(LongfellowLogic.BitWidth8, bytes[i]);
        }

        return result;
    }


    /// <summary>Builds the 256-bit target vector from a hash digest, under the reference's own bit indexing: <c>target[j] = (hash[(255 - j) / 8] &gt;&gt; (j % 8)) &amp; 1</c>.</summary>
    /// <param name="logic">The gadget layer to build wires over.</param>
    /// <param name="hash">The 32-byte digest.</param>
    /// <returns>The 256-bit target vector.</returns>
    private static LongfellowBitWire[] BuildTargetBits(LongfellowLogic logic, ReadOnlySpan<byte> hash)
    {
        var target = new LongfellowBitWire[HashBitWidth];
        for(int j = 0; j < HashBitWidth; j++)
        {
            int bit = (hash[(HashBitWidth - 1 - j) / LongfellowLogic.BitWidth8] >> (j % LongfellowLogic.BitWidth8)) & 1;
            target[j] = logic.Bit(bit);
        }

        return target;
    }


    /// <summary>Packs one 32-bit word through a bit-plucker encoder, interning every packed element as a constant wire (the reference's <c>L.konst(BPENC.mkpacked_v32(...))</c>).</summary>
    /// <param name="backend">The evaluation backend the constant wires are interned on.</param>
    /// <param name="encoder">The bit-plucker encoder.</param>
    /// <param name="word">The word to pack.</param>
    /// <returns>The packed wires.</returns>
    private static int[] PackWord(LongfellowEvaluationLogicBackend backend, LongfellowBitPluckerEncoder encoder, uint word)
    {
        ReadOnlyMemory<byte>[] packedElements = encoder.MakePackedV32(word);
        var wires = new int[packedElements.Length];
        for(int k = 0; k < packedElements.Length; k++)
        {
            wires[k] = backend.Constant(packedElements[k].Span);
        }

        return wires;
    }


    /// <summary>Packs an array of 32-bit words, one packed-wire row per word.</summary>
    /// <param name="backend">The evaluation backend the constant wires are interned on.</param>
    /// <param name="encoder">The bit-plucker encoder.</param>
    /// <param name="words">The words to pack.</param>
    /// <returns>One packed-wire row per word.</returns>
    private static int[][] BuildPackedWords(LongfellowEvaluationLogicBackend backend, LongfellowBitPluckerEncoder encoder, ReadOnlySpan<uint> words)
    {
        var result = new int[words.Length][];
        for(int i = 0; i < words.Length; i++)
        {
            result[i] = PackWord(backend, encoder, words[i]);
        }

        return result;
    }


    /// <summary>Fills a preallocated packed-word destination in place, one packed-wire row per word.</summary>
    /// <param name="backend">The evaluation backend the constant wires are interned on.</param>
    /// <param name="encoder">The bit-plucker encoder.</param>
    /// <param name="destination">The destination rows, already sized to <paramref name="words"/>'s length.</param>
    /// <param name="words">The words to pack.</param>
    private static void FillPackedWordArray(LongfellowEvaluationLogicBackend backend, LongfellowBitPluckerEncoder encoder, int[][] destination, uint[] words)
    {
        for(int i = 0; i < words.Length; i++)
        {
            destination[i] = PackWord(backend, encoder, words[i]);
        }
    }


    /// <summary>Packs a full set of plain block witnesses into the in-circuit all-packed witness record the reference's <c>BlockWitness::input</c> would otherwise declare through fresh input wires.</summary>
    /// <param name="backend">The evaluation backend the constant wires are interned on.</param>
    /// <param name="encoder">The bit-plucker encoder.</param>
    /// <param name="plainWitnesses">The plain-<see cref="uint"/> per-block witnesses to pack.</param>
    /// <returns>The packed per-block witnesses.</returns>
    private static LongfellowFlatSha256PackedBlockWitness[] BuildPackedBlockWitnesses(LongfellowEvaluationLogicBackend backend, LongfellowBitPluckerEncoder encoder, LongfellowFlatSha256BlockWitness[] plainWitnesses)
    {
        var result = new LongfellowFlatSha256PackedBlockWitness[plainWitnesses.Length];
        for(int block = 0; block < plainWitnesses.Length; block++)
        {
            var packed = new LongfellowFlatSha256PackedBlockWitness();
            FillPackedWordArray(backend, encoder, packed.ScheduleExtension, plainWitnesses[block].ScheduleExtension);
            FillPackedWordArray(backend, encoder, packed.RegisterEWitness, plainWitnesses[block].RegisterEWitness);
            FillPackedWordArray(backend, encoder, packed.RegisterAWitness, plainWitnesses[block].RegisterAWitness);
            FillPackedWordArray(backend, encoder, packed.FinalState, plainWitnesses[block].FinalState);

            result[block] = packed;
        }

        return result;
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
