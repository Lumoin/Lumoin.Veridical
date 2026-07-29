using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Globalization;
using System.Numerics;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The compile-half gates for the mdoc revocation statements: the kernel-compiled small-list and
/// span circuits pinned counter for counter against the reference compiler, and the ZK end-to-end
/// gates over both statements.
/// </summary>
/// <remarks>
/// <para>
/// Both pinned rows were regenerated from the pinned reference commit by running its own
/// <c>mdoc.mdoc_revocation_list_test</c> and <c>mdoc.mdoc_revocation_span_test</c> gtests in the
/// longfellow-ref Docker oracle (both dumps carry the reference's own copy-pasted label
/// <c>mdoc revocation list</c>). Matching every counter pins the product-tree association, the
/// comparator reduction, the two-block SHA-256 shape at the revocation packing width and the
/// ECDSA advice structure.
/// </para>
/// <para>
/// The end-to-end gates prove the reference span tuple and a small deterministic list through the
/// shipped ZK prover and verifier over the P-256 base field, reject a tampered proof, and refuse
/// to prove an out-of-span identifier and a listed identifier.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowMdocRevocationCompileTests
{
    /// <summary>The field element width in bytes used for every witness column entry.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The pinned list circuit's element count (the reference's <c>kListSize</c>).</summary>
    private const int PinnedListLength = 50000;

    /// <summary>The always-on end-to-end list length — small so the fast suite proves the list statement in milliseconds; the pinned 50000-element shape gets its own gate.</summary>
    private const int SmallListLength = 8;

    /// <summary>The small list's first element value; the list holds this and the next consecutive integers.</summary>
    private const int ListFirstValue = 2001;

    /// <summary>An identifier value off every deterministic list this class builds.</summary>
    private const int UnlistedIdValue = 90001;

    /// <summary>The list position the listed-identifier gate reuses as the identifier.</summary>
    private const int ListedIndex = 3;

    /// <summary>The list circuit's reference depth upper bound (Docker oracle, <c>mdoc.mdoc_revocation_list_test</c>).</summary>
    private const int ListDepth = 19;

    /// <summary>The list circuit's reference wire count.</summary>
    private const int ListWireCount = 165573;

    /// <summary>The list circuit's reference input count.</summary>
    private const int ListInputCount = 50003;

    /// <summary>The list circuit's reference output count.</summary>
    private const int ListOutputCount = 1;

    /// <summary>The list circuit's reference copy-wire overhead count.</summary>
    private const int ListCopyOverheadCount = 15570;

    /// <summary>The list circuit's reference quad-term count.</summary>
    private const int ListQuadTermCount = 165571;

    /// <summary>The list circuit's reference eliminated-subexpression count.</summary>
    private const int ListEliminatedSubexpressionCount = 0;

    /// <summary>The list circuit's reference not-needed count.</summary>
    private const int ListNotNeededCount = 50005;

    /// <summary>The span circuit's reference depth upper bound (Docker oracle, <c>mdoc.mdoc_revocation_span_test</c>).</summary>
    private const int SpanDepth = 12;

    /// <summary>The span circuit's reference wire count.</summary>
    private const int SpanWireCount = 198374;

    /// <summary>The span circuit's reference input count.</summary>
    private const int SpanInputCount = 5521;

    /// <summary>The span circuit's reference output count.</summary>
    private const int SpanOutputCount = 2;

    /// <summary>The span circuit's reference copy-wire overhead count.</summary>
    private const int SpanCopyOverheadCount = 31242;

    /// <summary>The span circuit's reference quad-term count.</summary>
    private const int SpanQuadTermCount = 597406;

    /// <summary>The span circuit's reference eliminated-subexpression count.</summary>
    private const int SpanEliminatedSubexpressionCount = 275398;

    /// <summary>The span circuit's reference not-needed count.</summary>
    private const int SpanNotNeededCount = 506466;

    /// <summary>The Fiat-Shamir transcript seed for the span end-to-end gate.</summary>
    private static byte[] SpanTranscriptSeed { get; } = Encoding.ASCII.GetBytes("mdoc-revocation-span-e2e");

    /// <summary>The Fiat-Shamir transcript seed for the list end-to-end gates.</summary>
    private static byte[] ListTranscriptSeed { get; } = Encoding.ASCII.GetBytes("mdoc-revocation-list-e2e");

    /// <summary>The curve constants shared by the circuit and the witness generator.</summary>
    private static LongfellowEllipticCurveParameters Curve { get; } = LongfellowEllipticCurveParameters.CreateP256();

    /// <summary>The production Montgomery base field addition delegate (the BigInteger reference delegates are too slow for these circuits' sizes).</summary>
    private static ScalarAddDelegate FastAdd { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    /// <summary>The production Montgomery base field subtraction delegate.</summary>
    private static ScalarSubtractDelegate FastSubtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    /// <summary>The production Montgomery base field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate FastMultiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

    /// <summary>The production Montgomery base field inversion delegate.</summary>
    private static ScalarInvertDelegate FastInvert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

    /// <summary>The order-field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate OrderMultiply { get; } = P256ScalarMontgomeryBackend.GetMultiply();

    /// <summary>The order-field subtraction delegate.</summary>
    private static ScalarSubtractDelegate OrderSubtract { get; } = P256ScalarMontgomeryBackend.GetSubtract();

    /// <summary>The order-field inversion delegate.</summary>
    private static ScalarInvertDelegate OrderInvert { get; } = P256ScalarMontgomeryBackend.GetInvert();


    /// <summary>Pins the kernel-compiled 50000-element list circuit's telemetry against the reference compiler's.</summary>
    [TestMethod]
    public void TheListCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileListCircuit(NewFastFp256Bundle(), PinnedListLength, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(ListDepth, builder.DepthUpperBound, "The list circuit's depth must match the reference compiler's.");
        Assert.AreEqual(ListWireCount, builder.WireCount, "The list circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(ListInputCount, builder.InputCount, "The list circuit's input count must match the reference compiler's.");
        Assert.AreEqual(ListOutputCount, builder.OutputCount, "The list circuit's output count must match the reference compiler's.");
        Assert.AreEqual(ListCopyOverheadCount, builder.CopyWireOverheadCount, "The list circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(ListQuadTermCount, builder.QuadTermCount, "The list circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(ListEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The list circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(ListNotNeededCount, builder.NotNeededCount, "The list circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled span circuit's telemetry against the reference compiler's.</summary>
    [TestMethod]
    public void TheSpanCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileSpanCircuit(NewFastFp256Bundle(), out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(SpanDepth, builder.DepthUpperBound, "The span circuit's depth must match the reference compiler's.");
        Assert.AreEqual(SpanWireCount, builder.WireCount, "The span circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(SpanInputCount, builder.InputCount, "The span circuit's input count must match the reference compiler's.");
        Assert.AreEqual(SpanOutputCount, builder.OutputCount, "The span circuit's output count must match the reference compiler's.");
        Assert.AreEqual(SpanCopyOverheadCount, builder.CopyWireOverheadCount, "The span circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(SpanQuadTermCount, builder.QuadTermCount, "The span circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(SpanEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The span circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(SpanNotNeededCount, builder.NotNeededCount, "The span circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins that the kernel-compiled small-list statement proves and verifies end to end, that a tampered proof rejects, and that a listed identifier's zero non-witness is unprovable.</summary>
    [TestMethod]
    public void TheSmallListStatementProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewFastFp256Bundle();
        LongfellowSumcheckCircuit circuit = CompileListCircuit(field, SmallListLength, out _);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, Production16SubFieldBytes);

        ReadOnlyMemory<byte>[] list = BuildList(SmallListLength);
        byte[] witnessColumn = BuildListWitnessColumn(field, circuit, list, Canonical(UnlistedIdValue));

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, parameters, witnessColumn, ListTranscriptSeed);
        byte[] publicInputs = Fp256PublicInputBytes(circuit, witnessColumn);
        AssertRevocationVerifies(circuit, parameters, proof.Bytes, publicInputs, ListTranscriptSeed, expectedAccept: true);

        //A flipped byte inside the sumcheck segment diverges the challenge stream.
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[DigestSize + 8] ^= 0x01;
        AssertRevocationVerifies(circuit, parameters, tamperedProof, publicInputs, ListTranscriptSeed, expectedAccept: false);

        //A listed identifier zeroes the product; the zero non-witness cannot satisfy the statement.
        byte[] listedColumn = BuildListWitnessColumn(field, circuit, list, list[ListedIndex].ToArray());
        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProduceProof(circuit, parameters, listedColumn, ListTranscriptSeed),
            "A listed identifier must be unprovable.");
    }


    /// <summary>Pins that the pinned 50000-element list statement proves and verifies end to end.</summary>
    [TestMethod]
    public void ThePinnedListStatementProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewFastFp256Bundle();
        LongfellowSumcheckCircuit circuit = CompileListCircuit(field, PinnedListLength, out _);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, Production16SubFieldBytes);

        ReadOnlyMemory<byte>[] list = BuildList(PinnedListLength);
        byte[] witnessColumn = BuildListWitnessColumn(field, circuit, list, Canonical(UnlistedIdValue));

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, parameters, witnessColumn, ListTranscriptSeed);
        byte[] publicInputs = Fp256PublicInputBytes(circuit, witnessColumn);
        AssertRevocationVerifies(circuit, parameters, proof.Bytes, publicInputs, ListTranscriptSeed, expectedAccept: true);
    }


    /// <summary>Pins that the kernel-compiled span statement proves and verifies the reference tuple end to end, that a tampered proof rejects, and that an out-of-span identifier is unprovable.</summary>
    [TestMethod]
    public void TheSpanStatementProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewFastFp256Bundle();
        LongfellowSumcheckCircuit circuit = CompileSpanCircuit(field, out _);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, Production16SubFieldBytes);

        byte[] witnessColumn = BuildSpanWitnessColumn(field, circuit, out int idBitsStartWire);

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, parameters, witnessColumn, SpanTranscriptSeed);
        byte[] publicInputs = Fp256PublicInputBytes(circuit, witnessColumn);
        AssertRevocationVerifies(circuit, parameters, proof.Bytes, publicInputs, SpanTranscriptSeed, expectedAccept: true);

        //A flipped byte inside the sumcheck segment diverges the challenge stream.
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[DigestSize + 8] ^= 0x01;
        AssertRevocationVerifies(circuit, parameters, tamperedProof, publicInputs, SpanTranscriptSeed, expectedAccept: false);

        //Setting the identifier's top bit pushes it above the span's upper bound, so the strict
        //range assertion fails and the witness is unprovable.
        byte[] outOfSpanColumn = (byte[])witnessColumn.Clone();
        field.Compiler.One.Span.CopyTo(outOfSpanColumn.AsSpan(((idBitsStartWire + LongfellowLogic.BitWidth256 - 1) * ScalarSize), ScalarSize));
        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProduceProof(circuit, parameters, outOfSpanColumn, SpanTranscriptSeed),
            "An out-of-span identifier must be unprovable.");
    }


    /// <summary>
    /// Compiles the reference's list-test shape: the statement gadget constructed first, the list
    /// as public inputs, then the private identifier and product inverse.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="listLength">The list element count.</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileListCircuit(LongfellowLogicFieldOperations field, int listLength, out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowMdocRevocationListCircuit(logic);

        var list = new int[listLength];
        for(int i = 0; i < listLength; i++)
        {
            list[i] = logic.InputElement();
        }

        builder.PrivateInput();
        int id = logic.InputElement();
        int inverse = logic.InputElement();

        circuit.AssertNotOnList(list, id, inverse);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Compiles the reference's <c>make_circuit</c> shape: the statement gadget constructed first,
    /// the authority key as public inputs, then the private identifier and the witness declaration.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileSpanCircuit(LongfellowLogicFieldOperations field, out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowMdocRevocationSpanCircuit(logic, Curve);

        int craPkX = logic.InputElement();
        int craPkY = logic.InputElement();

        builder.PrivateInput();
        int id = logic.InputElement();
        LongfellowMdocRevocationSpanWitnessWires witness = circuit.InputWitness();

        circuit.AssertNotOnList(craPkX, craPkY, id, witness);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>Builds a deterministic list of consecutive small canonical values.</summary>
    /// <param name="listLength">The element count.</param>
    /// <returns>The list elements.</returns>
    private static ReadOnlyMemory<byte>[] BuildList(int listLength)
    {
        var list = new ReadOnlyMemory<byte>[listLength];
        for(int i = 0; i < listLength; i++)
        {
            list[i] = Canonical(ListFirstValue + i);
        }

        return list;
    }


    /// <summary>
    /// Builds the list statement's witness column: the constant one, the public list, then the
    /// private identifier and the helper's product inverse.
    /// </summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="circuit">The compiled circuit declaring the input count.</param>
    /// <param name="list">The public list elements.</param>
    /// <param name="id">The identifier.</param>
    /// <returns>The witness column, one canonical scalar per declared input wire.</returns>
    private static byte[] BuildListWitnessColumn(LongfellowLogicFieldOperations field, LongfellowSumcheckCircuit circuit, ReadOnlyMemory<byte>[] list, byte[] id)
    {
        byte[] inverse = LongfellowMdocRevocationListWitness.ComputeProductInverse(field, id, list);

        byte[] column = new byte[circuit.InputCount * ScalarSize];
        field.Compiler.One.Span.CopyTo(column.AsSpan(0, ScalarSize));
        int cursor = 1;
        for(int i = 0; i < list.Length; i++)
        {
            list[i].Span.CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
            cursor++;
        }

        id.CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;
        inverse.CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;

        Assert.AreEqual(circuit.InputCount, cursor, "The column layout must cover exactly the declared input wires.");

        return column;
    }


    /// <summary>
    /// Builds the span statement's witness column for the reference tuple: the constant one, the
    /// public authority key, then the private identifier and the generator's witness region.
    /// </summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="circuit">The compiled circuit declaring the input count.</param>
    /// <param name="idBitsStartWire">Receives the identifier-bit region's first wire, for the unprovability probe.</param>
    /// <returns>The witness column, one canonical scalar per declared input wire.</returns>
    private static byte[] BuildSpanWitnessColumn(LongfellowLogicFieldOperations field, LongfellowSumcheckCircuit circuit, out int idBitsStartWire)
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;
        byte[] id = ParseScalar(vector.Id);

        var generator = new LongfellowMdocRevocationSpanWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve);
        Assert.IsTrue(
            generator.ComputeWitness(
                ParseScalar(vector.PkX),
                ParseScalar(vector.PkY),
                ParseScalar(vector.E),
                ParseScalar(vector.R),
                ParseScalar(vector.S),
                id,
                ParseScalar(vector.Left),
                ParseScalar(vector.Right),
                vector.Epoch),
            "The reference span tuple must produce a witness.");

        byte[] column = new byte[circuit.InputCount * ScalarSize];
        field.Compiler.One.Span.CopyTo(column.AsSpan(0, ScalarSize));
        int cursor = 1;
        ParseScalar(vector.PkX).CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;
        ParseScalar(vector.PkY).CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;
        id.CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;

        //The identifier-bit region sits after the three signature scalars, the advice bundle and
        //the preimage bytes; the layout mirrors the declaration order.
        int witnessStart = cursor;
        var probeGenerator = new LongfellowEcdsaVerifyWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve);
        idBitsStartWire = witnessStart + 3 + probeGenerator.ElementCount + (LongfellowMdocRevocationConstants.SpanBlockCount * BytesPerBlock * LongfellowLogic.BitWidth8);

        generator.FillWitness(column.AsSpan(witnessStart * ScalarSize, generator.ElementCount * ScalarSize));
        Assert.AreEqual(circuit.InputCount, witnessStart + generator.ElementCount, "The column layout must cover exactly the declared input wires.");

        return column;
    }


    /// <summary>Produces a ZK proof over the compiled circuit with the production Montgomery field delegates.</summary>
    /// <param name="circuit">The compiled circuit to prove.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="witnessColumn">The witness column.</param>
    /// <param name="transcriptSeed">The Fiat-Shamir transcript seed.</param>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    private static LongfellowZkProofEnvelope ProduceProof(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] transcriptSeed)
    {
        Fp256RealFft fft = NewFastFft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, FastAdd, FastSubtract, FastMultiply, FastInvert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        using LongfellowTranscript transcript = NewFp256Transcript(transcriptSeed);
        LongfellowRandomByteSource random = NewBelowModulusSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            LongfellowFp256Encoding.SignatureSubfieldBoundary,
            random,
            transcript,
            encoderFactory,
            profile,
            codec,
            FastAdd,
            FastSubtract,
            FastMultiply,
            FastInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>Parses a proof's segments, verifies it with the production Montgomery field delegates, and asserts the verdict.</summary>
    /// <param name="circuit">The compiled circuit the proof was produced over.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="proof">The proof bytes to verify.</param>
    /// <param name="publicInputs">The public input bytes.</param>
    /// <param name="transcriptSeed">The Fiat-Shamir transcript seed.</param>
    /// <param name="expectedAccept">Whether the proof is expected to be accepted.</param>
    private static void AssertRevocationVerifies(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, ReadOnlySpan<byte> proof, byte[] publicInputs, byte[] transcriptSeed, bool expectedAccept)
    {
        Fp256RealFft fft = NewFastFft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, FastAdd, FastSubtract, FastMultiply, FastInvert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        ReadOnlySpan<byte> proofSpan = proof;
        ReadOnlySpan<byte> root = proofSpan[..DigestSize];
        int sumcheckSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        ReadOnlySpan<byte> sumcheckBytes = proofSpan.Slice(DigestSize, sumcheckSize);
        ReadOnlySpan<byte> ligeroBytes = proofSpan[(DigestSize + sumcheckSize)..];

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, sumcheckBytes, out _);
        Assert.IsNotNull(sumcheckProof, "The sumcheck segment must parse.");

        using LongfellowLigeroProof? ligeroProof = LongfellowLigeroProofSerializer.Read(parameters, profile, codec, BaseMemoryPool.Shared, ligeroBytes, out _);
        Assert.IsNotNull(ligeroProof, "The Ligero segment must parse.");

        using LongfellowTranscript transcript = NewFp256Transcript(transcriptSeed);
        LongfellowZkVerifier.RecvCommitment(root, transcript);

        bool accepted = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
            circuit,
            parameters,
            sumcheckProof,
            ligeroProof,
            root,
            publicInputs,
            transcript,
            encoderFactory,
            profile,
            FastAdd,
            FastSubtract,
            FastMultiply,
            FastInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result);

        Assert.AreEqual(expectedAccept, accepted, $"The verdict must be {(expectedAccept ? "accept" : "reject")} (result {result}).");
    }


    /// <summary>Builds the P-256 base field bundle over the production Montgomery backend delegates.</summary>
    /// <returns>The bundle.</returns>
    private static LongfellowLogicFieldOperations NewFastFp256Bundle()
    {
        return LongfellowLogicFieldOperations.CreateFp256(FastAdd, FastSubtract, FastMultiply, FastInvert, Canonical(Prime - 1));
    }


    /// <summary>Builds the real FFT over the P-256 base field with the production Montgomery delegates.</summary>
    /// <returns>The FFT.</returns>
    private static Fp256RealFft NewFastFft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, FastAdd, FastSubtract, FastMultiply, FastInvert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Parses a 0x-prefixed hexadecimal scalar into its canonical big-endian form.</summary>
    /// <param name="text">The scalar text.</param>
    /// <returns>The canonical bytes.</returns>
    private static byte[] ParseScalar(string text)
    {
        return Canonical(BigInteger.Parse("0" + text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture));
    }
}
