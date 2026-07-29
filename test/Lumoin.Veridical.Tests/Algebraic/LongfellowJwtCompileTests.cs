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
/// The compile-half gates for the JWT statement stack: the kernel-compiled ECDSA verification,
/// base64url decoder and full JWT circuits pinned counter for counter against the reference
/// compiler, and the full ZK end-to-end over the kernel-compiled JWT statement at seven blocks.
/// </summary>
/// <remarks>
/// <para>
/// Every pinned figure was regenerated from the pinned reference commit by running its own gtests
/// (<c>ECDSA.Size</c>, <c>Base64.Circuit</c>, <c>jwt.JwtZk7</c>/<c>JwtZk9</c>) in the
/// longfellow-ref Docker oracle; the header comments in the reference sources are stale and do not
/// reproduce at the pin even in the reference itself. Matching every counter pins the whole
/// gadget-to-scheduler pipeline — the muxer interpolations, the barrel-shift association trees, the
/// espresso covers, the complete-addition arithmetization and the dead-node structure — without a
/// circuit blob.
/// </para>
/// <para>
/// The end-to-end gate proves the reference SD-JWT+KB token's statement (one disclosed attribute)
/// through the shipped ZK prover and verifier over the P-256 base field, rejects a tampered proof,
/// and refuses to prove a witness whose digest bits are inconsistent.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowJwtCompileTests
{
    /// <summary>The field element width in bytes used for every witness column entry.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The block capacity of the end-to-end statement (the reference's <c>JwtZk7</c>).</summary>
    private const int SevenBlocks = 7;

    /// <summary>The second pinned block capacity (the reference's <c>JwtZk9</c>).</summary>
    private const int NineBlocks = 9;

    /// <summary>The disclosed attribute count every pinned shape uses.</summary>
    private const int AttributeCount = 1;

    /// <summary>The ECDSA circuit's reference depth upper bound (Docker oracle, <c>ECDSA.Size</c>).</summary>
    private const int EcdsaDepth = 12;

    /// <summary>The ECDSA circuit's reference wire count.</summary>
    private const int EcdsaWireCount = 24477;

    /// <summary>The ECDSA circuit's reference input count.</summary>
    private const int EcdsaInputCount = 1038;

    /// <summary>The ECDSA circuit's reference output count.</summary>
    private const int EcdsaOutputCount = 2;

    /// <summary>The ECDSA circuit's reference copy-wire overhead count.</summary>
    private const int EcdsaCopyOverheadCount = 7245;

    /// <summary>The ECDSA circuit's reference quad-term count.</summary>
    private const int EcdsaQuadTermCount = 49646;

    /// <summary>The ECDSA circuit's reference eliminated-subexpression count.</summary>
    private const int EcdsaEliminatedSubexpressionCount = 11090;

    /// <summary>The ECDSA circuit's reference not-needed count.</summary>
    private const int EcdsaNotNeededCount = 37213;

    /// <summary>The base64 decoder circuit's reference depth upper bound (Docker oracle, <c>Base64.Circuit</c>, GF(2^128)).</summary>
    private const int Base64Depth = 8;

    /// <summary>The base64 decoder circuit's reference wire count.</summary>
    private const int Base64WireCount = 200;

    /// <summary>The base64 decoder circuit's reference input count.</summary>
    private const int Base64InputCount = 9;

    /// <summary>The base64 decoder circuit's reference output count.</summary>
    private const int Base64OutputCount = 6;

    /// <summary>The base64 decoder circuit's reference copy-wire overhead count.</summary>
    private const int Base64CopyOverheadCount = 47;

    /// <summary>The base64 decoder circuit's reference quad-term count.</summary>
    private const int Base64QuadTermCount = 334;

    /// <summary>The base64 decoder circuit's reference eliminated-subexpression count.</summary>
    private const int Base64EliminatedSubexpressionCount = 157;

    /// <summary>The base64 decoder circuit's reference not-needed count.</summary>
    private const int Base64NotNeededCount = 195;

    /// <summary>The seven-block JWT circuit's reference depth upper bound (Docker oracle, <c>jwt.JwtZk7</c>).</summary>
    private const int JwtSevenDepth = 23;

    /// <summary>The seven-block JWT circuit's reference wire count.</summary>
    private const int JwtSevenWireCount = 759190;

    /// <summary>The seven-block JWT circuit's reference input count.</summary>
    private const int JwtSevenInputCount = 17289;

    /// <summary>The seven-block JWT circuit's reference output count.</summary>
    private const int JwtSevenOutputCount = 128;

    /// <summary>The seven-block JWT circuit's reference copy-wire overhead count.</summary>
    private const int JwtSevenCopyOverheadCount = 138136;

    /// <summary>The seven-block JWT circuit's reference quad-term count.</summary>
    private const int JwtSevenQuadTermCount = 2224268;

    /// <summary>The seven-block JWT circuit's reference eliminated-subexpression count.</summary>
    private const int JwtSevenEliminatedSubexpressionCount = 994839;

    /// <summary>The seven-block JWT circuit's reference not-needed count.</summary>
    private const int JwtSevenNotNeededCount = 1879760;

    /// <summary>The nine-block JWT circuit's reference depth upper bound (Docker oracle, <c>jwt.JwtZk9</c>).</summary>
    private const int JwtNineDepth = 23;

    /// <summary>The nine-block JWT circuit's reference wire count.</summary>
    private const int JwtNineWireCount = 955545;

    /// <summary>The nine-block JWT circuit's reference input count.</summary>
    private const int JwtNineInputCount = 21257;

    /// <summary>The nine-block JWT circuit's reference output count.</summary>
    private const int JwtNineOutputCount = 128;

    /// <summary>The nine-block JWT circuit's reference copy-wire overhead count.</summary>
    private const int JwtNineCopyOverheadCount = 167015;

    /// <summary>The nine-block JWT circuit's reference quad-term count.</summary>
    private const int JwtNineQuadTermCount = 2831884;

    /// <summary>The nine-block JWT circuit's reference eliminated-subexpression count.</summary>
    private const int JwtNineEliminatedSubexpressionCount = 1279204;

    /// <summary>The nine-block JWT circuit's reference not-needed count.</summary>
    private const int JwtNineNotNeededCount = 2404040;

    /// <summary>The Fiat-Shamir transcript seed for the end-to-end gate.</summary>
    private static byte[] JwtTranscriptSeed { get; } = Encoding.ASCII.GetBytes("jwt-fp256-kernel-e2e");

    /// <summary>The curve constants shared by the circuit and the witness generator.</summary>
    private static LongfellowEllipticCurveParameters Curve { get; } = LongfellowEllipticCurveParameters.CreateP256();

    /// <summary>The production Montgomery base field addition delegate (the BigInteger reference delegates are too slow for this circuit's size).</summary>
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


    /// <summary>Pins the kernel-compiled ECDSA verification circuit's telemetry against the reference compiler's.</summary>
    [TestMethod]
    public void TheEcdsaVerifyCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileEcdsaCircuit(NewFastFp256Bundle(), out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(EcdsaDepth, builder.DepthUpperBound, "The ECDSA circuit's depth must match the reference compiler's.");
        Assert.AreEqual(EcdsaWireCount, builder.WireCount, "The ECDSA circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(EcdsaInputCount, builder.InputCount, "The ECDSA circuit's input count must match the reference compiler's.");
        Assert.AreEqual(EcdsaOutputCount, builder.OutputCount, "The ECDSA circuit's output count must match the reference compiler's.");
        Assert.AreEqual(EcdsaCopyOverheadCount, builder.CopyWireOverheadCount, "The ECDSA circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(EcdsaQuadTermCount, builder.QuadTermCount, "The ECDSA circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(EcdsaEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The ECDSA circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(EcdsaNotNeededCount, builder.NotNeededCount, "The ECDSA circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled base64url decoder circuit's telemetry against the reference compiler's, over GF(2^128) as the reference compiles it.</summary>
    [TestMethod]
    public void TheBase64DecoderCircuitTelemetryMatchesTheReferenceCompiler()
    {
        var builder = new LongfellowQuadCircuitBuilder(NewGfBundle().Compiler);
        var backend = new LongfellowCompileLogicBackend(NewGfBundle(), builder);
        var logic = new LongfellowLogic(backend, NewGfBundle());
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[] input = logic.InputVector(LongfellowLogic.BitWidth8);
        var output = new LongfellowBitWire[6];
        decoder.Decode(input, output);
        logic.OutputVector(output, 0);

        _ = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        Assert.AreEqual(Base64Depth, builder.DepthUpperBound, "The decoder circuit's depth must match the reference compiler's.");
        Assert.AreEqual(Base64WireCount, builder.WireCount, "The decoder circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(Base64InputCount, builder.InputCount, "The decoder circuit's input count must match the reference compiler's.");
        Assert.AreEqual(Base64OutputCount, builder.OutputCount, "The decoder circuit's output count must match the reference compiler's.");
        Assert.AreEqual(Base64CopyOverheadCount, builder.CopyWireOverheadCount, "The decoder circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(Base64QuadTermCount, builder.QuadTermCount, "The decoder circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(Base64EliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The decoder circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(Base64NotNeededCount, builder.NotNeededCount, "The decoder circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled seven-block JWT circuit's telemetry against the reference compiler's.</summary>
    [TestMethod]
    public void TheSevenBlockJwtCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileJwtCircuit(NewFastFp256Bundle(), SevenBlocks, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(JwtSevenDepth, builder.DepthUpperBound, "The seven-block JWT circuit's depth must match the reference compiler's.");
        Assert.AreEqual(JwtSevenWireCount, builder.WireCount, "The seven-block JWT circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(JwtSevenInputCount, builder.InputCount, "The seven-block JWT circuit's input count must match the reference compiler's.");
        Assert.AreEqual(JwtSevenOutputCount, builder.OutputCount, "The seven-block JWT circuit's output count must match the reference compiler's.");
        Assert.AreEqual(JwtSevenCopyOverheadCount, builder.CopyWireOverheadCount, "The seven-block JWT circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(JwtSevenQuadTermCount, builder.QuadTermCount, "The seven-block JWT circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(JwtSevenEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The seven-block JWT circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(JwtSevenNotNeededCount, builder.NotNeededCount, "The seven-block JWT circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins the kernel-compiled nine-block JWT circuit's telemetry against the reference compiler's, the second block-count point fixing the per-block scaling.</summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheNineBlockJwtCircuitTelemetryMatchesTheReferenceCompiler()
    {
        _ = CompileJwtCircuit(NewFastFp256Bundle(), NineBlocks, out LongfellowQuadCircuitBuilder builder);

        Assert.AreEqual(JwtNineDepth, builder.DepthUpperBound, "The nine-block JWT circuit's depth must match the reference compiler's.");
        Assert.AreEqual(JwtNineWireCount, builder.WireCount, "The nine-block JWT circuit's wire count must match the reference compiler's.");
        Assert.AreEqual(JwtNineInputCount, builder.InputCount, "The nine-block JWT circuit's input count must match the reference compiler's.");
        Assert.AreEqual(JwtNineOutputCount, builder.OutputCount, "The nine-block JWT circuit's output count must match the reference compiler's.");
        Assert.AreEqual(JwtNineCopyOverheadCount, builder.CopyWireOverheadCount, "The nine-block JWT circuit's copy overhead must match the reference compiler's.");
        Assert.AreEqual(JwtNineQuadTermCount, builder.QuadTermCount, "The nine-block JWT circuit's quad-term count must match the reference compiler's.");
        Assert.AreEqual(JwtNineEliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, "The nine-block JWT circuit's eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(JwtNineNotNeededCount, builder.NotNeededCount, "The nine-block JWT circuit's not-needed count must match the reference compiler's.");
    }


    /// <summary>Pins that the kernel-compiled seven-block JWT statement proves and verifies the reference token end to end over the P-256 base field, that a tampered proof rejects, and that a digest-inconsistent witness is unprovable.</summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheJwtStatementProvesAndVerifiesEndToEnd()
    {
        LongfellowLogicFieldOperations field = NewFastFp256Bundle();
        LongfellowSumcheckCircuit circuit = CompileJwtCircuit(field, SevenBlocks, out _);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, Production16SubFieldBytes);

        byte[] witnessColumn = BuildWitnessColumn(field, circuit, out int eBitsStartWire);

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, parameters, witnessColumn);
        byte[] publicInputs = Fp256PublicInputBytes(circuit, witnessColumn);
        AssertJwtVerifies(circuit, parameters, proof.Bytes, publicInputs, expectedAccept: true);

        //A flipped byte inside the sumcheck segment diverges the challenge stream.
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[DigestSize + 8] ^= 0x01;
        AssertJwtVerifies(circuit, parameters, tamperedProof, publicInputs, expectedAccept: false);

        //Flipping the first digest bit breaks the bit recomposition against the signature's digest.
        byte[] inconsistentColumn = (byte[])witnessColumn.Clone();
        inconsistentColumn[(eBitsStartWire * ScalarSize) + ScalarSize - 1] ^= 0x01;
        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProduceProof(circuit, parameters, inconsistentColumn),
            "A digest-inconsistent JWT witness must be unprovable.");
    }


    /// <summary>
    /// Compiles the reference's <c>make_circuit</c> shape: the statement gadget constructed first,
    /// then the public inputs (issuer key, key-binding digest, one disclosed attribute), the
    /// private boundary, and the witness declaration.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="blocks">The block capacity.</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileJwtCircuit(LongfellowLogicFieldOperations field, int blocks, out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowJwtCircuit(logic, Curve, blocks);

        int pkX = logic.InputElement();
        int pkY = logic.InputElement();
        int e2 = logic.InputElement();
        var attributes = new LongfellowJwtOpenedAttributeWires[AttributeCount];
        for(int i = 0; i < AttributeCount; i++)
        {
            attributes[i] = LongfellowJwtOpenedAttributeWires.Input(logic);
        }

        builder.PrivateInput();
        LongfellowJwtWitnessWires witness = circuit.InputWitness(AttributeCount);

        circuit.AssertJwtAttributes(pkX, pkY, e2, attributes, witness);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Compiles the reference's <c>ECDSA.Size</c> shape: the verification gadget constructed first,
    /// then the three element inputs and the advice declaration, with no private boundary.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="builder">Receives the builder for telemetry assertions.</param>
    /// <returns>The compiled circuit.</returns>
    private static LongfellowSumcheckCircuit CompileEcdsaCircuit(LongfellowLogicFieldOperations field, out LongfellowQuadCircuitBuilder builder)
    {
        builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowEcdsaVerifyCircuit(logic, Curve);

        int pkX = logic.InputElement();
        int pkY = logic.InputElement();
        int e = logic.InputElement();
        LongfellowEcdsaVerifyWitnessWires witness = LongfellowEcdsaVerifyWitnessWires.Input(logic, Curve.ScalarBitCount);

        verify.VerifySignature3(pkX, pkY, e, witness);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>
    /// Builds the witness column for the reference token: the constant one, the public issuer key,
    /// key-binding digest and disclosed attribute, then the generator's private witness region.
    /// </summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="circuit">The compiled circuit declaring the input count.</param>
    /// <param name="eBitsStartWire">Receives the digest-bit region's first wire, for the unprovability probe.</param>
    /// <returns>The witness column, one canonical scalar per declared input wire.</returns>
    private static byte[] BuildWitnessColumn(LongfellowLogicFieldOperations field, LongfellowSumcheckCircuit circuit, out int eBitsStartWire)
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;
        byte[] token = Encoding.ASCII.GetBytes(vector.Token);
        byte[] pkX = ParseScalar(vector.PkX);
        byte[] pkY = ParseScalar(vector.PkY);
        byte[] e2 = ParseScalar(vector.E2);
        var attribute = LongfellowJwtOpenedAttribute.FromStrings("given_name", "Erika");

        var generator = new LongfellowJwtWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve, SevenBlocks);
        Assert.IsTrue(generator.ComputeWitness(token, pkX, pkY, [attribute]), "The reference token must produce a witness at seven blocks.");

        byte[] column = new byte[circuit.InputCount * ScalarSize];
        field.Compiler.One.Span.CopyTo(column.AsSpan(0, ScalarSize));
        int cursor = 1;
        pkX.CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;
        pkY.CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;
        e2.CopyTo(column.AsSpan(cursor * ScalarSize, ScalarSize));
        cursor++;
        LongfellowJwtWitness.FillAttribute(field, attribute, column, ref cursor);

        //The digest-bit region sits after the three witness scalars and both advice bundles and the
        //preimage bytes; the layout mirrors the declaration order.
        int witnessStart = cursor;
        var probeGenerator = new LongfellowEcdsaVerifyWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve);
        eBitsStartWire = witnessStart + 3 + (2 * probeGenerator.ElementCount) + (SevenBlocks * 64 * LongfellowLogic.BitWidth8);

        int witnessElements = generator.GetElementCount(AttributeCount);
        generator.FillWitness(column.AsSpan(witnessStart * ScalarSize, witnessElements * ScalarSize));
        Assert.AreEqual(circuit.InputCount, witnessStart + witnessElements, "The column layout must cover exactly the declared input wires.");

        return column;
    }


    /// <summary>Produces a ZK proof over the compiled circuit with the production Montgomery field delegates.</summary>
    /// <param name="circuit">The compiled circuit to prove.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="witnessColumn">The witness column.</param>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    private static LongfellowZkProofEnvelope ProduceProof(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn)
    {
        Fp256RealFft fft = NewFastFft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, FastAdd, FastSubtract, FastMultiply, FastInvert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        using LongfellowTranscript transcript = NewFp256Transcript(JwtTranscriptSeed);
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
    /// <param name="expectedAccept">Whether the proof is expected to be accepted.</param>
    private static void AssertJwtVerifies(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, ReadOnlySpan<byte> proof, byte[] publicInputs, bool expectedAccept)
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

        using LongfellowTranscript transcript = NewFp256Transcript(JwtTranscriptSeed);
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
