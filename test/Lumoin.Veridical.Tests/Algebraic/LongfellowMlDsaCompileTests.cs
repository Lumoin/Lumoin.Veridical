using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Buffers;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The compile-half gates for the ML-DSA stack: every reference sub-circuit shape and the full
/// signature-verification statement, pinned counter for counter against the reference compiler
/// over the sextic extension of the FIPS 204 prime, at both wired parameter sets.
/// </summary>
/// <remarks>
/// <para>
/// Every pinned figure was regenerated from the pinned reference commit by running its own gtests
/// (<c>MlDsaCircuitTest.*</c>) in the longfellow-ref Docker oracle. The shapes mirror
/// <c>ml_dsa_circuit_test.cc</c> exactly: the public boundary, the private-input marker, the wire
/// bundle declaration order, and the commitment sponge witness count of seven blocks.
/// </para>
/// <para>
/// The sextic-extension statements are compile-pinned here, vector-checked in evaluation
/// (<c>LongfellowMlDsaCircuitTests</c>), and proved end to end in zero knowledge through the
/// shipped stack's <c>LongfellowFp24SexticEncoding</c> profile at the reference's own Ligero
/// parameters (rate 4, 128 opened columns — the pair the reference annotates at 86-plus bits of
/// statistical soundness; the sextic field size, about 2^138, likewise caps the field-side terms
/// below the 128-bit headline of the NIST P-256 statements).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowMlDsaCompileTests
{
    /// <summary>One shape's reference compiler telemetry, as the Docker oracle's <c>dump_info</c> reports it.</summary>
    /// <param name="Depth">The depth upper bound.</param>
    /// <param name="WireCount">The wire count.</param>
    /// <param name="InputCount">The input count.</param>
    /// <param name="OutputCount">The output count.</param>
    /// <param name="CopyOverheadCount">The copy-wire overhead count.</param>
    /// <param name="QuadTermCount">The quad-term count.</param>
    /// <param name="EliminatedSubexpressionCount">The eliminated-subexpression count.</param>
    /// <param name="NotNeededCount">The not-needed count.</param>
    private sealed record CounterPin(
        int Depth,
        int WireCount,
        int InputCount,
        int OutputCount,
        int CopyOverheadCount,
        int QuadTermCount,
        int EliminatedSubexpressionCount,
        int NotNeededCount);

    /// <summary>The sextic extension's subfield width, selecting the three-way SHAKE re-anchoring split.</summary>
    private const int SexticSubfieldBits = 32;

    /// <summary>The commitment sponge witness count of the pinned statement shapes (the reference's <c>kCPrimeTildeBlocks</c>, seven for both sets).</summary>
    private const int PinnedCommitmentBlockCount = 7;

    /// <summary>The message representative's byte count.</summary>
    private const int MuBytes = 64;

    /// <summary>The reference's ML-DSA ZK inverse rate (<c>ml_dsa_circuit_test.cc</c>'s literal <c>4</c>).</summary>
    private const int MlDsaInverseRate = 4;

    /// <summary>The reference's ML-DSA ZK opened-column count (<c>ml_dsa_circuit_test.cc</c>'s literal <c>128</c>; the reference annotates the rate-4/128 pair at 86-plus bits of statistical soundness).</summary>
    private const int MlDsaOpenedColumnCount = 128;

    /// <summary>The ML-DSA end-to-end gate's Fiat-Shamir seed.</summary>
    private static byte[] MlDsaTranscriptSeed { get; } = System.Text.Encoding.ASCII.GetBytes("ml-dsa-sextic-e2e");

    /// <summary>The reference telemetry of <c>ml_dsa_44_use_hint_single</c>.</summary>
    private static CounterPin MlDsa44UseHintSinglePin { get; } = new(6, 193, 36, 2, 32, 278, 50, 258);

    /// <summary>The reference telemetry of <c>ml_dsa_65_use_hint_single</c>.</summary>
    private static CounterPin MlDsa65UseHintSinglePin { get; } = new(6, 159, 33, 2, 21, 226, 37, 223);

    /// <summary>The reference telemetry of <c>ml_dsa_44_infty_norm</c>.</summary>
    private static CounterPin MlDsa44InfinityNormPin { get; } = new(6, 97285, 20481, 1024, 13316, 129028, 1023, 121860);

    /// <summary>The reference telemetry of <c>ml_dsa_65_infty_norm</c>.</summary>
    private static CounterPin MlDsa65InfinityNormPin { get; } = new(6, 121604, 26881, 1280, 12803, 154883, 1279, 149764);

    /// <summary>The reference telemetry of <c>ml_dsa_44_w_prime_approx</c>.</summary>
    private static CounterPin MlDsa44WPrimeApproxPin { get; } = new(9, 382517, 128272, 1280, 8967, 1692980, 1023, 397360);

    /// <summary>The reference telemetry of <c>ml_dsa_65_w_prime_approx</c>.</summary>
    private static CounterPin MlDsa65WPrimeApproxPin { get; } = new(9, 458042, 156263, 1536, 10759, 2812729, 1535, 482613);

    /// <summary>The reference telemetry of <c>ml_dsa_44_use_hint</c>.</summary>
    private static CounterPin MlDsa44UseHintPin { get; } = new(6, 313408, 77840, 2048, 28677, 399951, 52225, 375380);

    /// <summary>The reference telemetry of <c>ml_dsa_65_use_hint</c>.</summary>
    private static CounterPin MlDsa65UseHintPin { get; } = new(6, 388157, 101735, 3072, 26117, 491073, 58369, 480330);

    /// <summary>The reference telemetry of <c>ml_dsa_44_sample_in_ball</c>.</summary>
    private static CounterPin MlDsa44SampleInBallPin { get; } = new(38, 654308, 14089, 225, 227472, 1148470, 1081477, 806267);

    /// <summary>The reference telemetry of <c>ml_dsa_65_sample_in_ball</c>.</summary>
    private static CounterPin MlDsa65SampleInBallPin { get; } = new(38, 763687, 18017, 225, 265392, 1353125, 1365819, 959214);

    /// <summary>The reference telemetry of <c>ml_dsa_44_ctilde</c>.</summary>
    private static CounterPin MlDsa44CtildePin { get; } = new(39, 2594443, 123152, 450, 884995, 3921622, 4199, 2681680);

    /// <summary>The reference telemetry of <c>ml_dsa_65_ctilde</c>.</summary>
    private static CounterPin MlDsa65CtildePin { get; } = new(39, 2661264, 147047, 450, 884995, 3986139, 4199, 2746581);

    /// <summary>The reference telemetry of <c>ml_dsa_44_valid_signature_on_mu</c>.</summary>
    private static CounterPin MlDsa44ValidSignaturePin { get; } = new(39, 3382817, 128784, 450, 1163376, 6659791, 1139951, 3752755);

    /// <summary>The reference telemetry of <c>ml_dsa_65_valid_signature_on_mu</c>.</summary>
    private static CounterPin MlDsa65ValidSignaturePin { get; } = new(39, 3571545, 156775, 450, 1200016, 8009000, 1431205, 4028704);


    /// <summary>Pins the single-coefficient UseHint shape's telemetry against the reference compiler's, at both parameter sets.</summary>
    [TestMethod]
    public void TheUseHintSingleCircuitTelemetryMatchesTheReferenceCompiler()
    {
        AssertPinned(CompileUseHintSingle(LongfellowMlDsaParameters.MlDsa44), MlDsa44UseHintSinglePin, "ml_dsa_44_use_hint_single");
        AssertPinned(CompileUseHintSingle(LongfellowMlDsaParameters.MlDsa65), MlDsa65UseHintSinglePin, "ml_dsa_65_use_hint_single");
    }


    /// <summary>Pins the infinity-norm shape's telemetry against the reference compiler's, at both parameter sets.</summary>
    [TestMethod]
    public void TheInfinityNormCircuitTelemetryMatchesTheReferenceCompiler()
    {
        AssertPinned(CompileInfinityNorm(LongfellowMlDsaParameters.MlDsa44), MlDsa44InfinityNormPin, "ml_dsa_44_infty_norm");
        AssertPinned(CompileInfinityNorm(LongfellowMlDsaParameters.MlDsa65), MlDsa65InfinityNormPin, "ml_dsa_65_infty_norm");
    }


    /// <summary>Pins the commitment-recomputation shape's telemetry against the reference compiler's, at both parameter sets.</summary>
    [TestMethod]
    public void TheWPrimeApproxCircuitTelemetryMatchesTheReferenceCompiler()
    {
        AssertPinned(CompileWPrimeApprox(LongfellowMlDsaParameters.MlDsa44), MlDsa44WPrimeApproxPin, "ml_dsa_44_w_prime_approx");
        AssertPinned(CompileWPrimeApprox(LongfellowMlDsaParameters.MlDsa65), MlDsa65WPrimeApproxPin, "ml_dsa_65_w_prime_approx");
    }


    /// <summary>Pins the full UseHint shape's telemetry against the reference compiler's, at both parameter sets.</summary>
    [TestMethod]
    public void TheUseHintCircuitTelemetryMatchesTheReferenceCompiler()
    {
        AssertPinned(CompileUseHint(LongfellowMlDsaParameters.MlDsa44), MlDsa44UseHintPin, "ml_dsa_44_use_hint");
        AssertPinned(CompileUseHint(LongfellowMlDsaParameters.MlDsa65), MlDsa65UseHintPin, "ml_dsa_65_use_hint");
    }


    /// <summary>Pins the SampleInBall shape's telemetry against the reference compiler's, at both parameter sets.</summary>
    [TestMethod]
    public void TheSampleInBallCircuitTelemetryMatchesTheReferenceCompiler()
    {
        AssertPinned(CompileSampleInBall(LongfellowMlDsaParameters.MlDsa44), MlDsa44SampleInBallPin, "ml_dsa_44_sample_in_ball");
        AssertPinned(CompileSampleInBall(LongfellowMlDsaParameters.MlDsa65), MlDsa65SampleInBallPin, "ml_dsa_65_sample_in_ball");
    }


    /// <summary>Pins the commitment-hash shape's telemetry against the reference compiler's, at both parameter sets.</summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheCtildeCircuitTelemetryMatchesTheReferenceCompiler()
    {
        AssertPinned(CompileCtilde(LongfellowMlDsaParameters.MlDsa44), MlDsa44CtildePin, "ml_dsa_44_ctilde");
        AssertPinned(CompileCtilde(LongfellowMlDsaParameters.MlDsa65), MlDsa65CtildePin, "ml_dsa_65_ctilde");
    }


    /// <summary>
    /// Pins the full signature-verification statement's telemetry against the reference compiler's
    /// at both parameter sets, and asserts the witness generator's column layout covers exactly the
    /// statement's declared input wires — the constant one, the full witness fill, and the trailing
    /// message representative bytes, with the public region a strict prefix.
    /// </summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheValidSignatureCircuitTelemetryMatchesTheReferenceCompiler()
    {
        AssertPinned(CompileValidSignature(LongfellowMlDsaParameters.MlDsa44), MlDsa44ValidSignaturePin, "ml_dsa_44_valid_signature_on_mu");
        AssertPinned(CompileValidSignature(LongfellowMlDsaParameters.MlDsa65), MlDsa65ValidSignaturePin, "ml_dsa_65_valid_signature_on_mu");

        AssertColumnCovers(LongfellowMlDsaParameters.MlDsa44, MlDsa44ValidSignaturePin, LongfellowMlDsa44ExampleVectors.SignatureExamples[0], "ml_dsa_44");
        AssertColumnCovers(LongfellowMlDsaParameters.MlDsa65, MlDsa65ValidSignaturePin, LongfellowMlDsa65ExampleVectors.SignatureExamples[0], "ml_dsa_65");
    }


    /// <summary>
    /// Pins that the full kernel-compiled ML-DSA signature-verification statement proves and verifies
    /// in zero knowledge end to end through the shipped stack at BOTH parameter sets — the analogue of
    /// the reference's <c>AssertValidSignatureOnMu</c> ZK test at its own rate-4/128-column parameters —
    /// with the tamper-rejection and corrupted-witness-unprovable probes run at the 44 set (the 65 set's
    /// rejection lattice is the same code path; its accepting round trip is what this gate adds).
    /// </summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheValidSignatureStatementProvesAndVerifiesEndToEnd()
    {
        AssertStatementRoundTrips(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44ExampleVectors.SignatureExamples[0], probeRejections: true, "ml_dsa_44");
        AssertStatementRoundTrips(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65ExampleVectors.SignatureExamples[0], probeRejections: false, "ml_dsa_65");
    }


    /// <summary>Runs one parameter set's full-statement ZK round trip, optionally with the rejection probes.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="example">The signature example to prove.</param>
    /// <param name="probeRejections">Whether to run the tamper-rejection and corrupted-witness probes.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertStatementRoundTrips(LongfellowMlDsaParameters parameters, LongfellowMlDsaSignatureExample example, bool probeRejections, string setName)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        LongfellowSumcheckCircuit circuit = CompileValidSignatureStatement(parameters, field);

        int columnBytes = circuit.InputCount * Scalar.SizeBytes;
        using IMemoryOwner<byte> columnOwner = BuildStatementColumn(field, parameters, example, circuit, out int witnessStartWire);
        Span<byte> column = columnOwner.Memory.Span[..columnBytes];

        LongfellowLigeroParameters ligeroParameters = LongfellowZkVerifier.DeriveParameters(
            circuit, MlDsaInverseRate, MlDsaOpenedColumnCount, Fp24SexticElementBytes, Fp24SexticSubFieldBytes);
        using LongfellowZkProofEnvelope proof = ProduceFp24SexticProof(circuit, ligeroParameters, column, MlDsaTranscriptSeed);

        int publicInputBytes = circuit.PublicInputCount * Fp24SexticElementBytes;
        using IMemoryOwner<byte> publicOwner = BaseMemoryPool.Shared.Rent(publicInputBytes);
        Span<byte> publicInputs = publicOwner.Memory.Span[..publicInputBytes];
        FillFp24SexticPublicInputs(circuit, column, publicInputs);
        AssertFp24SexticVerifies(circuit, ligeroParameters, proof.Bytes, publicInputs, MlDsaTranscriptSeed, expectedAccept: true);

        if(!probeRejections)
        {
            column.Clear();

            return;
        }

        using IMemoryOwner<byte> tamperedOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[^1] ^= 0x01;
        AssertFp24SexticVerifies(circuit, ligeroParameters, tamperedProof, publicInputs, MlDsaTranscriptSeed, expectedAccept: false);

        //A corrupted first opened-columns run length drives the sextic run-length reader's
        //untrusted-length guard: the parse must fail gracefully, never over-read.
        proof.Bytes.CopyTo(tamperedProof);
        TamperFirstOpenedColumnsRunLength(circuit, ligeroParameters, tamperedProof);
        AssertFp24SexticVerifies(circuit, ligeroParameters, tamperedProof, publicInputs, MlDsaTranscriptSeed, expectedAccept: false);

        //Flipping the first private witness element in place breaks the statement's assertion lattice;
        //the accepting proof and the public inputs were already derived, so the column is free to mutate.
        Span<byte> witnessElement = column.Slice(witnessStartWire * Scalar.SizeBytes, Scalar.SizeBytes);
        ReadOnlyMemory<byte> flipped = LongfellowCompilerFieldOperations.ElementIsZero(witnessElement) ? field.Compiler.One : field.Compiler.Zero;
        flipped.Span.CopyTo(witnessElement);
        Memory<byte> corrupted = columnOwner.Memory[..columnBytes];
        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProduceFp24SexticProof(circuit, ligeroParameters, corrupted.Span, MlDsaTranscriptSeed),
            $"A corrupted {setName} witness element must be unprovable.");
        column.Clear();
    }


    /// <summary>Builds one parameter set's full-statement witness column into pooled memory: the constant one, the full witness fill, and the trailing message-representative bits.</summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="example">The signature example to compute the witness from.</param>
    /// <param name="circuit">The compiled statement declaring the input count.</param>
    /// <param name="witnessStartWire">Receives the first private wire (the public boundary), for the corruption probe.</param>
    /// <returns>The pooled witness column; the caller disposes it.</returns>
    private static IMemoryOwner<byte> BuildStatementColumn(LongfellowLogicFieldOperations field, LongfellowMlDsaParameters parameters, LongfellowMlDsaSignatureExample example, LongfellowSumcheckCircuit circuit, out int witnessStartWire)
    {
        LongfellowMlDsaWitness? witness = LongfellowMlDsaWitness.Compute(
            parameters,
            Convert.FromHexString(example.PublicKey),
            Convert.FromHexString(example.Signature),
            Convert.FromHexString(example.Message),
            Convert.FromHexString(example.Context));
        Assert.IsNotNull(witness, "The example witness must compute.");

        IMemoryOwner<byte> columnOwner = BaseMemoryPool.Shared.Rent(circuit.InputCount * Scalar.SizeBytes);
        Span<byte> column = columnOwner.Memory.Span[..(circuit.InputCount * Scalar.SizeBytes)];
        column.Clear();
        field.Compiler.One.Span.CopyTo(column[..Scalar.SizeBytes]);
        int cursor = 1;
        witness.FillPublicKey(field, column, ref cursor);
        witnessStartWire = cursor;

        cursor = 1;
        witness.FillWitness(field, column, ref cursor);
        for(int i = 0; i < witness.Mu.Length; i++)
        {
            for(int bit = 0; bit < LongfellowLogic.BitWidth8; bit++)
            {
                ReadOnlyMemory<byte> element = ((witness.Mu[i] >> bit) & 1) != 0 ? field.Compiler.One : field.Compiler.Zero;
                element.Span.CopyTo(column.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
                cursor++;
            }
        }

        Assert.AreEqual(circuit.InputCount, cursor, "The column layout must cover exactly the statement's declared input wires.");

        return columnOwner;
    }


    /// <summary>Asserts one parameter set's witness column layout against its statement pin's input count.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="pin">The statement's reference telemetry carrying the declared input count.</param>
    /// <param name="example">The signature example to compute the witness from.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertColumnCovers(LongfellowMlDsaParameters parameters, CounterPin pin, LongfellowMlDsaSignatureExample example, string setName)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        LongfellowMlDsaWitness? witness = LongfellowMlDsaWitness.Compute(
            parameters,
            Convert.FromHexString(example.PublicKey),
            Convert.FromHexString(example.Signature),
            Convert.FromHexString(example.Message),
            Convert.FromHexString(example.Context));
        Assert.IsNotNull(witness, $"The {setName} example witness must compute.");

        var column = new byte[pin.InputCount * Scalar.SizeBytes];
        field.Compiler.One.Span.CopyTo(column.AsSpan(0, Scalar.SizeBytes));
        int cursor = 1;
        witness.FillPublicKey(field, column, ref cursor);
        int publicBoundary = cursor;
        Assert.IsLessThan(pin.InputCount, publicBoundary, $"The {setName} public region must be a strict prefix of the column.");

        cursor = 1;
        witness.FillWitness(field, column, ref cursor);
        for(int i = 0; i < witness.Mu.Length; i++)
        {
            for(int bit = 0; bit < LongfellowLogic.BitWidth8; bit++)
            {
                ReadOnlyMemory<byte> element = ((witness.Mu[i] >> bit) & 1) != 0 ? field.Compiler.One : field.Compiler.Zero;
                element.Span.CopyTo(column.AsSpan(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
                cursor++;
            }
        }

        Assert.AreEqual(pin.InputCount, cursor, $"The {setName} column layout must cover exactly the statement's declared input wires.");
    }


    /// <summary>Asserts one compiled shape's telemetry against its reference pin.</summary>
    /// <param name="builder">The builder that compiled the shape.</param>
    /// <param name="pin">The reference telemetry.</param>
    /// <param name="shape">The reference's dump label, for the failure messages.</param>
    private static void AssertPinned(LongfellowQuadCircuitBuilder builder, CounterPin pin, string shape)
    {
        Assert.AreEqual(pin.Depth, builder.DepthUpperBound, $"The {shape} depth must match the reference compiler's.");
        Assert.AreEqual(pin.WireCount, builder.WireCount, $"The {shape} wire count must match the reference compiler's.");
        Assert.AreEqual(pin.InputCount, builder.InputCount, $"The {shape} input count must match the reference compiler's.");
        Assert.AreEqual(pin.OutputCount, builder.OutputCount, $"The {shape} output count must match the reference compiler's.");
        Assert.AreEqual(pin.CopyOverheadCount, builder.CopyWireOverheadCount, $"The {shape} copy overhead must match the reference compiler's.");
        Assert.AreEqual(pin.QuadTermCount, builder.QuadTermCount, $"The {shape} quad-term count must match the reference compiler's.");
        Assert.AreEqual(pin.EliminatedSubexpressionCount, builder.EliminatedSubexpressionCount, $"The {shape} eliminated-subexpression count must match the reference compiler's.");
        Assert.AreEqual(pin.NotNeededCount, builder.NotNeededCount, $"The {shape} not-needed count must match the reference compiler's.");
    }


    /// <summary>Compiles the reference's <c>make_ml_dsa_use_hint_single_circuit</c> shape.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder CompileUseHintSingle(LongfellowMlDsaParameters parameters)
    {
        return Compile(parameters, (logic, builder, verify) =>
        {
            builder.PrivateInput();
            int hintWire = logic.InputElement();
            int rWire = logic.InputElement();
            int rawHighWire = logic.InputElement();
            LongfellowBitWire[] rawHighBits = logic.InputVector(parameters.HighBitsWidth);
            LongfellowBitWire[] hintRemainderBits = logic.InputVector(parameters.LowBitsWidth + 1);
            int hintedHighWire = logic.InputElement();
            LongfellowBitWire[] hintedHighBits = logic.InputVector(parameters.HighBitsWidth);

            verify.AssertUseHintSingle(hintWire, rWire, rawHighWire, rawHighBits, hintRemainderBits, hintedHighWire, hintedHighBits);
        });
    }


    /// <summary>Compiles the reference's <c>make_ml_dsa_infty_norm_circuit</c> shape.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder CompileInfinityNorm(LongfellowMlDsaParameters parameters)
    {
        return Compile(parameters, (logic, builder, verify) =>
        {
            builder.PrivateInput();
            var z = new LongfellowMlDsaPolynomialWires[parameters.ColumnCount];
            for(int i = 0; i < parameters.ColumnCount; i++)
            {
                z[i] = new LongfellowMlDsaPolynomialWires();
                z[i].Input(logic);
            }

            var zBits = new LongfellowBitWire[parameters.ColumnCount][][];
            for(int i = 0; i < parameters.ColumnCount; i++)
            {
                zBits[i] = new LongfellowBitWire[LongfellowMlDsaParameters.CoefficientCount][];
                for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
                {
                    zBits[i][j] = logic.InputVector(parameters.ResponseBitWidth);
                }
            }

            verify.AssertInfinityNorm(z, zBits, parameters.MaskingBound - parameters.RejectionBound);
        });
    }


    /// <summary>Compiles the reference's <c>make_ml_dsa_w_prime_approx_circuit</c> shape.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder CompileWPrimeApprox(LongfellowMlDsaParameters parameters)
    {
        return Compile(parameters, (logic, builder, verify) =>
        {
            var publicKey = new LongfellowMlDsaPublicKeyWires(parameters);
            publicKey.Input(logic);

            builder.PrivateInput();
            var signature = new LongfellowMlDsaSignatureWires(parameters);
            signature.Input(logic);

            var witness = new LongfellowMlDsaWitnessWires(parameters, PinnedCommitmentBlockCount);
            witness.Input(logic);

            verify.AssertWPrimeApprox(publicKey, signature, witness);
        });
    }


    /// <summary>Compiles the reference's <c>make_ml_dsa_use_hint_circuit</c> shape, whose witness bundle carries no commitment sponge witnesses.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder CompileUseHint(LongfellowMlDsaParameters parameters)
    {
        return Compile(parameters, (logic, builder, verify) =>
        {
            builder.PrivateInput();
            var signature = new LongfellowMlDsaSignatureWires(parameters);
            signature.Input(logic);

            var witness = new LongfellowMlDsaWitnessWires(parameters, commitmentBlockCount: 0);
            witness.Input(logic);

            verify.AssertUseHint(
                signature.Hints,
                witness.WPrimeApprox,
                witness.W1,
                witness.W1Bits,
                witness.HintAuxBits,
                witness.WPrime1,
                witness.WPrime1Bits,
                witness.HintSumBits);
        });
    }


    /// <summary>Compiles the reference's <c>make_ml_dsa_sampleinball_circuit</c> shape.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder CompileSampleInBall(LongfellowMlDsaParameters parameters)
    {
        return Compile(parameters, (logic, builder, verify) =>
        {
            var rho = new LongfellowBitWire[parameters.CommitmentBytes][];
            for(int i = 0; i < parameters.CommitmentBytes; i++)
            {
                rho[i] = logic.InputVector(LongfellowLogic.BitWidth8);
            }

            builder.PrivateInput();
            var challenge = new LongfellowMlDsaPolynomialWires();
            challenge.Input(logic);

            var witness = new LongfellowMlDsaSampleInBallWitnessWires(parameters);
            witness.Input(logic);

            verify.AssertSampleInBall(rho, challenge, witness);
        });
    }


    /// <summary>Compiles the reference's <c>make_ml_dsa_ctilde_circuit</c> shape.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder CompileCtilde(LongfellowMlDsaParameters parameters)
    {
        return Compile(parameters, (logic, builder, verify) =>
        {
            builder.PrivateInput();
            var signature = new LongfellowMlDsaSignatureWires(parameters);
            signature.Input(logic);

            var witness = new LongfellowMlDsaWitnessWires(parameters, PinnedCommitmentBlockCount);
            witness.Input(logic);

            var mu = new LongfellowBitWire[MuBytes][];
            for(int i = 0; i < MuBytes; i++)
            {
                mu[i] = logic.InputVector(LongfellowLogic.BitWidth8);
            }

            verify.AssertCtilde(mu, witness.W1Tilde, witness.CommitmentBlockWitnesses, signature.CommitmentHash);
        });
    }


    /// <summary>Compiles the reference's <c>make_ml_dsa_circuit</c> statement shape.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder CompileValidSignature(LongfellowMlDsaParameters parameters) =>
        Compile(parameters, DefineValidSignature(parameters));


    /// <summary>The full statement's shape definition, shared by the telemetry pin and the ZK end-to-end: pk public, then the private boundary, then signature, witness and message-representative inputs, then the assertion.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <returns>The shape definition.</returns>
    private static Action<LongfellowLogic, LongfellowQuadCircuitBuilder, LongfellowMlDsaVerifyCircuit> DefineValidSignature(LongfellowMlDsaParameters parameters) =>
        (logic, builder, verify) =>
        {
            var publicKey = new LongfellowMlDsaPublicKeyWires(parameters);
            publicKey.Input(logic);

            builder.PrivateInput();
            var signature = new LongfellowMlDsaSignatureWires(parameters);
            signature.Input(logic);

            var witness = new LongfellowMlDsaWitnessWires(parameters, PinnedCommitmentBlockCount);
            witness.Input(logic);

            var mu = new LongfellowBitWire[MuBytes][];
            for(int i = 0; i < MuBytes; i++)
            {
                mu[i] = logic.InputVector(LongfellowLogic.BitWidth8);
            }

            verify.AssertValidSignatureOnMu(publicKey, signature, mu, witness);
        };


    /// <summary>Compiles the full statement and returns the circuit itself, for the ZK end-to-end.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="field">The field bundle to compile over.</param>
    /// <returns>The compiled statement circuit.</returns>
    private static LongfellowSumcheckCircuit CompileValidSignatureStatement(LongfellowMlDsaParameters parameters, LongfellowLogicFieldOperations field)
    {
        var builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);
        DefineValidSignature(parameters)(logic, builder, verify);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>Builds one shape through the compile backend, mirroring the reference's <c>build_ml_dsa_circuit</c> helper.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="define">The shape definition: inputs, the private boundary, and the assertion.</param>
    /// <returns>The builder, for telemetry assertions.</returns>
    private static LongfellowQuadCircuitBuilder Compile(
        LongfellowMlDsaParameters parameters,
        Action<LongfellowLogic, LongfellowQuadCircuitBuilder, LongfellowMlDsaVerifyCircuit> define)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

        define(logic, builder, verify);

        _ = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        return builder;
    }


    /// <summary>Builds the sextic-extension field bundle over the backend delegates.</summary>
    /// <returns>The bundle.</returns>
    private static LongfellowLogicFieldOperations NewFp24SexticBundle()
    {
        var minusOne = new byte[Scalar.SizeBytes];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(minusOne.AsSpan(Scalar.SizeBytes - 4, 4), Fp24SexticBackend.Modulus - 1);

        return LongfellowLogicFieldOperations.CreateFp24Sextic(
            Fp24SexticBackend.GetAdd(),
            Fp24SexticBackend.GetSubtract(),
            Fp24SexticBackend.GetMultiply(),
            Fp24SexticBackend.GetInvert(),
            minusOne);
    }
}
