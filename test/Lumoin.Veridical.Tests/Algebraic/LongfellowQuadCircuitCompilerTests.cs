using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the in-house Longfellow circuit compiler (the QuadCircuit kernel): the DAG builder,
/// the layer scheduler and the structural circuit id, compiled directly into the in-memory
/// <see cref="LongfellowSumcheckCircuit"/> the ZK stack consumes.
/// </summary>
/// <remarks>
/// <para>
/// The headline gate compiles the C.8 anchor's statement — the field-satisfiable relation
/// <c>w == (x + y)·(x + z)·x</c> over GF(2^128), x public, y/z/w private — through the kernel and
/// pins the result against the reference compiler's dump (zk-anchor-output.txt): the circuit shape,
/// every canonicalized quad corner in order, and the exact 32-byte structural id. The id is
/// computed by the reference's <c>circuit_id</c> over the in-memory structure, so a byte-for-byte
/// match pins the whole pipeline — the algebraic simplifier, dead-node elimination, copy wires,
/// canonical wire-id assignment, the Morton corner order and the id serialization — against the
/// reference compiler without any circuit blob.
/// </para>
/// <para>
/// The end-to-end gates then drive the compiled circuit through the real ZK prover and verifier
/// under the anchor's fixed seed, witness and randomness: the proof envelope must be byte-identical
/// to the reference's 1864-byte anchor proof, proofs must cross-verify between the compiled circuit
/// and the anchor-built circuit, and an unsatisfying witness must be unprovable.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowQuadCircuitCompilerTests
{
    private const string ZkDumpRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    private const int ElementBytes = 16;

    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkDumpRelativePath);


    [TestMethod]
    public void TheCompiledCircuitMatchesTheReferenceCompilerShape()
    {
        LongfellowQuadCircuitBuilder builder = BuildAnchorStatement(out LongfellowSumcheckCircuit circuit);

        Assert.AreEqual(Anchor("nv"), circuit.OutputCount, "The output count must match the reference compiler's nv.");
        Assert.AreEqual(Anchor("logv"), circuit.OutputLogCount, "The output binding rounds must match logv.");
        Assert.AreEqual(Anchor("nc"), circuit.CopyCount, "The copy count must match nc.");
        Assert.AreEqual(Anchor("logc"), circuit.CopyRounds, "The copy binding rounds must match logc.");
        Assert.AreEqual(Anchor("nl"), circuit.LayerCount, "The layer count must match nl.");
        Assert.AreEqual(Anchor("ninputs"), circuit.InputCount, "The input count must match ninputs.");
        Assert.AreEqual(Anchor("npub_in"), circuit.PublicInputCount, "The public input count must match npub_in.");
        Assert.AreEqual(Anchor("subfield_boundary"), builder.SubfieldBoundary, "The subfield boundary must match the reference's.");

        for(int i = 0; i < circuit.LayerCount; i++)
        {
            Assert.AreEqual(Anchor($"layer{i}_nw"), circuit.Layers[i].InputCount, $"Layer {i}'s input count must match nw.");
            Assert.AreEqual(Anchor($"layer{i}_logw"), circuit.Layers[i].HandRounds, $"Layer {i}'s hand rounds must match logw.");
            Assert.AreEqual(Anchor($"layer{i}_nterms"), circuit.Layers[i].TermCount, $"Layer {i}'s term count must match nterms.");
        }
    }


    [TestMethod]
    public void TheCompiledCornersMatchTheReferenceCompilerTermForTerm()
    {
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit circuit);

        for(int i = 0; i < circuit.LayerCount; i++)
        {
            LongfellowSumcheckQuadTerm[] corners = circuit.Layers[i].QuadTerms;
            for(int t = 0; t < corners.Length; t++)
            {
                Assert.AreEqual(Anchor($"L{i}_t{t}_g"), corners[t].GateIndex, $"Corner L{i} t{t}'s gate index must match.");
                Assert.AreEqual(Anchor($"L{i}_t{t}_h0"), corners[t].LeftIndex, $"Corner L{i} t{t}'s left hand must match.");
                Assert.AreEqual(Anchor($"L{i}_t{t}_h1"), corners[t].RightIndex, $"Corner L{i} t{t}'s right hand must match.");

                byte[] expected = ParseElement(Anchors[$"L{i}_t{t}_v"]);
                Assert.IsTrue(corners[t].Coefficient.Span.SequenceEqual(expected), $"Corner L{i} t{t}'s coefficient must match.");
            }
        }
    }


    [TestMethod]
    public void TheCompiledCircuitIdMatchesTheReferenceCompilerByteForByte()
    {
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit circuit);

        byte[] expected = Convert.FromHexString(Anchors["id"]);
        Assert.IsTrue(circuit.Id.Span.SequenceEqual(expected), "The structural circuit id must match the reference compiler's id byte for byte.");
    }


    [TestMethod]
    public void AProofOverTheCompiledCircuitIsByteIdenticalToTheAnchorProof()
    {
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit circuit);
        byte[] witnessColumn = BuildAnchorWitnessColumn(circuit);

        using LongfellowZkProofEnvelope proof = ProduceGfProof(circuit, witnessColumn, TranscriptSeed);

        byte[] expected = Convert.FromHexString(Anchors["proof_bytes"]);
        Assert.AreEqual(expected.Length, proof.Length, "The proof length over the compiled circuit must match the reference proof.");
        Assert.IsTrue(proof.Bytes.SequenceEqual(expected), "The proof over the compiled circuit must be byte-identical to the reference proof.");
    }


    [TestMethod]
    public void ProofsCrossVerifyBetweenTheCompiledAndTheAnchorBuiltCircuit()
    {
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit compiled);
        LongfellowSumcheckCircuit anchorBuilt = BuildAnchorCircuit();

        byte[] witnessColumn = BuildAnchorWitnessColumn(compiled);
        byte[] publicInputs = GfPublicInputBytes(compiled, witnessColumn);

        using LongfellowZkProofEnvelope proofOverCompiled = ProduceGfProof(compiled, witnessColumn, TranscriptSeed);
        AssertGfVerifies(anchorBuilt, proofOverCompiled.Bytes, publicInputs, TranscriptSeed, expectedAccept: true);

        using LongfellowZkProofEnvelope proofOverAnchorBuilt = ProduceGfProof(anchorBuilt, witnessColumn, TranscriptSeed);
        AssertGfVerifies(compiled, proofOverAnchorBuilt.Bytes, publicInputs, TranscriptSeed, expectedAccept: true);
    }


    [TestMethod]
    public void AnUnsatisfyingWitnessIsUnprovableOverTheCompiledCircuit()
    {
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit circuit);

        //Break the relation: flip a bit of w so w != (x+y)·(x+z)·x.
        byte[] column = BuildAnchorWitnessColumn(circuit);
        const int WitnessWireIndex = 4;
        column[(WitnessWireIndex * ScalarSize) + ScalarSize - 1] ^= 0x01;

        Assert.ThrowsExactly<InvalidOperationException>(() => ProduceGfProof(circuit, column, TranscriptSeed));
    }


    [TestMethod]
    public void ATamperedProofOverTheCompiledCircuitRejects()
    {
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit circuit);
        byte[] witnessColumn = BuildAnchorWitnessColumn(circuit);
        using LongfellowZkProofEnvelope proof = ProduceGfProof(circuit, witnessColumn, TranscriptSeed);

        //Flip one byte in the Ligero proof segment (past the root and the sumcheck segment).
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[^1] ^= 0x01;

        AssertGfVerifies(circuit, tamperedProof, GfPublicInputBytes(circuit, witnessColumn), TranscriptSeed, expectedAccept: false);
    }


    [TestMethod]
    public void CompilationIsDeterministic()
    {
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit first);
        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit second);

        Assert.IsTrue(first.Id.Span.SequenceEqual(second.Id.Span), "Two compilations of the same statement must produce the same id.");
    }


    [TestMethod]
    public void TheBuilderEliminatesCommonSubexpressions()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();

        int firstSum = builder.Add(x, y);
        int secondSum = builder.Add(x, y);

        Assert.AreEqual(firstSum, secondSum, "An identical subexpression must reuse the existing node.");
        Assert.AreEqual(1, builder.EliminatedSubexpressionCount, "The elimination must be counted once.");
    }


    [TestMethod]
    public void TheBuilderFoldsZeroAndIdentityOperands()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();

        byte[] zero = new byte[ScalarSize];
        byte[] one = new byte[ScalarSize];
        one[ScalarSize - 1] = 0x01;

        int zeroNode = builder.Konst(zero);
        Assert.AreEqual(x, builder.Add(x, zeroNode), "Adding zero must return the other operand.");
        Assert.AreEqual(x, builder.Add(zeroNode, x), "Adding zero must return the other operand.");
        Assert.AreEqual(x, builder.Mul(one, x), "Scaling by one must return the operand.");
        Assert.AreEqual(zeroNode, builder.Mul(x, zeroNode), "Multiplying by the zero node must return the zero node.");
        Assert.AreEqual(zeroNode, builder.Mul(zero, x), "Scaling by the zero constant must produce the zero node.");
    }


    [TestMethod]
    public void TheLinearBarrierIsNotFoldedAway()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();

        int barrier = builder.Linear(x);

        Assert.AreNotEqual(x, barrier, "The linear barrier must be a distinct node the simplifier keeps.");
        Assert.AreEqual(barrier, builder.Linear(x), "Repeated barriers over the same operand must share the node.");
    }


    [TestMethod]
    public void AssertZeroOnALinearNodeReducesToItsOperand()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();
        int product = builder.Mul(x, y);
        int barrier = builder.Linear(product);

        int assertionOverBarrier = builder.AssertZero(barrier);
        int assertionOverProduct = builder.AssertZero(product);

        Assert.AreEqual(assertionOverProduct, assertionOverBarrier, "An assertion over a linear barrier must reduce to the assertion over its operand.");
    }


    [TestMethod]
    public void ThePublicPrivateBoundaryIsSetOnce()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        _ = builder.InputWire();
        builder.PrivateInput();

        Assert.ThrowsExactly<InvalidOperationException>(builder.PrivateInput);
    }


    /// <summary>
    /// A recomputed expression must unify with a node already registered as an output: output-ness
    /// is a compiler annotation like depth, not part of subexpression identity.
    /// </summary>
    [TestMethod]
    public void ACommonSubexpressionUnifiesWithAnOutputNode()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();

        int product = builder.Mul(x, y);
        builder.OutputWire(product, 0);

        int recomputed = builder.Mul(x, y);

        Assert.AreEqual(product, recomputed, "The recomputed product must reuse the output node.");
        Assert.AreEqual(1, builder.EliminatedSubexpressionCount, "The reuse must be counted as a common-subexpression elimination.");
    }


    /// <summary>Registering the same node as an output twice is a construction error.</summary>
    [TestMethod]
    public void ANodeCannotBeRegisteredAsAnOutputTwice()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();
        int product = builder.Mul(x, y);
        builder.OutputWire(product, 0);

        Assert.ThrowsExactly<InvalidOperationException>(() => builder.OutputWire(product, 1));
    }


    /// <summary>A node already registered as an output cannot be absorbed into a new expression.</summary>
    [TestMethod]
    public void AnOutputNodeCannotBeAbsorbedIntoANewExpression()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();
        int product = builder.Mul(x, y);
        builder.OutputWire(product, 0);

        Assert.ThrowsExactly<InvalidOperationException>(() => builder.Add(product, y));
    }


    [TestMethod]
    public void ACircuitWithoutOutputsOrAssertionsIsRejected()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();
        _ = builder.Mul(x, y);

        Assert.ThrowsExactly<InvalidOperationException>(() => builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory()));
    }


    [TestMethod]
    public void TheBuilderRejectsConstructionAfterCompilation()
    {
        LongfellowQuadCircuitBuilder builder = BuildAnchorStatement(out _);

        Assert.ThrowsExactly<InvalidOperationException>(() => builder.InputWire());
        Assert.ThrowsExactly<InvalidOperationException>(() => builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory()));
    }


    [TestMethod]
    public void TheMortonOrderMatchesTheReferenceBitPlaneComparison()
    {
        //Edge values around the interleave bit boundaries plus a deterministic pseudo-random sweep.
        int[] edges = [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 255, 256, 65535, 65536, int.MaxValue];
        foreach(int a0 in edges)
        {
            foreach(int a1 in edges)
            {
                foreach(int b0 in edges)
                {
                    foreach(int b1 in edges)
                    {
                        Assert.AreEqual(
                            ReferenceMortonLess((ulong)a0, (ulong)a1, (ulong)b0, (ulong)b1),
                            LongfellowMortonOrder.Less(a0, a1, b0, b1),
                            $"Morton order must match the reference for ({a0},{a1}) vs ({b0},{b1}).");
                    }
                }
            }
        }

        //A multiplicative-congruential sweep keeps the check deterministic without a random source.
        const int SweepCount = 2048;
        ulong state = 0x2545F4914F6CDD1Dul;
        for(int i = 0; i < SweepCount; i++)
        {
            state = (state * 6364136223846793005ul) + 1442695040888963407ul;
            int a0 = (int)(state >> 33);
            state = (state * 6364136223846793005ul) + 1442695040888963407ul;
            int a1 = (int)(state >> 33);
            state = (state * 6364136223846793005ul) + 1442695040888963407ul;
            int b0 = (int)(state >> 33);
            state = (state * 6364136223846793005ul) + 1442695040888963407ul;
            int b1 = (int)(state >> 33);

            Assert.AreEqual(
                ReferenceMortonLess((ulong)a0, (ulong)a1, (ulong)b0, (ulong)b1),
                LongfellowMortonOrder.Less(a0, a1, b0, b1),
                $"Morton order must match the reference for ({a0},{a1}) vs ({b0},{b1}).");
        }
    }


    [TestMethod]
    public void TheCeilingLogarithmMatchesTheReference()
    {
        Assert.AreEqual(0, LongfellowMortonOrder.Lg(0), "Lg(0) is zero.");
        Assert.AreEqual(0, LongfellowMortonOrder.Lg(1), "Lg(1) is zero.");
        Assert.AreEqual(1, LongfellowMortonOrder.Lg(2), "Lg(2) is one.");
        Assert.AreEqual(2, LongfellowMortonOrder.Lg(3), "Lg(3) is two.");
        Assert.AreEqual(2, LongfellowMortonOrder.Lg(4), "Lg(4) is two.");
        Assert.AreEqual(3, LongfellowMortonOrder.Lg(5), "Lg(5) is three.");
        Assert.AreEqual(3, LongfellowMortonOrder.Lg(8), "Lg(8) is three.");
        Assert.AreEqual(4, LongfellowMortonOrder.Lg(9), "Lg(9) is four.");
    }


    [TestMethod]
    public void TheCoefficientOrderIsLittleEndianLexicographic()
    {
        LongfellowCompilerFieldOperations field = LongfellowCompilerFieldOperations.CreateCharacteristicTwo(
            Add,
            Multiply,
            CurveParameterSet.None,
            ElementBytes);

        //256 precedes 255 in the little-endian order: 256's least significant byte is zero. A
        //big-endian (numeric) comparison would order them the other way, so this pins the
        //serialization direction of the reference's elt_less_than.
        byte[] twoHundredFiftySix = new byte[ScalarSize];
        twoHundredFiftySix[ScalarSize - 2] = 0x01;
        byte[] twoHundredFiftyFive = new byte[ScalarSize];
        twoHundredFiftyFive[ScalarSize - 1] = 0xFF;

        Assert.IsTrue(field.CompareLittleEndian(twoHundredFiftySix, twoHundredFiftyFive), "256 precedes 255 little-endian.");
        Assert.IsFalse(field.CompareLittleEndian(twoHundredFiftyFive, twoHundredFiftySix), "255 does not precede 256 little-endian.");

        //The numerically largest element with a zero low byte still precedes 255.
        byte[] topByteOnly = new byte[ScalarSize];
        topByteOnly[ScalarSize - ElementBytes] = 0x01;

        Assert.IsTrue(field.CompareLittleEndian(topByteOnly, twoHundredFiftyFive), "A high-byte-only element precedes 255 little-endian.");
        Assert.IsFalse(field.CompareLittleEndian(twoHundredFiftyFive, twoHundredFiftyFive), "An element does not precede itself.");
    }


    [TestMethod]
    public void TheCanonicalWireOrderIsDecidedByTheLittleEndianCoefficientComparison()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();

        //Two gates over the same operand pair, distinguished only by their coefficients: the
        //canonical wire-id sort must fall through to the coefficient comparison, and 256 wins the
        //smaller wire id under the little-endian order.
        byte[] twoHundredFiftySix = new byte[ScalarSize];
        twoHundredFiftySix[ScalarSize - 2] = 0x01;
        byte[] twoHundredFiftyFive = new byte[ScalarSize];
        twoHundredFiftyFive[ScalarSize - 1] = 0xFF;

        int p = builder.Mul(twoHundredFiftySix, x, y);
        int q = builder.Mul(twoHundredFiftyFive, x, y);
        builder.OutputWire(builder.Mul(p, q), 0);

        LongfellowSumcheckCircuit circuit = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        Assert.AreEqual(2, circuit.LayerCount, "The product of the two gates adds one layer above them.");
        LongfellowSumcheckQuadTerm[] corners = circuit.Layers[1].QuadTerms;
        Assert.HasCount(2, corners, "Each coefficient gate contributes one corner.");
        Assert.AreEqual((0, 1, 2), (corners[0].GateIndex, corners[0].LeftIndex, corners[0].RightIndex), "The first-sorted gate takes wire zero.");
        Assert.IsTrue(corners[0].Coefficient.Span.SequenceEqual(twoHundredFiftySix), "The 256 coefficient sorts first little-endian.");
        Assert.AreEqual((1, 1, 2), (corners[1].GateIndex, corners[1].LeftIndex, corners[1].RightIndex), "The second-sorted gate takes wire one.");
        Assert.IsTrue(corners[1].Coefficient.Span.SequenceEqual(twoHundredFiftyFive), "The 255 coefficient sorts second little-endian.");
    }


    [TestMethod]
    public void TheSingleWireLayerShapeIsRejectedAsADocumentedDivergence()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int a = builder.InputWire();
        int b = builder.InputWire();

        //The sum is the only wire of its layer; the reference compiler accepts the shape, this
        //stack's circuit type does not, and the compiler must reject it rather than emit it.
        int c = builder.Add(a, b);
        builder.OutputWire(builder.Mul(c, c), 0);

        Assert.ThrowsExactly<InvalidOperationException>(() => builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory()));
    }


    [TestMethod]
    public void AssertZeroFastPathsGenerateNoAssertionNode()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();

        byte[] zero = new byte[ScalarSize];
        int zeroNode = builder.Konst(zero);
        Assert.AreEqual(zeroNode, builder.AssertZero(zeroNode), "Asserting the zero node generates nothing.");

        int product = builder.Mul(x, y);
        int assertion = builder.AssertZero(product);
        Assert.AreEqual(assertion, builder.AssertZero(assertion), "Asserting an assertion node returns it unchanged.");
    }


    [TestMethod]
    public void TheAnchorBuildTelemetryMatchesTheHandDerivedCounts()
    {
        LongfellowQuadCircuitBuilder builder = BuildAnchorStatement(out _);

        Assert.AreEqual(4, builder.DepthUpperBound, "The assertion sits at depth four.");
        Assert.AreEqual(15, builder.WireCount, "One output plus layer inputs of four, five and five.");
        Assert.AreEqual(13, builder.QuadTermCount, "Two, four and seven corners before coalescing.");
        Assert.AreEqual(6, builder.CopyWireOverheadCount, "The one, x and w wires each bridge two layers.");
        Assert.AreEqual(3, builder.NotNeededCount, "The absorbed product, the absorbed barrier and the converted assertion are dead.");
        Assert.AreEqual(0, builder.EliminatedSubexpressionCount, "The anchor statement has no repeated subexpression.");
        Assert.AreEqual(1, builder.OutputCount, "The converted assertion is the single output.");
        Assert.AreEqual(5, builder.InputCount, "The one wire plus x, y, z and w.");
    }


    [TestMethod]
    public void ALongCopyWireChainBridgesEveryIntermediateLayer()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();

        //x is consumed again at depth four, forcing a three-hop copy chain (depths one through
        //three) plus the constant-one copies that carry the chain's multiplications.
        int p1 = builder.Mul(x, y);
        int p2 = builder.Mul(p1, p1);
        int p3 = builder.Mul(p2, p2);
        builder.OutputWire(builder.Mul(p3, x), 0);

        LongfellowSumcheckCircuit circuit = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        Assert.AreEqual(4, circuit.LayerCount, "Depth five yields four layers.");
        Assert.AreEqual(2, circuit.Layers[0].InputCount, "The output layer reads the x copy and the cube.");
        Assert.AreEqual(3, circuit.Layers[1].InputCount, "The middle layers carry one, x and the running square.");
        Assert.AreEqual(3, circuit.Layers[2].InputCount, "The middle layers carry one, x and the running square.");
        Assert.AreEqual(3, circuit.Layers[3].InputCount, "The input layer holds one, x and y.");
        Assert.AreEqual(5, builder.CopyWireOverheadCount, "Three x copies and two constant-one copies bridge the gap.");

        LongfellowSumcheckQuadTerm[] outputCorners = circuit.Layers[0].QuadTerms;
        Assert.HasCount(1, outputCorners, "The output layer holds the single product corner.");
        Assert.AreEqual((0, 0, 1), (outputCorners[0].GateIndex, outputCorners[0].LeftIndex, outputCorners[0].RightIndex), "The product multiplies the x copy by the cube.");
    }


    [TestMethod]
    public void ExplicitOutputWiresClaimTheirPositionsInTheCanonicalOrder()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();

        //Two explicit outputs at claimed positions: out[0] = x·y and out[1] = x + y.
        builder.OutputWire(builder.Mul(x, y), 0);
        builder.OutputWire(builder.Add(x, y), 1);

        LongfellowSumcheckCircuit circuit = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        Assert.AreEqual(2, circuit.OutputCount, "Both explicit outputs must be counted.");
        Assert.AreEqual(1, circuit.LayerCount, "Both outputs sit at depth one, a single layer.");
        Assert.AreEqual(3, circuit.Layers[0].InputCount, "The input layer holds the one wire, x and y.");

        //The canonical Morton order over (h0, h1): the sum's corners (0,1) and (0,2) precede the
        //product corner (1,2); the claimed gate positions ride along unchanged.
        LongfellowSumcheckQuadTerm[] corners = circuit.Layers[0].QuadTerms;
        Assert.HasCount(3, corners, "The product contributes one corner and the sum two.");
        Assert.AreEqual((1, 0, 1), (corners[0].GateIndex, corners[0].LeftIndex, corners[0].RightIndex), "The sum's x corner comes first.");
        Assert.AreEqual((1, 0, 2), (corners[1].GateIndex, corners[1].LeftIndex, corners[1].RightIndex), "The sum's y corner comes second.");
        Assert.AreEqual((0, 1, 2), (corners[2].GateIndex, corners[2].LeftIndex, corners[2].RightIndex), "The product corner comes last.");
    }


    [TestMethod]
    public void MergeCancellationYieldsTheZeroNode()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();

        //In characteristic two the same scaled barrier added to itself cancels: 2·(k·x) = 0.
        byte[] two = new byte[ScalarSize];
        two[ScalarSize - 1] = 0x02;
        int scaled = builder.Linear(two, x);
        int sum = builder.Add(scaled, scaled);

        Assert.AreEqual(x, builder.Add(x, sum), "The cancelled sum must behave as the zero node under addition.");
    }


    [TestMethod]
    public void KonstAxpyAndApyFoldIntoTheCompiledLayer()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();

        byte[] two = new byte[ScalarSize];
        two[ScalarSize - 1] = 0x02;
        byte[] three = new byte[ScalarSize];
        three[ScalarSize - 1] = 0x03;

        //out[0] = x·y + 2·x + 3: the quadratic term, an axpy term and a konst term in one node.
        int accumulated = builder.Apy(builder.Axpy(builder.Mul(x, y), two, x), three);
        builder.OutputWire(accumulated, 0);

        LongfellowSumcheckCircuit circuit = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        Assert.AreEqual(1, circuit.LayerCount, "The accumulated node compiles into one layer.");
        LongfellowSumcheckQuadTerm[] corners = circuit.Layers[0].QuadTerms;
        Assert.HasCount(3, corners, "The konst, axpy and product terms each contribute one corner.");

        //Morton order: the konst corner (0,0), the 2·x corner (0,1), the x·y corner (1,2).
        Assert.AreEqual((0, 0), (corners[0].LeftIndex, corners[0].RightIndex), "The konst corner multiplies the one wire by itself.");
        Assert.IsTrue(corners[0].Coefficient.Span.SequenceEqual(three), "The konst corner carries three.");
        Assert.AreEqual((0, 1), (corners[1].LeftIndex, corners[1].RightIndex), "The axpy corner multiplies the one wire by x.");
        Assert.IsTrue(corners[1].Coefficient.Span.SequenceEqual(two), "The axpy corner carries two.");
        Assert.AreEqual((1, 2), (corners[2].LeftIndex, corners[2].RightIndex), "The product corner multiplies x by y.");
    }


    [TestMethod]
    public void TheSubfieldBoundaryIsSetOnceAndEntersTheId()
    {
        LongfellowQuadCircuitBuilder boundaryBuilder = BuildAnchorStatementWithFullFieldTail(out LongfellowSumcheckCircuit boundaryCircuit);
        Assert.AreEqual(4, boundaryBuilder.SubfieldBoundary, "The boundary records the input count at the BeginFullField call.");
        Assert.ThrowsExactly<InvalidOperationException>(boundaryBuilder.BeginFullField);

        _ = BuildAnchorStatement(out LongfellowSumcheckCircuit baseline);
        Assert.IsFalse(boundaryCircuit.Id.Span.SequenceEqual(baseline.Id.Span), "The subfield boundary must enter the structural id.");
    }


    [TestMethod]
    public void ACopyCountAboveOneEntersTheShapeAndTheId()
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();
        int x = builder.InputWire();
        int y = builder.InputWire();
        builder.OutputWire(builder.Mul(x, y), 0);

        const int TwoCopies = 2;
        LongfellowSumcheckCircuit twoCopyCircuit = builder.MakeCircuit(TwoCopies, Sha256FiatShamirBackend.GetIncrementalFactory());

        Assert.AreEqual(TwoCopies, twoCopyCircuit.CopyCount, "The copy count must be carried.");
        Assert.AreEqual(1, twoCopyCircuit.CopyRounds, "Two copies bind one copy variable.");

        LongfellowQuadCircuitBuilder singleBuilder = NewBuilder();
        int sx = singleBuilder.InputWire();
        int sy = singleBuilder.InputWire();
        singleBuilder.OutputWire(singleBuilder.Mul(sx, sy), 0);
        LongfellowSumcheckCircuit singleCopyCircuit = singleBuilder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        Assert.IsFalse(twoCopyCircuit.Id.Span.SequenceEqual(singleCopyCircuit.Id.Span), "The copy count must enter the structural id.");
    }


    //Builds the anchor statement w == (x+y)·(x+z)·x through the kernel: x public; y, z, w private;
    //the last-layer assertion becomes the single zero output, exactly the reference harness's build.
    private static LongfellowQuadCircuitBuilder BuildAnchorStatement(out LongfellowSumcheckCircuit circuit)
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();

        int x = builder.InputWire();
        builder.PrivateInput();

        int y = builder.InputWire();
        int z = builder.InputWire();
        int w = builder.InputWire();

        int t = builder.Mul(builder.Add(x, y), builder.Add(x, z));
        int u = builder.Mul(t, x);
        _ = builder.AssertZero(builder.Sub(w, u));

        circuit = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        return builder;
    }


    //The anchor statement with a subfield/full-field split: y and z stay subfield inputs and w is
    //declared past the BeginFullField watermark, so the boundary records four declared inputs.
    private static LongfellowQuadCircuitBuilder BuildAnchorStatementWithFullFieldTail(out LongfellowSumcheckCircuit circuit)
    {
        LongfellowQuadCircuitBuilder builder = NewBuilder();

        int x = builder.InputWire();
        builder.PrivateInput();

        int y = builder.InputWire();
        int z = builder.InputWire();
        builder.BeginFullField();

        int w = builder.InputWire();

        int t = builder.Mul(builder.Add(x, y), builder.Add(x, z));
        int u = builder.Mul(t, x);
        _ = builder.AssertZero(builder.Sub(w, u));

        circuit = builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());

        return builder;
    }


    private static LongfellowQuadCircuitBuilder NewBuilder()
    {
        LongfellowCompilerFieldOperations field = LongfellowCompilerFieldOperations.CreateCharacteristicTwo(
            Add,
            Multiply,
            CurveParameterSet.None,
            ElementBytes);

        return new LongfellowQuadCircuitBuilder(field);
    }


    //Reconstructs the circuit from the anchor's dumped parameters, the same construction the C.9
    //prover gate uses; the cross-verification gate pits it against the kernel-compiled circuit.
    private static LongfellowSumcheckCircuit BuildAnchorCircuit()
    {
        int nl = Anchor("nl");
        var layers = new LongfellowSumcheckLayer[nl];
        for(int i = 0; i < nl; i++)
        {
            int nw = Anchor($"layer{i}_nw");
            int logw = Anchor($"layer{i}_logw");
            int nterms = Anchor($"layer{i}_nterms");

            var quadTerms = new LongfellowSumcheckQuadTerm[nterms];
            for(int t = 0; t < nterms; t++)
            {
                quadTerms[t] = new LongfellowSumcheckQuadTerm(
                    Anchor($"L{i}_t{t}_g"),
                    Anchor($"L{i}_t{t}_h0"),
                    Anchor($"L{i}_t{t}_h1"),
                    ParseElement(Anchors[$"L{i}_t{t}_v"]));
            }

            layers[i] = new LongfellowSumcheckLayer(nw, logw, nterms, quadTerms);
        }

        return new LongfellowSumcheckCircuit(
            Anchor("nv"),
            Anchor("logv"),
            Anchor("nc"),
            Anchor("logc"),
            Anchor("ninputs"),
            Anchor("npub_in"),
            Convert.FromHexString(Anchors["id"]),
            layers);
    }


    //The full witness column (all ninputs) as canonical scalars, from the anchor's input0..input(n-1).
    private static byte[] BuildAnchorWitnessColumn(LongfellowSumcheckCircuit circuit)
    {
        byte[] column = new byte[circuit.InputCount * ScalarSize];
        for(int i = 0; i < circuit.InputCount; i++)
        {
            byte[] element = ParseElement(Anchors[$"input{i}"]);
            element.CopyTo(column.AsSpan(i * ScalarSize, ScalarSize));
        }

        return column;
    }


    //The reference morton::lt over the even/odd bit-plane representation (lib/util/ceildiv.h),
    //transcribed as the independent oracle for the interleave-based comparison.
    private static bool ReferenceMortonLess(ulong x0, ulong x1, ulong y0, ulong y1)
    {
        ReferenceMortonSub(ref x0, ref x1, y0, y1);

        return (x1 >> 63) == 1;
    }


    private static void ReferenceMortonSub(ref ulong x0, ref ulong x1, ulong y0, ulong y1)
    {
        x0 = ~x0;
        x1 = ~x1;
        ReferenceMortonAdd(ref x0, ref x1, y0, y1);
        x0 = ~x0;
        x1 = ~x1;
    }


    private static void ReferenceMortonAdd(ref ulong x0, ref ulong x1, ulong y0, ulong y1)
    {
        ulong g0 = x0 & y0;
        ulong g1 = x1 & y1;
        ulong p0 = x0 ^ y0;
        ulong p1 = x1 ^ y1;

        ulong g = g1 ^ (g0 & p1);
        ulong p = p0 & p1;

        ulong gprime = (g + (p ^ g)) ^ p;

        x0 = gprime ^ p0;
        x1 = g0 ^ (gprime & p0) ^ p1;
    }


    //Parses a 16-byte little-endian element into a 32-byte big-endian canonical scalar.
    private static byte[] ParseElement(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < ElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    private static Dictionary<string, string> LoadAnchors(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            if(line.Length == 0)
            {
                continue;
            }

            foreach(string token in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                int separator = token.IndexOf('=', StringComparison.Ordinal);
                if(separator < 0)
                {
                    continue;
                }

                map[token[..separator]] = token[(separator + 1)..];
            }
        }

        return map;
    }
}
