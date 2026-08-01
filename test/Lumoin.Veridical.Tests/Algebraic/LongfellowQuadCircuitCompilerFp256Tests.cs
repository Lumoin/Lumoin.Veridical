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
using System.Numerics;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The prime-field gates for the in-house Longfellow circuit compiler: the same statement the
/// GF(2^128) anchor pins — <c>w == (x + y)·(x + z)·x</c>, x public, y/z/w private — compiled by the
/// kernel over the 32-byte P-256 base field and driven through the field-generic ZK prover and
/// verifier end to end.
/// </summary>
/// <remarks>
/// <para>
/// Over a prime field the kernel's subtraction is genuine: <c>Sub(w, u)</c> scales <c>u</c> by
/// <c>−1 = p − 1</c>, so the compiled circuit shares the anchor's wiring indices but carries the
/// coefficient <c>p − 1</c> on the product corner, and the satisfying witness is the natural
/// <c>w = x·(x + y)·(x + z) mod p</c> — unlike the anchor-wiring Fp256 gate, whose all-one
/// coefficients force a negated witness. This exercises the prime-field arms the GF gates cannot:
/// the minus-one scale path, a non-trivial coefficient through the constant table, the corner sort
/// on 32-byte coefficients, and the odd-prime field marker in the structural id.
/// </para>
/// <para>
/// No reference anchor exists for this compiled circuit; the gates are structural (the wiring
/// against the hand-traceable expectation, the id's field separation) and functional (prove →
/// verify accepts, tampered proof and tampered public input reject with the Ligero soundness
/// cause).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowQuadCircuitCompilerFp256Tests
{
    private const string ZkDumpRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    private const int Fp256BitCount = 256;

    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("fp256-kernel-e2e");

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkDumpRelativePath);


    [TestMethod]
    public void TheCompiledFp256CircuitSharesTheWiringWithAGenuineNegationCoefficient()
    {
        _ = BuildFp256Statement(out LongfellowSumcheckCircuit circuit);

        //The layer structure matches the anchor: the wiring indices are field-independent.
        Assert.AreEqual(Anchor("nv"), circuit.OutputCount, "The output count must match the anchor structure.");
        Assert.AreEqual(Anchor("nl"), circuit.LayerCount, "The layer count must match the anchor structure.");
        Assert.AreEqual(Anchor("ninputs"), circuit.InputCount, "The input count must match the anchor structure.");
        Assert.AreEqual(Anchor("npub_in"), circuit.PublicInputCount, "The public input count must match the anchor structure.");
        for(int i = 0; i < circuit.LayerCount; i++)
        {
            Assert.AreEqual(Anchor($"layer{i}_nw"), circuit.Layers[i].InputCount, $"Layer {i}'s input count must match the anchor structure.");
            Assert.AreEqual(Anchor($"layer{i}_logw"), circuit.Layers[i].HandRounds, $"Layer {i}'s hand rounds must match the anchor structure.");
            Assert.AreEqual(Anchor($"layer{i}_nterms"), circuit.Layers[i].TermCount, $"Layer {i}'s term count must match the anchor structure.");
        }

        //The output layer computes w + (p−1)·x·(x+y)(x+z): the copy corner keeps the coefficient one
        //and the product corner carries the genuine minus one.
        LongfellowSumcheckQuadTerm copyCorner = circuit.Layers[0].QuadTerms[0];
        LongfellowSumcheckQuadTerm productCorner = circuit.Layers[0].QuadTerms[1];

        Assert.IsTrue(copyCorner.Coefficient.Span.SequenceEqual(CanonicalOne()), "The w copy corner keeps the coefficient one.");
        Assert.IsTrue(productCorner.Coefficient.Span.SequenceEqual(Canonical(Prime - 1)), "The product corner carries p − 1, the genuine minus one.");
    }


    [TestMethod]
    public void TheStructuralIdSeparatesTheFields()
    {
        _ = BuildFp256Statement(out LongfellowSumcheckCircuit fp256Circuit);

        byte[] anchorId = Convert.FromHexString(Anchors["id"]);
        Assert.IsFalse(fp256Circuit.Id.Span.SequenceEqual(anchorId), "The Fp256 compilation must not collide with the GF(2^128) anchor id.");
    }


    [TestMethod]
    public void OurVerifierAcceptsAProofOverTheCompiledFp256Circuit()
    {
        _ = BuildFp256Statement(out LongfellowSumcheckCircuit circuit);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        byte[] witnessColumn = BuildSatisfyingColumn(3, 5, 7);
        using LongfellowZkProofEnvelope proof = ProduceFp256Proof(circuit, parameters, witnessColumn, TranscriptSeed);

        AssertFp256Verifies(circuit, parameters, proof.Bytes, Fp256PublicInputBytes(circuit, witnessColumn), TranscriptSeed, expectedAccept: true);
    }


    [TestMethod]
    public void ATamperedProofOverTheCompiledFp256CircuitRejects()
    {
        _ = BuildFp256Statement(out LongfellowSumcheckCircuit circuit);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        byte[] witnessColumn = BuildSatisfyingColumn(3, 5, 7);
        using LongfellowZkProofEnvelope proof = ProduceFp256Proof(circuit, parameters, witnessColumn, TranscriptSeed);
        byte[] publicInputs = Fp256PublicInputBytes(circuit, witnessColumn);

        //A flipped byte inside the sumcheck segment diverges the challenge stream.
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[DigestSize + 8] ^= 0x01;
        AssertFp256Verifies(circuit, parameters, tamperedProof, publicInputs, TranscriptSeed, expectedAccept: false);

        //A flipped public input moves the Fiat–Shamir setup and the input-binding constraint.
        byte[] tamperedPublic = (byte[])publicInputs.Clone();
        tamperedPublic[Fp256ElementBytes + 1] ^= 0x01;
        AssertFp256Verifies(circuit, parameters, proof.Bytes, tamperedPublic, TranscriptSeed, expectedAccept: false);
    }


    [TestMethod]
    public void AnUnsatisfyingWitnessIsUnprovableOverTheCompiledFp256Circuit()
    {
        _ = BuildFp256Statement(out LongfellowSumcheckCircuit circuit);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        //Break the relation: w + 1 no longer equals x·(x+y)·(x+z).
        byte[] column = BuildSatisfyingColumn(3, 5, 7);
        const int WitnessWireIndex = 4;
        column[(WitnessWireIndex * ScalarSize) + ScalarSize - 1] ^= 0x01;

        Assert.ThrowsExactly<InvalidOperationException>(() => ProduceFp256Proof(circuit, parameters, column, TranscriptSeed));
    }


    [TestMethod]
    public void MergeCancellationOfDistinctValuesYieldsTheZeroNode()
    {
        LongfellowCompilerFieldOperations field = LongfellowCompilerFieldOperations.CreatePrime(
            Fp256Add,
            Fp256Multiply,
            CurveParameterSet.None,
            Canonical(Prime - 1),
            Fp256ElementBytes,
            Fp256BitCount);

        var builder = new LongfellowQuadCircuitBuilder(field);

        int x = builder.InputWire();

        //Two genuinely different coefficients that sum to zero mod p: the merged term's coefficient
        //cancels and the sum collapses to the zero node.
        const uint Five = 5;
        int scaledUp = builder.Linear(Canonical(Five), x);
        int scaledDown = builder.Linear(Canonical(Prime - Five), x);
        int sum = builder.Add(scaledUp, scaledDown);

        Assert.AreEqual(x, builder.Add(x, sum), "The cancelled sum must behave as the zero node under addition.");
    }


    //Builds w == (x+y)·(x+z)·x through the kernel over the P-256 base field: x public; y, z, w
    //private. Sub is genuine over a prime field, so the compiled output asserts w − x·(x+y)(x+z) = 0.
    private static LongfellowQuadCircuitBuilder BuildFp256Statement(out LongfellowSumcheckCircuit circuit)
    {
        LongfellowCompilerFieldOperations field = LongfellowCompilerFieldOperations.CreatePrime(
            Fp256Add,
            Fp256Multiply,
            CurveParameterSet.None,
            Canonical(Prime - 1),
            Fp256ElementBytes,
            Fp256BitCount);

        var builder = new LongfellowQuadCircuitBuilder(field);

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


    //Builds the satisfying Fp256 column [one, x, y, z, w] with w = x·(x+y)·(x+z) mod p — the natural
    //witness, because the kernel's genuine subtraction put the negation into the circuit coefficient.
    private static byte[] BuildSatisfyingColumn(uint x, uint y, uint z)
    {
        byte[] column = new byte[5 * ScalarSize];

        Span<byte> one = column.AsSpan(0, ScalarSize);
        one.Clear();
        one[ScalarSize - 1] = 0x01;

        OfScalarFp256(x, column.AsSpan(ScalarSize, ScalarSize));
        OfScalarFp256(y, column.AsSpan(2 * ScalarSize, ScalarSize));
        OfScalarFp256(z, column.AsSpan(3 * ScalarSize, ScalarSize));

        Span<byte> xPlusY = stackalloc byte[ScalarSize];
        Span<byte> xPlusZ = stackalloc byte[ScalarSize];
        Fp256Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(2 * ScalarSize, ScalarSize), xPlusY, CurveParameterSet.None);
        Fp256Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(3 * ScalarSize, ScalarSize), xPlusZ, CurveParameterSet.None);

        Span<byte> w = column.AsSpan(4 * ScalarSize, ScalarSize);
        Fp256Multiply(xPlusY, xPlusZ, w, CurveParameterSet.None);
        Fp256Multiply(w, column.AsSpan(ScalarSize, ScalarSize), w, CurveParameterSet.None);

        return column;
    }


    private static byte[] CanonicalOne()
    {
        byte[] one = new byte[ScalarSize];
        one[ScalarSize - 1] = 0x01;

        return one;
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
