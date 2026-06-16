using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The wire-format-conformant Ligero PROVE flow (conformance step C.4), gated as a faithful port of
/// google/longfellow-zk's <c>lib/ligero/ligero_prover.h</c> <c>prove()</c> over the C.2 commit and the
/// C.3 transcript, anchored to a complete reference-computed proof reproduced field by field.
/// </summary>
/// <remarks>
/// <para>
/// The oracle dump (prove-anchor-output.txt in TestMaterial/Longfellow) is computed by the reference
/// implementation running in its own build environment via development tooling outside this repository.
/// It runs the real <c>LigeroProver::commit()+prove()</c> and the real <c>LigeroProof</c> with the
/// deterministic counter random engine and a fixed transcript seed, and dumps every proof field: the
/// commitment root, the challenge arrays exactly as squeezed (<c>u_ldt</c>, <c>alphal</c>,
/// <c>alphaq</c>, <c>u_quad</c>), the response rows (<c>y_ldt</c>, <c>y_dot</c>, <c>y_quad_0</c>,
/// <c>y_quad_2</c>), the opened columns (<c>req</c>, one row per tableau row), the opened-column indices
/// (<c>idx</c>), each opened column's per-leaf nonce, and the compressed Merkle multi-proof path. The
/// dump's <c>verify=1</c> confirms <c>LigeroVerifier::verify()</c> accepts the proof, so the gate
/// reproduces a verifying proof.
/// </para>
/// <para>
/// The C# gates reproduce every field byte for byte through the real C.2 commit and C.3 transcript
/// ports, over both subfields the reference instantiates (production GF(2^16) and test-parity
/// GF(2^32)). The adversarial duals: a one-bit-flipped witness changes the responses and the opened
/// columns; a one-byte-different transcript seed changes the challenges, responses and opened indices;
/// and a tampered response, re-absorbed, changes the drawn opened-column indices (the commit-then-
/// challenge binding — the prover cannot move a response without moving the columns it will be checked
/// at).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowLigeroProveTests
{
    private const string DumpRelativePath = "TestMaterial/Longfellow/prove-anchor-output.txt";

    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSize = 32;
    private const int ElementBytes = 16;

    //GF(2^128) byte sizes: the full field element is 16 bytes; the production GF(2^16) subfield is 2
    //bytes, the test-parity GF(2^32) subfield is 4 bytes.
    private const int FieldBytes = 16;
    private const int Production16SubFieldBytes = 2;
    private const int TestParity32SubFieldBytes = 4;

    //The fixed prove tuple the harness drives.
    private const int WitnessCount = 8;
    private const int QuadraticConstraintCount = 1;
    private const int InverseRate = 4;
    private const int OpenedColumnCount = 2;
    private const int TranscriptVersion = 6;

    private static readonly byte[] TranscriptSeed = Encoding.ASCII.GetBytes("c4");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors();


    [TestMethod]
    public void TheProofMatchesTheReferenceForTheProductionSubfield()
    {
        AssertProofMatchesReference(Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
    }


    [TestMethod]
    public void TheProofMatchesTheReferenceForTheTestParitySubfield()
    {
        AssertProofMatchesReference(Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    [TestMethod]
    public void AFlippedWitnessChangesTheResponsesAndOpenedColumns()
    {
        using Lch14AdditiveFft fft = NewFft(Lch14Subfield.Production16);

        byte[] baselineLowDegree;
        byte[] baselineColumn0;
        using(LongfellowLigeroProof baseline = ProduceProof(fft, Production16SubFieldBytes, witnessFlipIndex: -1, TranscriptSeed))
        {
            baselineLowDegree = baseline.LowDegreeResponse.ToArray();
            baselineColumn0 = baseline.OpenedColumnElement(0, 0).ToArray();
        }

        using LongfellowLigeroProof tampered = ProduceProof(fft, Production16SubFieldBytes, witnessFlipIndex: 0, TranscriptSeed);

        Assert.IsFalse(tampered.LowDegreeResponse.SequenceEqual(baselineLowDegree), "A flipped witness must change the low-degree response.");
        Assert.IsFalse(tampered.OpenedColumnElement(0, 0).SequenceEqual(baselineColumn0), "A flipped witness must change the opened columns.");
    }


    [TestMethod]
    public void ADifferentSeedChangesTheChallengesAndOpenedIndices()
    {
        using Lch14AdditiveFft fft = NewFft(Lch14Subfield.Production16);

        int[] baselineIndices;
        byte[] baselineLowDegree;
        using(LongfellowLigeroProof baseline = ProduceProof(fft, Production16SubFieldBytes, witnessFlipIndex: -1, TranscriptSeed))
        {
            baselineIndices = baseline.OpenedColumnIndices.ToArray();
            baselineLowDegree = baseline.LowDegreeResponse.ToArray();
        }

        byte[] altSeed = Encoding.ASCII.GetBytes("c5");
        using LongfellowLigeroProof altered = ProduceProof(fft, Production16SubFieldBytes, witnessFlipIndex: -1, altSeed);

        Assert.IsFalse(altered.LowDegreeResponse.SequenceEqual(baselineLowDegree), "A different seed must change the responses (the challenges differ).");

        bool indicesDiffer = !altered.OpenedColumnIndices.SequenceEqual(baselineIndices);
        Assert.IsTrue(indicesDiffer, "A different seed must change the drawn opened-column indices.");
    }


    [TestMethod]
    public void ATamperedResponseChangesTheDrawnOpenedIndices()
    {
        //The commit-then-challenge binding: idx is drawn from the transcript AFTER the responses are
        //absorbed, so flipping one byte of one absorbed response re-derives a different idx set. The
        //gate replays the transcript through the response absorbs with one byte flipped and checks the
        //index subset moves, demonstrating the prover cannot decouple a response from its check columns.
        using Lch14AdditiveFft fft = NewFft(Lch14Subfield.Production16);

        int[] honestIndices;
        byte[] lowDegreeResponse;
        byte[] dotResponse;
        byte[] quadLow;
        byte[] quadHigh;
        using(LongfellowLigeroProof proof = ProduceProof(fft, Production16SubFieldBytes, witnessFlipIndex: -1, TranscriptSeed))
        {
            honestIndices = proof.OpenedColumnIndices.ToArray();
            lowDegreeResponse = proof.LowDegreeResponse.ToArray();
            dotResponse = proof.DotResponse.ToArray();
            quadLow = proof.QuadraticResponseLow.ToArray();
            quadHigh = proof.QuadraticResponseHigh.ToArray();
        }

        var parameters = NewParameters(Production16SubFieldBytes);

        //Honest replay: absorb root, theorem statement, the four challenge squeezes, then the four
        //honest responses, then draw idx. Must match the proof's indices.
        int[] honestReplay = ReplayOpenedIndices(parameters, lowDegreeResponse, dotResponse, quadLow, quadHigh);
        Assert.IsTrue(honestReplay.AsSpan().SequenceEqual(honestIndices), "The honest transcript replay must reproduce the proof's opened indices.");

        //Tampered replay: a one-byte flip of an absorbed response re-keys the post-response transcript,
        //so the drawn idx is generically different. The opened-column universe here is small
        //(block_ext = 23, nreq = 2), so a particular byte flip can land on the same pair by chance;
        //the binding is that SOME single-byte response change moves idx. Sweep the dot response bytes
        //and assert at least one flip moves the opened indices.
        bool anyFlipMovesIndices = false;
        for(int bytePosition = 0; bytePosition < dotResponse.Length && !anyFlipMovesIndices; bytePosition++)
        {
            byte[] tamperedDot = (byte[])dotResponse.Clone();
            tamperedDot[bytePosition] ^= 0x01;
            int[] tamperedReplay = ReplayOpenedIndices(parameters, lowDegreeResponse, tamperedDot, quadLow, quadHigh);
            anyFlipMovesIndices = !tamperedReplay.AsSpan().SequenceEqual(honestIndices);
        }

        Assert.IsTrue(anyFlipMovesIndices, "A tampered response must change the drawn opened-column indices (the commit-then-challenge binding).");
    }


    //Builds the proof through the real C.2 commit + C.3 transcript + C.4 prove, then asserts every
    //field equals the reference dump for the given subfield prefix.
    private static void AssertProofMatchesReference(Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        using Lch14AdditiveFft fft = NewFft(subfield);
        using LongfellowLigeroProof proof = ProduceProof(fft, subFieldBytes, witnessFlipIndex: -1, TranscriptSeed);
        var parameters = NewParameters(subFieldBytes);

        //The commitment root (identical to the C.2 anchor).
        Span<byte> root = stackalloc byte[DigestSize];
        using(LongfellowLigeroCommitment commitment = ProduceCommitment(fft, subFieldBytes, witnessFlipIndex: -1))
        {
            commitment.CopyRoot(root);
        }

        AssertHexEquals($"{prefix}_root", root, "The commitment root must match the reference.");

        //The opened-column indices.
        int[] expectedIndices = ParseIntList(Anchors[$"{prefix}_idx"]);
        Assert.IsTrue(proof.OpenedColumnIndices.SequenceEqual(expectedIndices), $"{prefix}: the opened-column indices must match the reference.");

        //The response rows.
        AssertElementsEqual($"{prefix}_yldt", proof.LowDegreeResponse, parameters.Block, $"{prefix}: y_ldt must match the reference.");
        AssertElementsEqual($"{prefix}_ydot", proof.DotResponse, parameters.DoubleBlock, $"{prefix}: y_dot must match the reference.");
        AssertElementsEqual($"{prefix}_yquad0", proof.QuadraticResponseLow, parameters.RandomCount, $"{prefix}: y_quad_0 must match the reference.");
        AssertElementsEqual($"{prefix}_yquad2", proof.QuadraticResponseHigh, parameters.DoubleBlock - parameters.Block, $"{prefix}: y_quad_2 must match the reference.");

        //The opened columns: one anchor line per tableau row.
        for(int i = 0; i < parameters.RowCount; i++)
        {
            ReadOnlySpan<byte> rowElements = proof.OpenedColumns.Slice(i * OpenedColumnCount * ScalarSize, OpenedColumnCount * ScalarSize);
            AssertElementsEqual($"{prefix}_req{i}", rowElements, OpenedColumnCount, $"{prefix}: opened-column row {i} must match the reference.");
        }

        //The per-leaf nonces.
        for(int j = 0; j < OpenedColumnCount; j++)
        {
            AssertHexEquals($"{prefix}_nonce{j}", proof.Nonce(j), $"{prefix}: opened-column nonce {j} must match the reference.");
        }

        //The compressed Merkle multi-proof.
        int expectedPathLength = int.Parse(Anchors[$"{prefix}_pathlen"], System.Globalization.CultureInfo.InvariantCulture);
        Assert.AreEqual(expectedPathLength, proof.MerklePathLength, $"{prefix}: the compressed multi-proof length must match the reference.");
        for(int i = 0; i < expectedPathLength; i++)
        {
            AssertHexEquals($"{prefix}_path{i}", proof.PathDigest(i), $"{prefix}: multi-proof digest {i} must match the reference.");
        }
    }


    //Replays the transcript exactly as Prove drives it through the response absorbs, returning the idx
    //subset drawn from the given (possibly tampered) responses. The challenges before the responses are
    //identical regardless of the responses, so only the absorbed responses can move idx.
    private static int[] ReplayOpenedIndices(LongfellowLigeroParameters parameters, ReadOnlySpan<byte> yLdt, ReadOnlySpan<byte> yDot, ReadOnlySpan<byte> yQuad0, ReadOnlySpan<byte> yQuad2)
    {
        Span<byte> root = stackalloc byte[DigestSize];
        using(Lch14AdditiveFft fft = NewFft(Lch14Subfield.Production16))
        using(LongfellowLigeroCommitment commitment = ProduceCommitment(fft, Production16SubFieldBytes, witnessFlipIndex: -1))
        {
            commitment.CopyRoot(root);
        }

        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        transcript.AbsorbCommitmentRoot(root);
        transcript.AbsorbByteString(TheoremStatementHash());

        int nwqrow = parameters.WitnessQuadraticRowCount;
        int nq = parameters.QuadraticConstraintCount;
        int nqtriples = parameters.QuadraticTripleCount;
        SqueezeAndDiscard(transcript, nwqrow);
        SqueezeAndDiscard(transcript, WitnessCount);
        SqueezeAndDiscard(transcript, 3 * nq);
        SqueezeAndDiscard(transcript, nqtriples);

        AbsorbResponseRow(transcript, yLdt, parameters.Block);
        AbsorbResponseRow(transcript, yDot, parameters.DoubleBlock);
        AbsorbResponseRow(transcript, yQuad0, parameters.RandomCount);
        AbsorbResponseRow(transcript, yQuad2, parameters.DoubleBlock - parameters.Block);

        int[] indices = new int[OpenedColumnCount];
        transcript.SqueezeIndexSubset(parameters.BlockExtension, OpenedColumnCount, indices);

        return indices;
    }


    private static void SqueezeAndDiscard(LongfellowTranscript transcript, int count)
    {
        Span<byte> element = stackalloc byte[ElementBytes];
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElementBytes(element);
        }
    }


    private static void AbsorbResponseRow(LongfellowTranscript transcript, ReadOnlySpan<byte> canonical, int count)
    {
        Span<byte> littleEndian = stackalloc byte[count == 0 ? 1 : count * ElementBytes];
        for(int i = 0; i < count; i++)
        {
            ToBytesField(canonical.Slice(i * ScalarSize, ScalarSize), littleEndian.Slice(i * ElementBytes, ElementBytes));
        }

        transcript.AbsorbFieldElementArray(littleEndian[..(count * ElementBytes)], count);
    }


    //Commits the fixed witness set over the given subfield, absorbs the root, and proves, returning the
    //proof. The witness flip and the seed are parameters for the adversarial gates.
    private static LongfellowLigeroProof ProduceProof(Lch14AdditiveFft fft, int subFieldBytes, int witnessFlipIndex, ReadOnlySpan<byte> seed)
    {
        var parameters = NewParameters(subFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses, witnessFlipIndex);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];

        LigeroLinearConstraint[] linearConstraints = BuildLinearConstraints(fft);

        LongfellowRandomByteSource random = NewCounterSource();
        using LongfellowLigeroCommitment commitment = LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), LongfellowGf2k128Encoding.CreateProfile(fft),
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);

        Span<byte> root = stackalloc byte[DigestSize];
        commitment.CopyRoot(root);

        using LongfellowTranscript transcript = NewTranscript(seed);
        transcript.AbsorbCommitmentRoot(root);

        LongfellowLigeroProof proof = LongfellowLigeroProver.Prove(
            commitment, transcript, WitnessCount, linearConstraints, TheoremStatementHash(), quadraticConstraints,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), LongfellowGf2k128Encoding.CreateProfile(fft),
            Add, Subtract, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        witnesses.Clear();

        return proof;
    }


    //Commits only (for the root cross-check and the transcript replay).
    private static LongfellowLigeroCommitment ProduceCommitment(Lch14AdditiveFft fft, int subFieldBytes, int witnessFlipIndex)
    {
        var parameters = NewParameters(subFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses, witnessFlipIndex);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];

        LongfellowRandomByteSource random = NewCounterSource();
        LongfellowLigeroCommitment commitment = LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), LongfellowGf2k128Encoding.CreateProfile(fft),
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);

        witnesses.Clear();

        return commitment;
    }


    private static LongfellowLigeroParameters NewParameters(int subFieldBytes) =>
        new(WitnessCount, QuadraticConstraintCount, InverseRate, OpenedColumnCount, FieldBytes, subFieldBytes);


    //W[i] = of_scalar(i + 1) (NodeElement(i+1)), then W[2] = W[0]·W[1] to satisfy the one quadratic
    //constraint. An optional flip XORs one low bit of a witness, then W[2] is recomputed.
    private static void BuildWitnesses(Lch14AdditiveFft fft, Span<byte> witnesses, int witnessFlipIndex)
    {
        for(int i = 0; i < WitnessCount; i++)
        {
            fft.NodeElement((uint)(i + 1), witnesses.Slice(i * ScalarSize, ScalarSize));
        }

        if(witnessFlipIndex >= 0)
        {
            witnesses[(witnessFlipIndex * ScalarSize) + ScalarSize - 1] ^= 0x01;
        }

        Multiply(witnesses[..ScalarSize], witnesses.Slice(ScalarSize, ScalarSize), witnesses.Slice(2 * ScalarSize, ScalarSize), CurveParameterSet.None);
    }


    //The harness's linear constraints: nl = nw constraints, one term each. Constraint c selects
    //witness c with coefficient of_scalar(c+1) = NodeElement(c+1). The targets b are b[c] = k·W[c],
    //which the prover never sees (only the verifier checks them); the prover only needs the terms.
    private static LigeroLinearConstraint[] BuildLinearConstraints(Lch14AdditiveFft fft)
    {
        var constraints = new LigeroLinearConstraint[WitnessCount];
        for(int c = 0; c < WitnessCount; c++)
        {
            byte[] coefficient = new byte[ScalarSize];
            fft.NodeElement((uint)(c + 1), coefficient);
            constraints[c] = new LigeroLinearConstraint(c, c, coefficient);
        }

        return constraints;
    }


    //The fixed 32-byte theorem statement the harness absorbs: 0x10, 0x11, ..., 0x2f.
    private static byte[] TheoremStatementHash()
    {
        byte[] hash = new byte[DigestSize];
        for(int i = 0; i < DigestSize; i++)
        {
            hash[i] = (byte)(0x10 + i);
        }

        return hash;
    }


    //A fresh deterministic counter source: the k-th byte produced is (k & 0xFF), identical to the C++
    //oracle's CounterRandomEngine. Each call returns a new source so a test restarts the stream at 0.
    private static LongfellowRandomByteSource NewCounterSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(counter & 0xFF);
                counter++;
            }
        };
    }


    private static LongfellowTranscript NewTranscript(ReadOnlySpan<byte> seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Lch14AdditiveFft NewFft(Lch14Subfield subfield) =>
        new(subfield, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    //to_bytes_field: the low 16 big-endian bytes of a canonical scalar reverse into 16 little-endian
    //element bytes.
    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    //The reference's node combine: SHA256(left || right).
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    //The one-shot leaf/snapshot hash: SHA256 over the whole input span.
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    //AES-256-ECB over a single 16-byte block with no padding: the transcript PRF's block transform.
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    //Asserts a comma-separated run of `count` 16-byte little-endian elements equals the canonical
    //scalars, comparing the reference's to_bytes_field framing against the canonical scalar's low bytes.
    private static void AssertElementsEqual(string label, ReadOnlySpan<byte> canonicalElements, int count, string message)
    {
        string[] hexElements = Anchors[label].Split(',', StringSplitOptions.RemoveEmptyEntries);
        Assert.HasCount(count, hexElements, $"{message} (the anchor must carry {count} elements).");

        Span<byte> littleEndian = stackalloc byte[ElementBytes];
        for(int i = 0; i < count; i++)
        {
            ToBytesField(canonicalElements.Slice(i * ScalarSize, ScalarSize), littleEndian);
            byte[] expected = Convert.FromHexString(hexElements[i]);
            Assert.IsTrue(littleEndian.SequenceEqual(expected), $"{message} (element {i} differs).");
        }
    }


    private static void AssertHexEquals(string label, ReadOnlySpan<byte> actual, string message)
    {
        byte[] expected = Convert.FromHexString(Anchors[label]);
        Assert.IsTrue(actual.SequenceEqual(expected), $"{message} (label {label}).");
    }


    private static int[] ParseIntList(string commaList)
    {
        string[] tokens = commaList.Split(',', StringSplitOptions.RemoveEmptyEntries);
        int[] values = new int[tokens.Length];
        for(int i = 0; i < tokens.Length; i++)
        {
            values[i] = int.Parse(tokens[i], System.Globalization.CultureInfo.InvariantCulture);
        }

        return values;
    }


    //Parses the oracle dump into a label -> value map. Each line is "label=value" or a space-separated
    //run of such tokens (the _param line); values never contain spaces.
    private static Dictionary<string, string> LoadAnchors()
    {
        string path = $"../../../{DumpRelativePath}";
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
