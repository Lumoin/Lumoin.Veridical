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
/// The wire-format-conformant Ligero PROVE flow, gated as a faithful port of
/// google/longfellow-zk's <c>lib/ligero/ligero_prover.h</c> <c>prove()</c> over the commitment step and the
/// transcript step, anchored to a complete reference-computed proof reproduced field by field.
/// </summary>
/// <remarks>
/// <para>
/// The anchor file (prove-anchor-output.txt in TestMaterial/Longfellow) records a run of the real
/// <c>LigeroProver::commit()+prove()</c> and the real <c>LigeroProof</c> with the deterministic
/// counter random engine and a fixed transcript seed: the commitment root, the challenge arrays
/// exactly as squeezed (<c>u_ldt</c>, <c>alphal</c>, <c>alphaq</c>, <c>u_quad</c>), the response rows
/// (<c>y_ldt</c>, <c>y_dot</c>, <c>y_quad_0</c>, <c>y_quad_2</c>), the opened columns (<c>req</c>, one
/// row per tableau row), the opened-column indices (<c>idx</c>), each opened column's per-leaf nonce,
/// and the compressed Merkle multi-proof path. Its <c>verify=1</c> confirms
/// <c>LigeroVerifier::verify()</c> accepts the proof, so the gate reproduces a verifying proof.
/// </para>
/// <para>
/// The C# gates reproduce every field byte for byte through the real commitment-step and
/// transcript-step ports, over both subfields the reference instantiates (production GF(2^16) and test-parity
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
    /// <summary>The relative path to this gate's reference-computed prove-flow anchor values.</summary>
    private const string AnchorRelativePath = "TestMaterial/Longfellow/prove-anchor-output.txt";

    /// <summary>The width in bytes of one field element in its canonical scalar representation.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The SHA-256 digest width in bytes: the commitment root and the theorem-statement hash.</summary>
    private const int DigestSize = 32;

    /// <summary>The on-wire GF(2^128) element width in bytes.</summary>
    private const int ElementBytes = 16;

    /// <summary>The full GF(2^128) field element width in bytes.</summary>
    private const int FieldBytes = 16;

    /// <summary>The production GF(2^16) subfield's element width in bytes.</summary>
    private const int Production16SubFieldBytes = 2;

    /// <summary>The test-parity GF(2^32) subfield's element width in bytes.</summary>
    private const int TestParity32SubFieldBytes = 4;

    /// <summary>The fixed prove tuple's witness count the harness drives.</summary>
    private const int WitnessCount = 8;

    /// <summary>The fixed prove tuple's quadratic-constraint count the harness drives: one, <c>W[0]·W[1]=W[2]</c>.</summary>
    private const int QuadraticConstraintCount = 1;

    /// <summary>The fixed prove tuple's Ligero code inverse rate the harness drives.</summary>
    private const int InverseRate = 4;

    /// <summary>The fixed prove tuple's opened-column count the harness drives.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The transcript wire-format version this gate's transcript is seeded with.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The fixed transcript seed ("c4") the honest prove flow uses, so the transcript's driven values are deterministic across runs.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("c4");

    /// <summary>The GF(2^128) field addition delegate every gate in this file drives the commit and prove flows through.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate every gate in this file drives the commit and prove flows through.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate every gate in this file drives the commit and prove flows through.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate the FFT construction requires.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The reference-computed values loaded from <see cref="AnchorRelativePath"/>, keyed by field name.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors();


    /// <summary>Verifies that a proof produced over the production GF(2^16) subfield matches the reference field by field.</summary>
    [TestMethod]
    public void TheProofMatchesTheReferenceForTheProductionSubfield()
    {
        AssertProofMatchesReference(Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
    }


    /// <summary>Verifies that a proof produced over the test-parity GF(2^32) subfield matches the reference field by field.</summary>
    [TestMethod]
    public void TheProofMatchesTheReferenceForTheTestParitySubfield()
    {
        AssertProofMatchesReference(Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    /// <summary>Verifies that flipping one bit of a witness element changes both the low-degree response and the opened columns relative to the honest proof.</summary>
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


    /// <summary>Verifies that proving with a different transcript seed changes both the low-degree response and the drawn opened-column indices relative to the honest proof.</summary>
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


    /// <summary>Verifies that flipping one byte of the absorbed dot response, replayed through the transcript, changes the drawn opened-column indices for at least one byte position — the commit-then-challenge binding.</summary>
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


    /// <summary>Builds the proof through the real commitment step, transcript step and prove step, then asserts every field equals the reference for the given subfield prefix.</summary>
    private static void AssertProofMatchesReference(Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        using Lch14AdditiveFft fft = NewFft(subfield);
        using LongfellowLigeroProof proof = ProduceProof(fft, subFieldBytes, witnessFlipIndex: -1, TranscriptSeed);
        var parameters = NewParameters(subFieldBytes);

        //The commitment root (identical to the commitment step's anchor).
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


    /// <summary>
    /// Replays the transcript exactly as <c>Prove</c> drives it through the response absorbs,
    /// returning the <c>idx</c> subset drawn from the given (possibly tampered) responses. The
    /// challenges before the responses are identical regardless of the responses, so only the
    /// absorbed responses can move <c>idx</c>.
    /// </summary>
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


    /// <summary>Squeezes and discards <paramref name="count"/> field elements from the transcript, replaying a challenge draw whose value is not otherwise needed.</summary>
    private static void SqueezeAndDiscard(LongfellowTranscript transcript, int count)
    {
        Span<byte> element = stackalloc byte[ElementBytes];
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElementBytes(element);
        }
    }


    /// <summary>Converts <paramref name="count"/> canonical scalars to on-wire little-endian elements and absorbs them as one array into the transcript.</summary>
    private static void AbsorbResponseRow(LongfellowTranscript transcript, ReadOnlySpan<byte> canonical, int count)
    {
        Span<byte> littleEndian = stackalloc byte[count == 0 ? 1 : count * ElementBytes];
        for(int i = 0; i < count; i++)
        {
            ToBytesField(canonical.Slice(i * ScalarSize, ScalarSize), littleEndian.Slice(i * ElementBytes, ElementBytes));
        }

        transcript.AbsorbFieldElementArray(littleEndian[..(count * ElementBytes)], count);
    }


    /// <summary>Commits the fixed witness set over the given subfield, absorbs the root, and proves, returning the proof. <paramref name="witnessFlipIndex"/> and <paramref name="seed"/> are parameters for the adversarial gates.</summary>
    private static LongfellowLigeroProof ProduceProof(Lch14AdditiveFft fft, int subFieldBytes, int witnessFlipIndex, ReadOnlySpan<byte> seed)
    {
        var parameters = NewParameters(subFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses, witnessFlipIndex);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];

        LigeroLinearConstraint[] linearConstraints = BuildLinearConstraints(fft);

        LongfellowRandomByteSource random = NewCounterSource();
        using LongfellowFieldProfile commitProfile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        using LongfellowLigeroCommitment commitment = LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), commitProfile,
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);

        Span<byte> root = stackalloc byte[DigestSize];
        commitment.CopyRoot(root);

        using LongfellowTranscript transcript = NewTranscript(seed);
        transcript.AbsorbCommitmentRoot(root);

        using LongfellowFieldProfile proveProfile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowLigeroProof proof = LongfellowLigeroProver.Prove(
            commitment, transcript, WitnessCount, linearConstraints, TheoremStatementHash(), quadraticConstraints,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), proveProfile,
            Add, Subtract, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        witnesses.Clear();

        return proof;
    }


    /// <summary>Commits the fixed witness set only, for the root cross-check and the transcript replay.</summary>
    private static LongfellowLigeroCommitment ProduceCommitment(Lch14AdditiveFft fft, int subFieldBytes, int witnessFlipIndex)
    {
        var parameters = NewParameters(subFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses, witnessFlipIndex);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];

        LongfellowRandomByteSource random = NewCounterSource();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowLigeroCommitment commitment = LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), profile,
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);

        witnesses.Clear();

        return commitment;
    }


    /// <summary>Builds the fixed prove tuple's Ligero parameters at the given subfield width.</summary>
    private static LongfellowLigeroParameters NewParameters(int subFieldBytes) =>
        new(WitnessCount, QuadraticConstraintCount, InverseRate, OpenedColumnCount, FieldBytes, subFieldBytes);


    /// <summary>
    /// Builds <c>W[i] = of_scalar(i + 1)</c> (<c>NodeElement(i+1)</c>), then <c>W[2] = W[0]·W[1]</c> to
    /// satisfy the one quadratic constraint. An optional flip at <paramref name="witnessFlipIndex"/>
    /// XORs one low bit of a witness before <c>W[2]</c> is recomputed.
    /// </summary>
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


    /// <summary>
    /// Builds the harness's linear constraints: <c>nl = nw</c> constraints, one term each. Constraint
    /// <c>c</c> selects witness <c>c</c> with coefficient <c>of_scalar(c+1) = NodeElement(c+1)</c>. The
    /// targets <c>b</c> are <c>b[c] = k·W[c]</c>, which the prover never sees (only the verifier checks
    /// them); the prover only needs the terms.
    /// </summary>
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


    /// <summary>Builds the fixed 32-byte theorem statement the harness absorbs: <c>0x10, 0x11, ..., 0x2f</c>.</summary>
    private static byte[] TheoremStatementHash()
    {
        byte[] hash = new byte[DigestSize];
        for(int i = 0; i < DigestSize; i++)
        {
            hash[i] = (byte)(0x10 + i);
        }

        return hash;
    }


    /// <summary>
    /// Creates a fresh deterministic counter source: the <c>k</c>-th byte produced is <c>(k &amp;
    /// 0xFF)</c>, identical to the reference's <c>CounterRandomEngine</c>. Each call returns a new
    /// source so a test restarts the stream at zero.
    /// </summary>
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


    /// <summary>Creates a transcript seeded with <paramref name="seed"/>, wired to this file's AES-256-ECB and SHA-256 delegates.</summary>
    private static LongfellowTranscript NewTranscript(ReadOnlySpan<byte> seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates the additive FFT over <paramref name="subfield"/>, driven by this file's GF(2^128) field delegates.</summary>
    private static Lch14AdditiveFft NewFft(Lch14Subfield subfield) =>
        new(subfield, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>The reference's <c>to_bytes_field</c>: the low 16 big-endian bytes of a canonical scalar reverse into 16 little-endian element bytes.</summary>
    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    /// <summary>The reference's node combine: <c>SHA256(left ‖ right)</c>.</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The one-shot leaf/snapshot hash: SHA-256 over the whole input span; <paramref name="hashFunction"/> is unused since this file only ever selects SHA-256.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    /// <summary>AES-256-ECB over a single 16-byte block with no padding: the transcript PRF's block transform.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Asserts a comma-separated run of <paramref name="count"/> 16-byte little-endian elements equals the canonical scalars, comparing the reference's <c>to_bytes_field</c> framing against the canonical scalar's low bytes.</summary>
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


    /// <summary>Asserts that <paramref name="actual"/> equals the reference anchor's hex-decoded bytes keyed by <paramref name="label"/>.</summary>
    private static void AssertHexEquals(string label, ReadOnlySpan<byte> actual, string message)
    {
        byte[] expected = Convert.FromHexString(Anchors[label]);
        Assert.IsTrue(actual.SequenceEqual(expected), $"{message} (label {label}).");
    }


    /// <summary>Parses a comma-separated run of decimal integers.</summary>
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


    /// <summary>Parses the anchor file into a label-to-value map. Each line is <c>label=value</c> or a space-separated run of such tokens (the <c>_param</c> line); values never contain spaces.</summary>
    private static Dictionary<string, string> LoadAnchors()
    {
        string path = $"../../../{AnchorRelativePath}";
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
