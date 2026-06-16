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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The wire-format-conformant Ligero proof BYTE SERIALIZATION (conformance step C.6), gated as a faithful
/// port of google/longfellow-zk's <c>ZkProof&lt;Field&gt;::write_com_proof</c> / <c>read_com_proof</c>
/// (<c>lib/zk/zk_proof.h</c>) — the lowest real serialization boundary the reference exposes for the
/// Ligero layer. C.5 proved the forward half of the cross-implementation loop (their proof verifies in
/// ours); C.6 closes it: our serialized bytes equal the reference's byte for byte, our reader parses the
/// reference's bytes into a verifying proof, and — recorded by the reference verifier in the Docker
/// oracle — our prover's serialized bytes verify in THEIR verifier.
/// </summary>
/// <remarks>
/// <para>
/// The serialize anchor (serialize-anchor-output.txt in TestMaterial/Longfellow) is computed by the
/// reference implementation in its own build environment via development tooling outside this repository.
/// It re-runs the real <c>LigeroProver::commit()+prove()</c> with the fixed deterministic inputs, then
/// serializes the resulting <c>LigeroProof</c> through the real <c>write_com_proof</c>, dumping the bytes
/// (<c>*_ligero_bytes</c>). Its <c>*_ref_roundtrip=1</c> confirms the reference's own reader round-trips
/// them; its <c>*_reverse_verify=1 why=ok</c> records that our prover's bytes, fed through the reference
/// reader and verifier, are accepted.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Round-trip</b>: our prover's proof is written, read back, and every field matches; the read-back proof verifies in our C.5 verifier.</description></item>
///   <item><description><b>Reference bytes — Write</b>: the reference proof reconstructed from the C.4 dump serializes (our Write) to exactly the anchor's <c>*_ligero_bytes</c>, exercising the subfield run-length optimization (a full-field run, a subfield run, a full-field run, then the path).</description></item>
///   <item><description><b>Reference bytes — Read</b>: our Read of the anchor's <c>*_ligero_bytes</c> yields a proof our verifier accepts.</description></item>
///   <item><description><b>Reverse round-trip</b>: the recorded <c>*_reverse_verify=1 why=ok</c> is asserted, the closing half of the loop.</description></item>
///   <item><description><b>Helper</b>: writes our prover's serialized bytes to the anchor folder so the harness can feed them to the reference verifier (skipped when the folder is absent — e.g. on a non-developer machine).</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class LongfellowLigeroSerializeTests
{
    private const string ProveDumpRelativePath = "TestMaterial/Longfellow/prove-anchor-output.txt";
    private const string SerializeDumpRelativePath = "TestMaterial/Longfellow/serialize-anchor-output.txt";

    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSize = 32;
    private const int NonceSize = 32;
    private const int ElementBytes = 16;

    private const int FieldBytes = 16;
    private const int Production16SubFieldBytes = 2;
    private const int TestParity32SubFieldBytes = 4;

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

    private static Dictionary<string, string> ProveAnchors { get; } = LoadAnchors(ProveDumpRelativePath);

    private static Dictionary<string, string> SerializeAnchors { get; } = LoadAnchors(SerializeDumpRelativePath);


    [TestMethod]
    public void TheProofRoundTripsForTheProductionSubfield()
    {
        AssertProofRoundTrips(Lch14Subfield.Production16, Production16SubFieldBytes);
    }


    [TestMethod]
    public void TheProofRoundTripsForTheTestParitySubfield()
    {
        AssertProofRoundTrips(Lch14Subfield.TestParity32, TestParity32SubFieldBytes);
    }


    [TestMethod]
    public void OurWriteMatchesTheReferenceBytesForTheProductionSubfield()
    {
        AssertWriteMatchesReference(Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
    }


    [TestMethod]
    public void OurWriteMatchesTheReferenceBytesForTheTestParitySubfield()
    {
        AssertWriteMatchesReference(Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    [TestMethod]
    public void OurReadOfTheReferenceBytesVerifiesForTheProductionSubfield()
    {
        AssertReadOfReferenceVerifies(Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
    }


    [TestMethod]
    public void OurReadOfTheReferenceBytesVerifiesForTheTestParitySubfield()
    {
        AssertReadOfReferenceVerifies(Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    [TestMethod]
    public void TheReferenceReaderRoundTripsOurReferenceBytes()
    {
        //The harness records that the reference's own read_com_proof parses *_ligero_bytes and
        //re-serializes them identically. This pins the anchor's internal consistency.
        Assert.AreEqual("1", SerializeAnchors["q16_ref_roundtrip"], "q16: the reference reader must round-trip the dumped bytes.");
        Assert.AreEqual("1", SerializeAnchors["q32_ref_roundtrip"], "q32: the reference reader must round-trip the dumped bytes.");
    }


    [TestMethod]
    public void OurBytesVerifyInTheReferenceVerifierForTheProductionSubfield()
    {
        AssertReverseRoundTripRecorded("q16");
    }


    [TestMethod]
    public void OurBytesVerifyInTheReferenceVerifierForTheTestParitySubfield()
    {
        AssertReverseRoundTripRecorded("q32");
    }


    [TestMethod]
    public void WritesOurProofBytesForTheReverseHarness()
    {
        //A developer-machine helper: writes our prover's serialized Ligero bytes into the anchor folder
        //(tempdocs/longfellow-anchors) so the reverse harness can feed them to the reference verifier. On
        //a machine without the anchor folder (a non-developer checkout) there is nothing to feed, so the
        //helper is inconclusive rather than failing.
        string? anchorFolder = LocateAnchorFolder();
        if(anchorFolder is null)
        {
            Assert.Inconclusive("The anchor folder (tempdocs/longfellow-anchors) is not present; the reverse harness is a developer-machine step.");

            return;
        }

        WriteOurProofBytes(anchorFolder, Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
        WriteOurProofBytes(anchorFolder, Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    //Produces our proof, writes it, reads it back, and asserts every field matches and the read-back
    //proof verifies in the C.5 verifier.
    private static void AssertProofRoundTrips(Lch14Subfield subfield, int subFieldBytes)
    {
        var parameters = NewParameters(subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);
        using LongfellowLigeroProof proof = ProduceProof(fft, subFieldBytes, out byte[] root, out byte[] linearTargets);

        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        int size = LongfellowLigeroProofSerializer.SerializedSize(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(size);
        Span<byte> buffer = bufferOwner.Memory.Span[..size];
        int written = LongfellowLigeroProofSerializer.Write(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared, buffer);

        Assert.AreEqual(size, written, "Write must consume exactly the computed serialized size.");

        using LongfellowLigeroProof? parsed = LongfellowLigeroProofSerializer.Read(parameters, subFieldBytes, profile, fft, BaseMemoryPool.Shared, buffer, out int read);

        Assert.IsNotNull(parsed, "Read must parse the bytes our Write produced.");
        Assert.AreEqual(written, read, "Read must consume exactly the bytes Write produced.");

        AssertProofFieldsEqual(proof, parsed, parameters);

        //The read-back proof must verify in the C.5 verifier (idx is re-derived by the verifier's
        //transcript replay, so the parsed proof's zeroed indices are immaterial).
        bool accepted = RunVerify(parameters, fft, parsed, root, linearTargets, out LongfellowLigeroVerificationResult cause);
        Assert.IsTrue(accepted, $"The read-back proof must verify (cause {cause}).");
    }


    //Reconstructs the reference proof from the C.4 dump, serializes it (our Write), and asserts the bytes
    //equal the anchor's *_ligero_bytes — exercising the subfield run-length optimization.
    private static void AssertWriteMatchesReference(Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        var parameters = NewParameters(subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);
        using LongfellowLigeroProof proof = BuildReferenceProof(parameters, prefix);

        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        int size = LongfellowLigeroProofSerializer.SerializedSize(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(size);
        Span<byte> buffer = bufferOwner.Memory.Span[..size];
        int written = LongfellowLigeroProofSerializer.Write(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared, buffer);

        byte[] expected = Convert.FromHexString(SerializeAnchors[$"{prefix}_ligero_bytes"]);
        int expectedLength = int.Parse(SerializeAnchors[$"{prefix}_ligero_len"], System.Globalization.CultureInfo.InvariantCulture);

        Assert.HasCount(expectedLength, expected, $"{prefix}: the anchor length and the dumped bytes must agree.");
        Assert.AreEqual(expectedLength, written, $"{prefix}: our serialized length must match the reference.");
        Assert.IsTrue(buffer[..written].SequenceEqual(expected), $"{prefix}: our serialized bytes must equal the reference's write_com_proof output.");
    }


    //Reads the reference's *_ligero_bytes with our Read and asserts the parsed proof verifies.
    private static void AssertReadOfReferenceVerifies(Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        var parameters = NewParameters(subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);
        byte[] referenceBytes = Convert.FromHexString(SerializeAnchors[$"{prefix}_ligero_bytes"]);

        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        using LongfellowLigeroProof? parsed = LongfellowLigeroProofSerializer.Read(parameters, subFieldBytes, profile, fft, BaseMemoryPool.Shared, referenceBytes, out int read);

        Assert.IsNotNull(parsed, $"{prefix}: Read must parse the reference bytes.");
        Assert.AreEqual(referenceBytes.Length, read, $"{prefix}: Read must consume the whole reference byte buffer.");

        byte[] root = Convert.FromHexString(ProveAnchors[$"{prefix}_root"]);
        byte[] linearTargets = ParseCanonicalElements(ProveAnchors[$"{prefix}_b"], WitnessCount);

        bool accepted = RunVerify(parameters, fft, parsed, root, linearTargets, out LongfellowLigeroVerificationResult cause);
        Assert.IsTrue(accepted, $"{prefix}: the proof read from the reference bytes must verify (cause {cause}).");
    }


    //Asserts the recorded reverse round-trip result from the serialize anchor: our bytes verify in the
    //reference verifier. When the harness ran without our proof file present, the result is "absent" and
    //the assertion is inconclusive (the byte-equality gate already proves our bytes equal the reference's,
    //which the reference verifier accepts — the reverse harness is the explicit cross-tool confirmation).
    private static void AssertReverseRoundTripRecorded(string prefix)
    {
        string verdict = SerializeAnchors[$"{prefix}_reverse_verify"];
        if(verdict == "absent")
        {
            Assert.Inconclusive($"{prefix}: the reverse harness has not been run against our proof bytes (no recorded result).");

            return;
        }

        Assert.AreEqual("1", verdict, $"{prefix}: our serialized bytes must verify in the reference's LigeroVerifier.");
        Assert.AreEqual("ok", SerializeAnchors[$"{prefix}_reverse_verify_why"], $"{prefix}: the reference verdict must be ok.");
    }


    //Serializes our prover's proof and writes the bytes to the anchor folder for the reverse harness.
    private static void WriteOurProofBytes(string anchorFolder, Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        using Lch14AdditiveFft fft = NewFft(subfield);
        using LongfellowLigeroProof proof = ProduceProof(fft, subFieldBytes, out _, out _);

        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        int size = LongfellowLigeroProofSerializer.SerializedSize(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared);
        byte[] buffer = new byte[size];
        LongfellowLigeroProofSerializer.Write(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared, buffer);

        File.WriteAllBytes(Path.Combine(anchorFolder, $"our-ligero-proof-{prefix}.bin"), buffer);
    }


    //Asserts the response rows, opened columns, indices, nonces and Merkle path are identical between two
    //proofs. The parsed proof's indices are zeroed by Read (idx is not transmitted), so they are excluded.
    private static void AssertProofFieldsEqual(LongfellowLigeroProof expected, LongfellowLigeroProof actual, LongfellowLigeroParameters parameters)
    {
        Assert.IsTrue(actual.LowDegreeResponse.SequenceEqual(expected.LowDegreeResponse), "y_ldt must round-trip.");
        Assert.IsTrue(actual.DotResponse.SequenceEqual(expected.DotResponse), "y_dot must round-trip.");
        Assert.IsTrue(actual.QuadraticResponseLow.SequenceEqual(expected.QuadraticResponseLow), "y_quad_0 must round-trip.");
        Assert.IsTrue(actual.QuadraticResponseHigh.SequenceEqual(expected.QuadraticResponseHigh), "y_quad_2 must round-trip.");

        int columnBytes = parameters.RowCount * OpenedColumnCount * ScalarSize;
        Assert.IsTrue(actual.OpenedColumns[..columnBytes].SequenceEqual(expected.OpenedColumns[..columnBytes]), "The opened columns must round-trip.");

        for(int j = 0; j < OpenedColumnCount; j++)
        {
            Assert.IsTrue(actual.Nonce(j).SequenceEqual(expected.Nonce(j)), $"Nonce {j} must round-trip.");
        }

        Assert.AreEqual(expected.MerklePathLength, actual.MerklePathLength, "The Merkle path length must round-trip.");
        for(int i = 0; i < expected.MerklePathLength; i++)
        {
            Assert.IsTrue(actual.PathDigest(i).SequenceEqual(expected.PathDigest(i)), $"Merkle path digest {i} must round-trip.");
        }
    }


    //Drives the C.5 verifier over the given proof and public inputs.
    private static bool RunVerify(LongfellowLigeroParameters parameters, Lch14AdditiveFft fft, LongfellowLigeroProof proof, ReadOnlySpan<byte> root, byte[] linearTargets, out LongfellowLigeroVerificationResult cause)
    {
        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];
        LigeroLinearConstraint[] linearConstraints = BuildLinearConstraints(fft);

        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        transcript.AbsorbCommitmentRoot(root);

        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        return LongfellowLigeroVerifier.Verify(
            parameters, proof, root, transcript, TheoremStatementHash(),
            WitnessCount, linearConstraints, linearTargets, quadraticConstraints,
            encoderFactory, profile, Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None, BaseMemoryPool.Shared, out cause);
    }


    //Commits the fixed witness set, proves, and returns the proof plus the public verify inputs (root,
    //the linear targets b[c] = coefficient·W[c]).
    private static LongfellowLigeroProof ProduceProof(Lch14AdditiveFft fft, int subFieldBytes, out byte[] root, out byte[] linearTargets)
    {
        var parameters = NewParameters(subFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];
        LigeroLinearConstraint[] linearConstraints = BuildLinearConstraints(fft);

        LongfellowRandomByteSource random = NewCounterSource();
        using LongfellowLigeroCommitment commitment = LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), LongfellowGf2k128Encoding.CreateProfile(fft),
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);

        root = new byte[DigestSize];
        commitment.CopyRoot(root);

        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        transcript.AbsorbCommitmentRoot(root);

        LongfellowLigeroProof proof = LongfellowLigeroProver.Prove(
            commitment, transcript, WitnessCount, linearConstraints, TheoremStatementHash(), quadraticConstraints,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), LongfellowGf2k128Encoding.CreateProfile(fft),
            Add, Subtract, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        linearTargets = new byte[WitnessCount * ScalarSize];
        Span<byte> coefficient = stackalloc byte[ScalarSize];
        for(int c = 0; c < WitnessCount; c++)
        {
            fft.NodeElement((uint)(c + 1), coefficient);
            Multiply(coefficient, witnesses.Slice(c * ScalarSize, ScalarSize), linearTargets.AsSpan(c * ScalarSize, ScalarSize), CurveParameterSet.None);
        }

        witnesses.Clear();

        return proof;
    }


    //Reconstructs the reference proof from the C.4 prove dump (response rows, opened columns, nonces,
    //compressed path), the same reconstruction the C.5 verify gate uses.
    private static LongfellowLigeroProof BuildReferenceProof(LongfellowLigeroParameters parameters, string prefix)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int quadHigh = dblock - block;
        int rowCount = parameters.RowCount;

        IMemoryOwner<byte> responseOwner = BaseMemoryPool.Shared.Rent(LongfellowLigeroProof.ResponseBufferSize(parameters));
        IMemoryOwner<byte> openedColumnsOwner = BaseMemoryPool.Shared.Rent(rowCount * OpenedColumnCount * ScalarSize);
        IMemoryOwner<byte> indicesOwner = BaseMemoryPool.Shared.Rent(OpenedColumnCount * sizeof(int));
        IMemoryOwner<byte> nonceOwner = BaseMemoryPool.Shared.Rent(OpenedColumnCount * NonceSize);

        byte[] lowDegree = ParseCanonicalElements(ProveAnchors[$"{prefix}_yldt"], block);
        byte[] dot = ParseCanonicalElements(ProveAnchors[$"{prefix}_ydot"], dblock);
        byte[] quadLow = ParseCanonicalElements(ProveAnchors[$"{prefix}_yquad0"], r);
        byte[] quadHighElements = ParseCanonicalElements(ProveAnchors[$"{prefix}_yquad2"], quadHigh);

        Span<byte> responses = responseOwner.Memory.Span[..LongfellowLigeroProof.ResponseBufferSize(parameters)];
        lowDegree.CopyTo(responses[..(block * ScalarSize)]);
        dot.CopyTo(responses.Slice(block * ScalarSize, dblock * ScalarSize));
        quadLow.CopyTo(responses.Slice((block + dblock) * ScalarSize, r * ScalarSize));
        quadHighElements.CopyTo(responses.Slice(((block + dblock) * ScalarSize) + (r * ScalarSize), quadHigh * ScalarSize));

        Span<byte> openedColumns = openedColumnsOwner.Memory.Span[..(rowCount * OpenedColumnCount * ScalarSize)];
        for(int i = 0; i < rowCount; i++)
        {
            byte[] rowElements = ParseCanonicalElements(ProveAnchors[$"{prefix}_req{i}"], OpenedColumnCount);
            rowElements.CopyTo(openedColumns.Slice(i * OpenedColumnCount * ScalarSize, OpenedColumnCount * ScalarSize));
        }

        Span<int> indices = MemoryMarshal.Cast<byte, int>(indicesOwner.Memory.Span[..(OpenedColumnCount * sizeof(int))]);
        int[] parsedIndices = ParseIntList(ProveAnchors[$"{prefix}_idx"]);
        parsedIndices.CopyTo(indices);

        Span<byte> nonces = nonceOwner.Memory.Span[..(OpenedColumnCount * NonceSize)];
        for(int j = 0; j < OpenedColumnCount; j++)
        {
            byte[] nonce = Convert.FromHexString(ProveAnchors[$"{prefix}_nonce{j}"]);
            nonce.CopyTo(nonces.Slice(j * NonceSize, NonceSize));
        }

        int pathLength = int.Parse(ProveAnchors[$"{prefix}_pathlen"], System.Globalization.CultureInfo.InvariantCulture);
        IMemoryOwner<byte> pathOwner = BaseMemoryPool.Shared.Rent(Math.Max(pathLength, 1) * DigestSize);
        Span<byte> path = pathOwner.Memory.Span[..(Math.Max(pathLength, 1) * DigestSize)];
        for(int i = 0; i < pathLength; i++)
        {
            byte[] digest = Convert.FromHexString(ProveAnchors[$"{prefix}_path{i}"]);
            digest.CopyTo(path.Slice(i * DigestSize, DigestSize));
        }

        return new LongfellowLigeroProof(parameters, responseOwner, openedColumnsOwner, indicesOwner, nonceOwner, pathOwner, pathLength);
    }


    //W[i] = of_scalar(i + 1), then W[2] = W[0]·W[1] for the one quadratic constraint.
    private static void BuildWitnesses(Lch14AdditiveFft fft, Span<byte> witnesses)
    {
        for(int i = 0; i < WitnessCount; i++)
        {
            fft.NodeElement((uint)(i + 1), witnesses.Slice(i * ScalarSize, ScalarSize));
        }

        Multiply(witnesses[..ScalarSize], witnesses.Slice(ScalarSize, ScalarSize), witnesses.Slice(2 * ScalarSize, ScalarSize), CurveParameterSet.None);
    }


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


    private static byte[] TheoremStatementHash()
    {
        byte[] hash = new byte[DigestSize];
        for(int i = 0; i < DigestSize; i++)
        {
            hash[i] = (byte)(0x10 + i);
        }

        return hash;
    }


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


    private static LongfellowLigeroParameters NewParameters(int subFieldBytes) =>
        new(WitnessCount, QuadraticConstraintCount, InverseRate, OpenedColumnCount, FieldBytes, subFieldBytes);


    private static LongfellowTranscript NewTranscript(ReadOnlySpan<byte> seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Lch14AdditiveFft NewFft(Lch14Subfield subfield) =>
        new(subfield, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    //of_bytes_field: 16 little-endian element bytes reverse into the low 16 bytes of a 32-byte
    //big-endian canonical scalar.
    private static void FromBytesField(ReadOnlySpan<byte> littleEndian, Span<byte> canonical)
    {
        canonical.Clear();
        for(int i = 0; i < ElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }
    }


    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    //Parses a comma-separated run of `count` 16-byte little-endian elements into `count` canonical
    //big-endian scalars.
    private static byte[] ParseCanonicalElements(string commaList, int count)
    {
        string[] hexElements = count == 0 ? [] : commaList.Split(',', StringSplitOptions.RemoveEmptyEntries);
        Assert.HasCount(count, hexElements, $"The anchor must carry {count} elements.");

        byte[] canonical = new byte[count * ScalarSize];
        for(int i = 0; i < count; i++)
        {
            byte[] littleEndian = Convert.FromHexString(hexElements[i]);
            FromBytesField(littleEndian, canonical.AsSpan(i * ScalarSize, ScalarSize));
        }

        return canonical;
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


    //Locates tempdocs/longfellow-anchors by walking up from the test base directory. Returns null when
    //the folder is not present (a non-developer checkout).
    private static string? LocateAnchorFolder()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while(directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "tempdocs", "longfellow-anchors");
            if(Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        return null;
    }


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
