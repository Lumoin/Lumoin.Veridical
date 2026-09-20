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
/// The wire-format-conformant Ligero proof BYTE SERIALIZATION, gated as a faithful
/// port of google/longfellow-zk's <c>ZkProof&lt;Field&gt;::write_com_proof</c> / <c>read_com_proof</c>
/// (<c>lib/zk/zk_proof.h</c>) — the lowest real serialization boundary the reference exposes for the
/// Ligero layer. The verify step proved the forward half of the cross-implementation loop (their proof
/// verifies in ours); serialization closes it: our serialized bytes equal the reference's byte for byte,
/// our reader parses the reference's bytes into a verifying proof, and our prover's serialized bytes
/// verify in THEIR verifier.
/// </summary>
/// <remarks>
/// <para>
/// The serialize anchor's <c>*_ligero_bytes</c> is the reference's <c>write_com_proof</c> output for the
/// fixed deterministic inputs; its <c>*_ref_roundtrip=1</c> confirms the reference's own reader
/// round-trips them, and its <c>*_reverse_verify=1 why=ok</c> records that our prover's bytes, fed
/// through the reference reader and verifier, are accepted.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Round-trip</b>: our prover's proof is written, read back, and every field matches; the read-back proof verifies in our verify step.</description></item>
///   <item><description><b>Reference bytes — Write</b>: the reference proof reconstructed from the prove-step anchor serializes (our Write) to exactly the anchor's <c>*_ligero_bytes</c>, exercising the subfield run-length optimization (a full-field run, a subfield run, a full-field run, then the path).</description></item>
///   <item><description><b>Reference bytes — Read</b>: our Read of the anchor's <c>*_ligero_bytes</c> yields a proof our verifier accepts.</description></item>
///   <item><description><b>Reverse round-trip</b>: the recorded <c>*_reverse_verify=1 why=ok</c> is asserted, the closing half of the loop.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class LongfellowLigeroSerializeTests
{
    /// <summary>The repository-relative path to the prove-step anchor file, loaded once into <see cref="ProveAnchors"/>.</summary>
    private const string ProveAnchorRelativePath = "TestMaterial/Longfellow/prove-anchor-output.txt";

    /// <summary>The repository-relative path to the serialization anchor file, loaded once into <see cref="SerializeAnchors"/>.</summary>
    private const string SerializeAnchorRelativePath = "TestMaterial/Longfellow/serialize-anchor-output.txt";

    /// <summary>The byte width of one canonical scalar, taken from <see cref="Scalar.SizeBytes"/>.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The byte width of a SHA-256 digest, used for the commitment root and each Merkle path entry.</summary>
    private const int DigestSize = 32;

    /// <summary>The byte width of the per-column opening nonce.</summary>
    private const int NonceSize = 32;

    /// <summary>The byte width of one little-endian field element as the reference tool encodes it, half the canonical scalar width.</summary>
    private const int ElementBytes = 16;

    /// <summary>The full-field element width in bytes, passed to <see cref="LongfellowLigeroParameters"/> as the base field width.</summary>
    private const int FieldBytes = 16;

    /// <summary>The subfield element width in bytes for the production GF(2^128) subfield, <c>Lch14Subfield.Production16</c>.</summary>
    private const int Production16SubFieldBytes = 2;

    /// <summary>The subfield element width in bytes for the test-parity GF(2^128) subfield, <c>Lch14Subfield.TestParity32</c>.</summary>
    private const int TestParity32SubFieldBytes = 4;

    /// <summary>The number of witness values committed in every test proof; W[2] = W[0]·W[1] is the one quadratic constraint among them.</summary>
    private const int WitnessCount = 8;

    /// <summary>The number of quadratic constraints the test parameters declare: exactly the one constraint W[2] = W[0]·W[1].</summary>
    private const int QuadraticConstraintCount = 1;

    /// <summary>The Reed-Solomon code rate's inverse used by the test parameters.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of columns the verifier opens per proof, matching the anchor's two recorded query indices.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The transcript version tag passed to <see cref="NewTranscript"/>, matching the anchor's fixed transcript configuration.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The fixed transcript seed, the ASCII bytes of <c>c4</c>, shared by every test in this file and matching the anchor's recorded seed.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("c4");

    /// <summary>The GF(2^128) addition delegate used to build witnesses, constraints and verifier inputs throughout this file.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate passed to the prover, verifier and additive FFT.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate used to build the witness set, the quadratic constraint and the linear targets.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate passed to <see cref="NewFft"/>.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The prove-step anchor's key/value pairs, loaded once from <see cref="ProveAnchorRelativePath"/>.</summary>
    private static Dictionary<string, string> ProveAnchors { get; } = LoadAnchors(ProveAnchorRelativePath);

    /// <summary>The serialization anchor's key/value pairs, loaded once from <see cref="SerializeAnchorRelativePath"/>.</summary>
    private static Dictionary<string, string> SerializeAnchors { get; } = LoadAnchors(SerializeAnchorRelativePath);


    /// <summary>
    /// Verifies that a proof produced over the production GF(2^128) subfield survives a write/read
    /// round trip with every field intact and still verifies.
    /// </summary>
    [TestMethod]
    public void TheProofRoundTripsForTheProductionSubfield()
    {
        AssertProofRoundTrips(Lch14Subfield.Production16, Production16SubFieldBytes);
    }


    /// <summary>
    /// Verifies that a proof produced over the test-parity GF(2^128) subfield survives a write/read
    /// round trip with every field intact and still verifies.
    /// </summary>
    [TestMethod]
    public void TheProofRoundTripsForTheTestParitySubfield()
    {
        AssertProofRoundTrips(Lch14Subfield.TestParity32, TestParity32SubFieldBytes);
    }


    /// <summary>
    /// Verifies that serializing the reference-reconstructed proof for the production subfield
    /// reproduces the reference implementation's own <c>write_com_proof</c> bytes exactly.
    /// </summary>
    [TestMethod]
    public void OurWriteMatchesTheReferenceBytesForTheProductionSubfield()
    {
        AssertWriteMatchesReference(Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
    }


    /// <summary>
    /// Verifies that serializing the reference-reconstructed proof for the test-parity subfield
    /// reproduces the reference implementation's own <c>write_com_proof</c> bytes exactly.
    /// </summary>
    [TestMethod]
    public void OurWriteMatchesTheReferenceBytesForTheTestParitySubfield()
    {
        AssertWriteMatchesReference(Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    /// <summary>
    /// Verifies that reading the reference implementation's serialized production-subfield proof
    /// bytes yields a proof that verifies against the recorded public inputs.
    /// </summary>
    [TestMethod]
    public void OurReadOfTheReferenceBytesVerifiesForTheProductionSubfield()
    {
        AssertReadOfReferenceVerifies(Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
    }


    /// <summary>
    /// Verifies that reading the reference implementation's serialized test-parity-subfield proof
    /// bytes yields a proof that verifies against the recorded public inputs.
    /// </summary>
    [TestMethod]
    public void OurReadOfTheReferenceBytesVerifiesForTheTestParitySubfield()
    {
        AssertReadOfReferenceVerifies(Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    /// <summary>
    /// Verifies that the anchor records the reference implementation's own reader round-tripping its
    /// bytes for both subfields, confirming the anchor's internal consistency.
    /// </summary>
    [TestMethod]
    public void TheReferenceReaderRoundTripsOurReferenceBytes()
    {
        //The recorded flag is set when the reference's own read_com_proof parses *_ligero_bytes and
        //re-serializes them identically, pinning the anchor's internal consistency.
        Assert.AreEqual("1", SerializeAnchors["q16_ref_roundtrip"], "q16: the reference reader must round-trip its recorded bytes.");
        Assert.AreEqual("1", SerializeAnchors["q32_ref_roundtrip"], "q32: the reference reader must round-trip its recorded bytes.");
    }


    /// <summary>
    /// Verifies that the anchor records our production-subfield proof bytes verifying successfully
    /// in the reference implementation's own verifier.
    /// </summary>
    [TestMethod]
    public void OurBytesVerifyInTheReferenceVerifierForTheProductionSubfield()
    {
        AssertReverseRoundTripRecorded("q16");
    }


    /// <summary>
    /// Verifies that the anchor records our test-parity-subfield proof bytes verifying successfully
    /// in the reference implementation's own verifier.
    /// </summary>
    [TestMethod]
    public void OurBytesVerifyInTheReferenceVerifierForTheTestParitySubfield()
    {
        AssertReverseRoundTripRecorded("q32");
    }


    /// <summary>
    /// Produces our proof, writes it, reads it back, and asserts every field matches and the
    /// read-back proof verifies in the verify step.
    /// </summary>
    private static void AssertProofRoundTrips(Lch14Subfield subfield, int subFieldBytes)
    {
        var parameters = NewParameters(subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);
        using LongfellowLigeroProof proof = ProduceProof(fft, subFieldBytes, out byte[] root, out byte[] linearTargets);

        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        int size = LongfellowLigeroProofSerializer.SerializedSize(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(size);
        Span<byte> buffer = bufferOwner.Memory.Span[..size];
        int written = LongfellowLigeroProofSerializer.Write(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared, buffer);

        Assert.AreEqual(size, written, "Write must consume exactly the computed serialized size.");

        using LongfellowLigeroProof? parsed = LongfellowLigeroProofSerializer.Read(parameters, subFieldBytes, profile, fft, BaseMemoryPool.Shared, buffer, out int read);

        Assert.IsNotNull(parsed, "Read must parse the bytes our Write produced.");
        Assert.AreEqual(written, read, "Read must consume exactly the bytes Write produced.");

        AssertProofFieldsEqual(proof, parsed, parameters);

        //The read-back proof must verify in the verify step (idx is re-derived by the verifier's
        //transcript replay, so the parsed proof's zeroed indices are immaterial).
        bool accepted = RunVerify(parameters, fft, parsed, root, linearTargets, out LongfellowLigeroVerificationResult cause);
        Assert.IsTrue(accepted, $"The read-back proof must verify (cause {cause}).");
    }


    /// <summary>
    /// Reconstructs the reference proof from the prove-step anchor, serializes it with our Write, and
    /// asserts the bytes equal the anchor's *_ligero_bytes, exercising the subfield run-length
    /// optimization.
    /// </summary>
    private static void AssertWriteMatchesReference(Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        var parameters = NewParameters(subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);
        using LongfellowLigeroProof proof = BuildReferenceProof(parameters, prefix);

        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        int size = LongfellowLigeroProofSerializer.SerializedSize(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(size);
        Span<byte> buffer = bufferOwner.Memory.Span[..size];
        int written = LongfellowLigeroProofSerializer.Write(proof, subFieldBytes, profile, fft, BaseMemoryPool.Shared, buffer);

        byte[] expected = Convert.FromHexString(SerializeAnchors[$"{prefix}_ligero_bytes"]);
        int expectedLength = int.Parse(SerializeAnchors[$"{prefix}_ligero_len"], System.Globalization.CultureInfo.InvariantCulture);

        Assert.HasCount(expectedLength, expected, $"{prefix}: the anchor length and its recorded bytes must agree.");
        Assert.AreEqual(expectedLength, written, $"{prefix}: our serialized length must match the reference.");
        Assert.IsTrue(buffer[..written].SequenceEqual(expected), $"{prefix}: our serialized bytes must equal the reference's write_com_proof output.");
    }


    /// <summary>
    /// Reads the reference's *_ligero_bytes with our Read and asserts the parsed proof verifies.
    /// </summary>
    private static void AssertReadOfReferenceVerifies(Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        var parameters = NewParameters(subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);
        byte[] referenceBytes = Convert.FromHexString(SerializeAnchors[$"{prefix}_ligero_bytes"]);

        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        using LongfellowLigeroProof? parsed = LongfellowLigeroProofSerializer.Read(parameters, subFieldBytes, profile, fft, BaseMemoryPool.Shared, referenceBytes, out int read);

        Assert.IsNotNull(parsed, $"{prefix}: Read must parse the reference bytes.");
        Assert.AreEqual(referenceBytes.Length, read, $"{prefix}: Read must consume the whole reference byte buffer.");

        byte[] root = Convert.FromHexString(ProveAnchors[$"{prefix}_root"]);
        byte[] linearTargets = ParseCanonicalElements(ProveAnchors[$"{prefix}_b"], WitnessCount);

        bool accepted = RunVerify(parameters, fft, parsed, root, linearTargets, out LongfellowLigeroVerificationResult cause);
        Assert.IsTrue(accepted, $"{prefix}: the proof read from the reference bytes must verify (cause {cause}).");
    }


    /// <summary>
    /// Asserts the recorded reverse round-trip result from the serialize anchor: our bytes verify in
    /// the reference verifier. The result can be <c>absent</c>, in which case the assertion is
    /// inconclusive, because the byte-equality gate already proves our bytes equal the reference's,
    /// which the reference verifier accepts; the recorded reverse verification is the explicit
    /// cross-tool confirmation of that acceptance.
    /// </summary>
    private static void AssertReverseRoundTripRecorded(string prefix)
    {
        string verdict = SerializeAnchors[$"{prefix}_reverse_verify"];
        if(verdict == "absent")
        {
            Assert.Inconclusive($"{prefix}: the reverse verification has not been recorded for our proof bytes.");

            return;
        }

        Assert.AreEqual("1", verdict, $"{prefix}: our serialized bytes must verify in the reference's LigeroVerifier.");
        Assert.AreEqual("ok", SerializeAnchors[$"{prefix}_reverse_verify_why"], $"{prefix}: the reference verdict must be ok.");
    }


    /// <summary>
    /// Asserts the response rows, opened columns, indices, nonces and Merkle path are identical
    /// between two proofs. The parsed proof's indices are zeroed by Read because idx is not
    /// transmitted, so they are excluded from the comparison.
    /// </summary>
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


    /// <summary>
    /// Drives the verify step over the given proof and public inputs.
    /// </summary>
    private static bool RunVerify(LongfellowLigeroParameters parameters, Lch14AdditiveFft fft, LongfellowLigeroProof proof, ReadOnlySpan<byte> root, byte[] linearTargets, out LongfellowLigeroVerificationResult cause)
    {
        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];
        LigeroLinearConstraint[] linearConstraints = BuildLinearConstraints(fft);

        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        transcript.AbsorbCommitmentRoot(root);

        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        return LongfellowLigeroVerifier.Verify(
            parameters, proof, root, transcript, TheoremStatementHash(),
            WitnessCount, linearConstraints, linearTargets, quadraticConstraints,
            encoderFactory, profile, Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None, BaseMemoryPool.Shared, out cause);
    }


    /// <summary>
    /// Commits the fixed witness set, proves, and returns the proof plus the public verify inputs
    /// (root, the linear targets b[c] = coefficient·W[c]).
    /// </summary>
    private static LongfellowLigeroProof ProduceProof(Lch14AdditiveFft fft, int subFieldBytes, out byte[] root, out byte[] linearTargets)
    {
        var parameters = NewParameters(subFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];
        LigeroLinearConstraint[] linearConstraints = BuildLinearConstraints(fft);

        LongfellowRandomByteSource random = NewCounterSource();
        using LongfellowFieldProfile commitProfile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        using LongfellowLigeroCommitment commitment = LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), commitProfile,
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);

        root = new byte[DigestSize];
        commitment.CopyRoot(root);

        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        transcript.AbsorbCommitmentRoot(root);

        using LongfellowFieldProfile proveProfile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowLigeroProof proof = LongfellowLigeroProver.Prove(
            commitment, transcript, WitnessCount, linearConstraints, TheoremStatementHash(), quadraticConstraints,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), proveProfile,
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


    /// <summary>
    /// Reconstructs the reference proof from the prove-step anchor (response rows, opened columns,
    /// nonces, compressed path), the same reconstruction the verify gate uses.
    /// </summary>
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


    /// <summary>
    /// Fills the witness buffer so that W[i] = of_scalar(i + 1) for every index, then overwrites
    /// W[2] with W[0]·W[1] to satisfy the one quadratic constraint.
    /// </summary>
    private static void BuildWitnesses(Lch14AdditiveFft fft, Span<byte> witnesses)
    {
        for(int i = 0; i < WitnessCount; i++)
        {
            fft.NodeElement((uint)(i + 1), witnesses.Slice(i * ScalarSize, ScalarSize));
        }

        Multiply(witnesses[..ScalarSize], witnesses.Slice(ScalarSize, ScalarSize), witnesses.Slice(2 * ScalarSize, ScalarSize), CurveParameterSet.None);
    }


    /// <summary>
    /// Builds one linear constraint per witness index, each with coefficient of_scalar(index + 1)
    /// and its own row and column index.
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


    /// <summary>
    /// Returns a fixed, deterministic 32-byte hash standing in for the theorem statement digest that
    /// the prover and verifier must agree on.
    /// </summary>
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
    /// Returns a deterministic byte source that fills each requested span with an incrementing
    /// counter, wrapping modulo 256.
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


    /// <summary>
    /// Builds the fixed Ligero parameter set the tests share, varying only the subfield element
    /// width.
    /// </summary>
    private static LongfellowLigeroParameters NewParameters(int subFieldBytes) =>
        new(WitnessCount, QuadraticConstraintCount, InverseRate, OpenedColumnCount, FieldBytes, subFieldBytes);


    /// <summary>
    /// Builds a fresh transcript seeded with the given bytes, using the fixed version, block width
    /// and backend the tests share.
    /// </summary>
    private static LongfellowTranscript NewTranscript(ReadOnlySpan<byte> seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>
    /// Builds the additive FFT for the given subfield, wired to this file's shared field-arithmetic
    /// delegates.
    /// </summary>
    private static Lch14AdditiveFft NewFft(Lch14Subfield subfield) =>
        new(subfield, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>
    /// Implements of_bytes_field: reverses 16 little-endian element bytes into the low 16 bytes of a
    /// 32-byte big-endian canonical scalar, zeroing the high bytes.
    /// </summary>
    private static void FromBytesField(ReadOnlySpan<byte> littleEndian, Span<byte> canonical)
    {
        canonical.Clear();
        for(int i = 0; i < ElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }
    }


    /// <summary>
    /// Computes the two-to-one SHA-256 compression the Merkle tree uses, hashing the concatenation of
    /// the left and right inputs.
    /// </summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>
    /// Computes a one-shot SHA-256 digest of the input, ignoring the named hash function since this
    /// file only ever selects SHA-256.
    /// </summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    /// <summary>
    /// Encrypts one block with AES in ECB mode and no padding, the block cipher the transcript uses
    /// to derive challenges.
    /// </summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>
    /// Parses a comma-separated run of the given count of 16-byte little-endian elements into that
    /// many canonical big-endian scalars.
    /// </summary>
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


    /// <summary>
    /// Parses a comma-separated run of decimal integers into an array, in the order the anchor lists
    /// them.
    /// </summary>
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


    /// <summary>
    /// Reads an anchor file relative to the test assembly's output directory and collects every
    /// whitespace-separated <c>key=value</c> token across all its lines into a dictionary, skipping
    /// blank lines and tokens without an <c>=</c>.
    /// </summary>
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
