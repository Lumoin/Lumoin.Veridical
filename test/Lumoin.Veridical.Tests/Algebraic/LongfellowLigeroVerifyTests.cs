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
/// The wire-format-conformant Ligero VERIFY flow (conformance step C.5), gated as a faithful port of
/// google/longfellow-zk's <c>lib/ligero/ligero_verifier.h</c> <c>verify()</c>. The milestone gate is the
/// first half of the cross-implementation round-trip: a proof the REFERENCE prover computed, reconstructed
/// field by field from the C.4 oracle dump, verifies in our verifier. The self gates run our C.4 prover's
/// proof through our verifier (both subfields), and the rejection duals confirm each of the four checks
/// (plus the dot value-check) catches the fault it owns.
/// </summary>
/// <remarks>
/// <para>
/// The oracle dump (prove-anchor-output.txt in TestMaterial/Longfellow) is computed by the reference
/// implementation running in its own build environment via development tooling outside this repository. It
/// runs the real <c>LigeroProver::commit()+prove()</c> and the real <c>LigeroProof</c>, and its
/// <c>verify=1 why=ok</c> confirms <c>LigeroVerifier::verify()</c> accepts the dumped proof. The C.5 gate
/// reconstructs that exact proof — the response rows, the opened columns, the per-leaf nonces and the
/// compressed Merkle path — and the public verify inputs (the commitment root, the theorem statement, the
/// linear-constraint targets <c>b</c>), then asserts OUR <see cref="LongfellowLigeroVerifier"/> accepts it.
/// </para>
/// <para>
/// The rejection duals tamper one input each and assert the verifier rejects with the matching check.
/// Because the response rows are absorbed into the transcript before <c>idx</c> is squeezed (the commit-
/// then-challenge order), any change to a transcript-feeding field moves <c>idx</c> and so fails the
/// Merkle check first: a flipped response byte and a wrong theorem statement both fall here, as do a
/// flipped opened-column element, a flipped nonce, a flipped path digest and a wrong root (their leaves or
/// path no longer recompute the root). The one input the transcript never sees is the public linear-target
/// vector <c>b</c>; flipping it leaves <c>idx</c> and the column checks intact and rejects only at the dot
/// value check (<c>want_dot = Σ_c b[c]·alphal[c]</c> against the response's witness-block sum).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowLigeroVerifyTests
{
    private const string DumpRelativePath = "TestMaterial/Longfellow/prove-anchor-output.txt";

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

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors();


    [TestMethod]
    public void TheVerifierAcceptsTheReferenceProofForTheProductionSubfield()
    {
        AssertReferenceProofAccepted(Lch14Subfield.Production16, Production16SubFieldBytes, "q16");
    }


    [TestMethod]
    public void TheVerifierAcceptsTheReferenceProofForTheTestParitySubfield()
    {
        AssertReferenceProofAccepted(Lch14Subfield.TestParity32, TestParity32SubFieldBytes, "q32");
    }


    [TestMethod]
    public void TheVerifierAcceptsOurProverProofForTheProductionSubfield()
    {
        AssertOwnProofAccepted(Lch14Subfield.Production16, Production16SubFieldBytes);
    }


    [TestMethod]
    public void TheVerifierAcceptsOurProverProofForTheTestParitySubfield()
    {
        AssertOwnProofAccepted(Lch14Subfield.TestParity32, TestParity32SubFieldBytes);
    }


    [TestMethod]
    public void ATamperedResponseFailsTheMerkleCheck()
    {
        //The response rows are absorbed into the transcript BEFORE idx is squeezed (the commit-then-
        //challenge order), so a flipped response re-derives a different idx set. The verifier then opens
        //columns the proof did not carry leaves for, and the Merkle check — the first check that consumes
        //idx — rejects. This is the same transcript-replay behavior the reference exhibits.
        AssertRejection(
            mutate: fields => fields.LowDegreeResponse[ScalarSize - 1] ^= 0x01,
            expected: LongfellowLigeroVerificationResult.MerkleCheckFailed);
    }


    [TestMethod]
    public void ATamperedLinearTargetFailsTheDotValueCheck()
    {
        //The linear-constraint targets b[c] are public verify inputs that never enter the transcript, so
        //a flipped b leaves idx and the Merkle/low-degree/dot column checks intact; only the dot value
        //check (want_dot = sum_c b[c]*alphal[c] against the response's witness-block sum) rejects.
        AssertRejection(
            mutate: fields => fields.LinearTargets[ScalarSize - 1] ^= 0x01,
            expected: LongfellowLigeroVerificationResult.WrongDotProduct);
    }


    [TestMethod]
    public void ATamperedOpenedColumnFailsTheMerkleCheck()
    {
        AssertRejection(
            mutate: fields => fields.OpenedColumns[(LongfellowLigeroParameters.FirstWitnessRowIndex * OpenedColumnCount * ScalarSize) + ScalarSize - 1] ^= 0x01,
            expected: LongfellowLigeroVerificationResult.MerkleCheckFailed);
    }


    [TestMethod]
    public void ATamperedNonceFailsTheMerkleCheck()
    {
        AssertRejection(
            mutate: fields => fields.Nonces[0] ^= 0x01,
            expected: LongfellowLigeroVerificationResult.MerkleCheckFailed);
    }


    [TestMethod]
    public void ATamperedPathDigestFailsTheMerkleCheck()
    {
        AssertRejection(
            mutate: fields => fields.MerklePath[0] ^= 0x01,
            expected: LongfellowLigeroVerificationResult.MerkleCheckFailed);
    }


    [TestMethod]
    public void AWrongRootFailsTheMerkleCheck()
    {
        AssertRejection(
            mutate: fields => fields.Root[0] ^= 0x01,
            expected: LongfellowLigeroVerificationResult.MerkleCheckFailed);
    }


    [TestMethod]
    public void AWrongStatementHashFailsTheMerkleCheck()
    {
        //A different theorem statement re-keys the whole transcript, so every squeezed challenge and the
        //drawn opened indices move. The verifier opens columns the proof did not carry, and the Merkle
        //check — the first check that consumes idx — rejects.
        AssertRejection(
            mutate: fields => fields.StatementHash[0] ^= 0x01,
            expected: LongfellowLigeroVerificationResult.MerkleCheckFailed);
    }


    //Reconstructs the reference proof from the dump and asserts the verifier accepts it.
    private static void AssertReferenceProofAccepted(Lch14Subfield subfield, int subFieldBytes, string prefix)
    {
        var parameters = NewParameters(subFieldBytes);
        ReferenceFields fields = ParseReferenceFields(parameters, prefix);

        using Lch14AdditiveFft fft = NewFft(subfield);
        bool accepted = RunVerify(parameters, fft, fields, out LongfellowLigeroVerificationResult cause);

        Assert.IsTrue(accepted, $"{prefix}: the reference proof must verify (cause {cause}).");
        Assert.AreEqual(LongfellowLigeroVerificationResult.Accepted, cause, $"{prefix}: the verdict must be Accepted.");
    }


    //Produces a proof with our C.4 prover and asserts our verifier accepts it.
    private static void AssertOwnProofAccepted(Lch14Subfield subfield, int subFieldBytes)
    {
        var parameters = NewParameters(subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);
        ReferenceFields fields = ProduceOwnFields(parameters, fft, subFieldBytes);

        bool accepted = RunVerify(parameters, fft, fields, out LongfellowLigeroVerificationResult cause);

        Assert.IsTrue(accepted, $"Our prover's proof must verify (cause {cause}).");
        Assert.AreEqual(LongfellowLigeroVerificationResult.Accepted, cause, "The verdict must be Accepted.");
    }


    //Produces our own proof (production subfield), applies a single-field mutation, and asserts the
    //verifier rejects with the expected cause.
    private static void AssertRejection(Action<ReferenceFields> mutate, LongfellowLigeroVerificationResult expected)
    {
        var parameters = NewParameters(Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewFft(Lch14Subfield.Production16);
        ReferenceFields fields = ProduceOwnFields(parameters, fft, Production16SubFieldBytes);

        //Sanity: the untampered fields verify.
        Assert.IsTrue(RunVerify(parameters, fft, fields, out _), "The baseline proof must verify before tampering.");

        mutate(fields);

        bool accepted = RunVerify(parameters, fft, fields, out LongfellowLigeroVerificationResult cause);

        Assert.IsFalse(accepted, $"The tampered proof must be rejected (got cause {cause}).");
        Assert.AreEqual(expected, cause, "The rejection must be caught by the expected check.");
    }


    //Drives LongfellowLigeroVerifier over the given fields: builds the proof object, seeds the transcript,
    //absorbs the root, and verifies against the public constraints.
    private static bool RunVerify(LongfellowLigeroParameters parameters, Lch14AdditiveFft fft, ReferenceFields fields, out LongfellowLigeroVerificationResult cause)
    {
        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];
        LigeroLinearConstraint[] linearConstraints = BuildLinearConstraints(fft);

        using LongfellowLigeroProof proof = BuildProof(parameters, fields);
        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        transcript.AbsorbCommitmentRoot(fields.Root);

        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        return LongfellowLigeroVerifier.Verify(
            parameters, proof, fields.Root, transcript, fields.StatementHash,
            WitnessCount, linearConstraints, fields.LinearTargets, quadraticConstraints,
            encoderFactory, profile, Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None, BaseMemoryPool.Shared, out cause);
    }


    //Builds a LongfellowLigeroProof carrying the given fields, packing the four response rows into the
    //proof's contiguous response buffer and the opened columns row-major.
    private static LongfellowLigeroProof BuildProof(LongfellowLigeroParameters parameters, ReferenceFields fields)
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
        IMemoryOwner<byte> pathOwner = BaseMemoryPool.Shared.Rent(Math.Max(fields.MerklePathLength, 1) * DigestSize);

        Span<byte> responses = responseOwner.Memory.Span[..LongfellowLigeroProof.ResponseBufferSize(parameters)];
        fields.LowDegreeResponse.CopyTo(responses[..(block * ScalarSize)]);
        fields.DotResponse.CopyTo(responses.Slice(block * ScalarSize, dblock * ScalarSize));
        fields.QuadraticResponseLow.CopyTo(responses.Slice((block + dblock) * ScalarSize, r * ScalarSize));
        fields.QuadraticResponseHigh.CopyTo(responses.Slice(((block + dblock) * ScalarSize) + (r * ScalarSize), quadHigh * ScalarSize));

        fields.OpenedColumns.CopyTo(openedColumnsOwner.Memory.Span[..(rowCount * OpenedColumnCount * ScalarSize)]);

        Span<int> indices = MemoryMarshal.Cast<byte, int>(indicesOwner.Memory.Span[..(OpenedColumnCount * sizeof(int))]);
        fields.Indices.CopyTo(indices);

        fields.Nonces.CopyTo(nonceOwner.Memory.Span[..(OpenedColumnCount * NonceSize)]);
        if(fields.MerklePathLength > 0)
        {
            fields.MerklePath.CopyTo(pathOwner.Memory.Span[..(fields.MerklePathLength * DigestSize)]);
        }

        return new LongfellowLigeroProof(parameters, responseOwner, openedColumnsOwner, indicesOwner, nonceOwner, pathOwner, fields.MerklePathLength);
    }


    //Produces the verify-input fields by running our C.2 commit + C.4 prove for the given subfield, and
    //computing the linear targets b[c] = coefficient * W[c] the verifier's value-check needs.
    private static ReferenceFields ProduceOwnFields(LongfellowLigeroParameters parameters, Lch14AdditiveFft fft, int subFieldBytes)
    {
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

        byte[] root = new byte[DigestSize];
        commitment.CopyRoot(root);

        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        transcript.AbsorbCommitmentRoot(root);

        using LongfellowLigeroProof proof = LongfellowLigeroProver.Prove(
            commitment, transcript, WitnessCount, linearConstraints, TheoremStatementHash(), quadraticConstraints,
            LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared), LongfellowGf2k128Encoding.CreateProfile(fft),
            Add, Subtract, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        byte[] linearTargets = new byte[WitnessCount * ScalarSize];
        Span<byte> coefficient = stackalloc byte[ScalarSize];
        for(int c = 0; c < WitnessCount; c++)
        {
            //b[c] = coefficient(c) * W[c] with coefficient(c) = of_scalar(c+1).
            fft.NodeElement((uint)(c + 1), coefficient);
            Multiply(coefficient, witnesses.Slice(c * ScalarSize, ScalarSize), linearTargets.AsSpan(c * ScalarSize, ScalarSize), CurveParameterSet.None);
        }

        var fields = ReferenceFields.FromProof(parameters, proof, root, TheoremStatementHash(), linearTargets);
        witnesses.Clear();

        return fields;
    }


    //Parses the dumped reference proof fields for the given prefix into a mutable field set.
    private static ReferenceFields ParseReferenceFields(LongfellowLigeroParameters parameters, string prefix)
    {
        byte[] root = Convert.FromHexString(Anchors[$"{prefix}_root"]);
        byte[] statementHash = Convert.FromHexString(Anchors[$"{prefix}_hashllterm"]);
        byte[] linearTargets = ParseCanonicalElements(Anchors[$"{prefix}_b"], WitnessCount);

        byte[] lowDegree = ParseCanonicalElements(Anchors[$"{prefix}_yldt"], parameters.Block);
        byte[] dot = ParseCanonicalElements(Anchors[$"{prefix}_ydot"], parameters.DoubleBlock);
        byte[] quadLow = ParseCanonicalElements(Anchors[$"{prefix}_yquad0"], parameters.RandomCount);
        byte[] quadHigh = ParseCanonicalElements(Anchors[$"{prefix}_yquad2"], parameters.DoubleBlock - parameters.Block);

        int rowCount = parameters.RowCount;
        byte[] openedColumns = new byte[rowCount * OpenedColumnCount * ScalarSize];
        for(int i = 0; i < rowCount; i++)
        {
            byte[] rowElements = ParseCanonicalElements(Anchors[$"{prefix}_req{i}"], OpenedColumnCount);
            Array.Copy(rowElements, 0, openedColumns, i * OpenedColumnCount * ScalarSize, OpenedColumnCount * ScalarSize);
        }

        int[] indices = ParseIntList(Anchors[$"{prefix}_idx"]);

        byte[] nonces = new byte[OpenedColumnCount * NonceSize];
        for(int j = 0; j < OpenedColumnCount; j++)
        {
            byte[] nonce = Convert.FromHexString(Anchors[$"{prefix}_nonce{j}"]);
            Array.Copy(nonce, 0, nonces, j * NonceSize, NonceSize);
        }

        int pathLength = int.Parse(Anchors[$"{prefix}_pathlen"], System.Globalization.CultureInfo.InvariantCulture);
        byte[] path = new byte[pathLength * DigestSize];
        for(int i = 0; i < pathLength; i++)
        {
            byte[] digest = Convert.FromHexString(Anchors[$"{prefix}_path{i}"]);
            Array.Copy(digest, 0, path, i * DigestSize, DigestSize);
        }

        return new ReferenceFields(root, statementHash, linearTargets, lowDegree, dot, quadLow, quadHigh, openedColumns, indices, nonces, path, pathLength);
    }


    //W[i] = of_scalar(i + 1), then W[2] = W[0]·W[1] to satisfy the one quadratic constraint.
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
    //big-endian scalars (of_bytes_field per element).
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


    //A mutable verify-input field set: the public inputs (root, statement hash, linear targets) and the
    //proof's wire fields, all as byte arrays the rejection duals can tamper in place.
    private sealed class ReferenceFields
    {
        public byte[] Root { get; }

        public byte[] StatementHash { get; }

        public byte[] LinearTargets { get; }

        public byte[] LowDegreeResponse { get; }

        public byte[] DotResponse { get; }

        public byte[] QuadraticResponseLow { get; }

        public byte[] QuadraticResponseHigh { get; }

        public byte[] OpenedColumns { get; }

        public int[] Indices { get; }

        public byte[] Nonces { get; }

        public byte[] MerklePath { get; }

        public int MerklePathLength { get; }


        public ReferenceFields(
            byte[] root,
            byte[] statementHash,
            byte[] linearTargets,
            byte[] lowDegreeResponse,
            byte[] dotResponse,
            byte[] quadraticResponseLow,
            byte[] quadraticResponseHigh,
            byte[] openedColumns,
            int[] indices,
            byte[] nonces,
            byte[] merklePath,
            int merklePathLength)
        {
            Root = root;
            StatementHash = statementHash;
            LinearTargets = linearTargets;
            LowDegreeResponse = lowDegreeResponse;
            DotResponse = dotResponse;
            QuadraticResponseLow = quadraticResponseLow;
            QuadraticResponseHigh = quadraticResponseHigh;
            OpenedColumns = openedColumns;
            Indices = indices;
            Nonces = nonces;
            MerklePath = merklePath;
            MerklePathLength = merklePathLength;
        }


        //Extracts the wire fields out of a produced proof into copies the rejection duals can tamper.
        public static ReferenceFields FromProof(LongfellowLigeroParameters parameters, LongfellowLigeroProof proof, byte[] root, byte[] statementHash, byte[] linearTargets)
        {
            int rowCount = parameters.RowCount;
            byte[] openedColumns = proof.OpenedColumns[..(rowCount * OpenedColumnCount * ScalarSize)].ToArray();
            int[] indices = proof.OpenedColumnIndices.ToArray();
            byte[] nonces = proof.Nonces[..(OpenedColumnCount * NonceSize)].ToArray();
            byte[] path = proof.MerklePathLength > 0 ? proof.MerklePath[..(proof.MerklePathLength * DigestSize)].ToArray() : [];

            return new ReferenceFields(
                root, statementHash, linearTargets,
                proof.LowDegreeResponse.ToArray(),
                proof.DotResponse.ToArray(),
                proof.QuadraticResponseLow.ToArray(),
                proof.QuadraticResponseHigh.ToArray(),
                openedColumns, indices, nonces, path, proof.MerklePathLength);
        }
    }
}
