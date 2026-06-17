using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The P-256 base-field (<c>Fp256</c>) binding of the wire-format Ligero seam (conformance step C.12,
/// the Fp256 sig-circuit RS wiring): <see cref="LongfellowFp256Encoding"/> together with the field-generic
/// commitment and the <see cref="LongfellowSubfieldRunCodec"/> serializer seam over the prime field. These
/// do NOT assert end-to-end conformance against reference bytes — the byte-exact Fp256 commitment root
/// against a reference dump lands with the Docker dump harness in a later step. They gate the construction
/// faithfulness instead:
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description><b>Root provenance</b>: the pinned <c>kRootX</c> / <c>kRootY</c> bytes equal the decimal sources re-parsed here, and both lie below the modulus.</description></item>
///   <item><description><b>RS-binding fidelity</b>: the factory-built encoder's <c>interpolate</c> equals calling <see cref="Fp256ReedSolomon"/> directly for the same shape on a sample row, proving the wrapper binding is faithful.</description></item>
///   <item><description><b>Commitment end-to-end</b>: a small Fp256 witness set commits to a root that is produced, deterministic, and sensitive to a witness flip.</description></item>
///   <item><description><b>Dispose-correctness</b>: the factory-built encoder owns and releases its <see cref="Fp256ReedSolomon"/> precompute.</description></item>
///   <item><description><b>Subfield run codec</b>: the Fp256 <c>in_subfield ≡ true</c> / 32-byte-framing semantics the serializer's run-length pass routes through.</description></item>
///   <item><description><b>Parameter pins</b>: the sig-circuit's <c>kSubFieldBytes</c> and <c>subfield_boundary</c>.</description></item>
/// </list>
/// <para>
/// The arithmetic uses <see cref="P256BaseFieldReference"/> (the BigInteger-backed P-256 base field). The
/// random source draws integers below <c>p</c> (the most significant little-endian byte zeroed) so every
/// <c>of_bytes_field</c> draw is accepted — the established seam-test pattern, since the transcript's
/// rejection-sampling conversion is the later dual-field step.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowFp256EncodingTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSize = 32;
    private const int Fp256ElementBytes = 32;

    //mdoc_zk.cc:83-88: the two decimal constants the reference parses into the extension root of unity.
    private const string RootXDecimal = "112649224146410281873500457609690258373018840430489408729223714171582664680802";
    private const string RootYDecimal = "84087994358540907695740461427818660560182168997182378749313018254450460212908";

    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();


    [TestMethod]
    public void ThePinnedRootOfUnityMatchesTheDecimalSource()
    {
        //The binding pins kRootX/kRootY as canonical big-endian bytes; re-parse the decimal strings and
        //confirm the pin. The reference parses them as the extension element kRootX + i·kRootY, so the
        //64-byte root is [real(kRootX) || imag(kRootY)].
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        BigInteger real = ReadCanonicalBigEndian(root.AsSpan(0, ScalarSize));
        BigInteger imaginary = ReadCanonicalBigEndian(root.AsSpan(ScalarSize, ScalarSize));

        Assert.AreEqual(BigInteger.Parse(RootXDecimal, CultureInfo.InvariantCulture), real, "The pinned real part must equal kRootX.");
        Assert.AreEqual(BigInteger.Parse(RootYDecimal, CultureInfo.InvariantCulture), imaginary, "The pinned imaginary part must equal kRootY.");

        Assert.IsLessThan(Prime, real, "kRootX must lie below the P-256 base-field modulus.");
        Assert.IsLessThan(Prime, imaginary, "kRootY must lie below the P-256 base-field modulus.");

        //mdoc_zk.cc:479 builds the FftExtConvolutionFactory with omega_order = 1ull << 31; the binding
        //pins that order (exercised through every NewFft below, and re-derived here to gate the pin).
        ulong rederivedOrder = 1UL;
        for(int i = 0; i < 31; i++)
        {
            rederivedOrder *= 2;
        }

        Assert.AreEqual(LongfellowFp256Encoding.OmegaOrder, rederivedOrder, "The production root has multiplicative order 2^31.");
    }


    [TestMethod]
    public void TheProfileIsTheFp256Profile()
    {
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalar, InRange);

        Assert.AreEqual(Fp256ElementBytes, profile.ElementBytes, "The Fp256 on-wire element width is 32 bytes.");

        Span<byte> third = stackalloc byte[ScalarSize];
        profile.CopyThirdEvaluationPoint(third);
        Assert.AreEqual(new BigInteger(2), ReadCanonicalBigEndian(third), "The Fp256 third evaluation point is 2.");
    }


    [TestMethod]
    public void TheFactoryEncoderAgreesWithDirectFp256ReedSolomon()
    {
        //The wrapper binding must be byte-faithful: the factory-built encoder's interpolate must equal
        //calling Fp256ReedSolomon directly for the same (dim, blockLen) on the same sample row.
        const int Dimension = 9;
        const int BlockLength = 23;

        byte[] sampleRow = BuildSampleRow(Dimension, BlockLength);

        byte[] viaFactory = (byte[])sampleRow.Clone();
        Fp256RealFft factoryFft = NewFft();
        LongfellowRowEncoderFactory factory = LongfellowFp256Encoding.CreateEncoderFactory(
            factoryFft, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);
        using(LongfellowRowEncoder encoder = factory(Dimension, BlockLength))
        {
            encoder.Interpolate(viaFactory);
        }

        byte[] viaDirect = (byte[])sampleRow.Clone();
        Fp256RealFft directFft = NewFft();
        using(Fp256ReedSolomon rs = new(Dimension, BlockLength, directFft, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared))
        {
            rs.Interpolate(viaDirect);
        }

        Assert.IsTrue(viaFactory.AsSpan().SequenceEqual(viaDirect), "The factory encoder must extend the row byte-for-byte as the direct Fp256ReedSolomon.");
    }


    [TestMethod]
    public void TheFactoryEncoderDisposesItsState()
    {
        //The Fp256 encoder owns its per-(N,M) precompute as the wrapper's disposable state: after the
        //encoder is disposed the underlying Fp256ReedSolomon is disposed too, so a second interpolate
        //throws ObjectDisposedException (the only externally observable proof the state was released).
        const int Dimension = 5;
        const int BlockLength = 16;

        Fp256RealFft fft = NewFft();
        LongfellowRowEncoderFactory factory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);

        LongfellowRowEncoder encoder = factory(Dimension, BlockLength);
        byte[] row = BuildSampleRow(Dimension, BlockLength);
        encoder.Interpolate(row);
        encoder.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => encoder.Interpolate(BuildSampleRow(Dimension, BlockLength)), "Disposing the encoder must dispose its Fp256ReedSolomon state.");
    }


    [TestMethod]
    public void TheCommitmentBuildsDeterministically()
    {
        Span<byte> first = stackalloc byte[DigestSize];
        Span<byte> second = stackalloc byte[DigestSize];
        Commit(witnessFlipIndex: -1, first);
        Commit(witnessFlipIndex: -1, second);

        Assert.IsFalse(IsZero(first), "The commitment must produce a non-zero root.");
        Assert.IsTrue(first.SequenceEqual(second), "The same witness and random stream must produce the same root.");
    }


    [TestMethod]
    public void AFlippedWitnessChangesTheRoot()
    {
        Span<byte> original = stackalloc byte[DigestSize];
        Span<byte> tampered = stackalloc byte[DigestSize];
        Commit(witnessFlipIndex: -1, original);
        Commit(witnessFlipIndex: 0, tampered);

        Assert.IsFalse(original.SequenceEqual(tampered), "A flipped witness element must change the commitment root.");
    }


    [TestMethod]
    public void TheSubfieldRunCodecForFp256IsAlwaysFullField()
    {
        //fp_generic.h: in_subfield ≡ true (line 284), kSubFieldBytes = kBytes = 32 (line 47),
        //to_bytes_subfield ≡ to_bytes_field / of_bytes_subfield ≡ of_bytes_field (lines 382-388). The
        //codec the serializer's run-length pass routes through must reproduce exactly that.
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalar, InRange);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        Assert.AreEqual(Fp256ElementBytes, codec.SubFieldBytes, "The Fp256 subfield byte width is 32.");

        //Every element is in the subfield, so the run-length pass collapses to a single subfield run.
        Span<byte> zero = stackalloc byte[ScalarSize];
        Span<byte> nearModulus = Canonical(Prime - 1);
        Span<byte> arbitrary = Canonical(new BigInteger(123456789) % Prime);
        Assert.IsTrue(codec.InSubfield(zero), "Zero is in the subfield.");
        Assert.IsTrue(codec.InSubfield(nearModulus), "p - 1 is in the subfield.");
        Assert.IsTrue(codec.InSubfield(arbitrary), "An arbitrary element is in the subfield.");

        //to_bytes_subfield equals to_bytes_field: the 32 little-endian bytes, and of_bytes_subfield
        //reverses them back.
        Span<byte> subfieldBytes = stackalloc byte[Fp256ElementBytes];
        Span<byte> fieldBytes = stackalloc byte[Fp256ElementBytes];
        codec.ToBytesSubfield(arbitrary, subfieldBytes);
        profile.ToBytesField(arbitrary, fieldBytes);
        Assert.IsTrue(subfieldBytes.SequenceEqual(fieldBytes), "to_bytes_subfield must equal to_bytes_field for the prime field.");

        Span<byte> decoded = stackalloc byte[ScalarSize];
        Assert.IsTrue(codec.OfBytesSubfield(subfieldBytes, decoded), "of_bytes_subfield must accept an in-range element.");
        Assert.IsTrue(decoded.SequenceEqual(arbitrary), "of_bytes_subfield must reverse to_bytes_subfield.");

        //An out-of-range 32-byte sequence (p itself) is rejected gracefully, mirroring of_bytes_field.
        Span<byte> atModulus = stackalloc byte[Fp256ElementBytes];
        WriteLittleEndian(Prime, atModulus);
        Span<byte> sink = stackalloc byte[ScalarSize];
        Assert.IsFalse(codec.OfBytesSubfield(atModulus, sink), "of_bytes_subfield must reject the integer p.");
    }


    [TestMethod]
    public void TheSignatureSubfieldParametersMatchTheReference()
    {
        //fp_generic.h:47 — Fp256Base::kSubFieldBytes == kBytes == 32: the subfield byte size is the full
        //element width the profile reports.
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalar, InRange);
        Assert.AreEqual(LongfellowFp256Encoding.SignatureSubFieldBytes, profile.ElementBytes, "The Fp256 subfield byte size is the full 32-byte element.");

        //The dumped sig_subfield_boundary is 0 (mdoc-circuit-anchor-output.txt). With it zero, no witness
        //row is subfield-only: for the first witness row the subfield_only test 1*w <= boundary is false
        //(the row width strictly exceeds the boundary), so the commit draws full-field padding throughout.
        int boundary = LongfellowFp256Encoding.SignatureSubfieldBoundary;
        Assert.AreEqual(0, boundary, "subfield_boundary 0 leaves the first witness row full-field.");
    }


    [TestMethod]
    public void AnFp256ProofRoundTripsThroughTheRunLengthSerializer()
    {
        //The serializer's run-length opened-column pass (Measure/Write/ReadOpenedColumns) over the Fp256
        //codec has no end-to-end gate elsewhere: for the prime field every element is in_subfield, so Write
        //emits a length-0 leading full-field run then one subfield run covering all nreq·nrow elements, and
        //Read must parse it back. A synthetic proof of Fp256 elements below p exercises that path without
        //the full prover; byte-exact conformance against a reference dump lands with the Docker harness.
        const int WitnessCount = 8;
        const int QuadraticConstraintCount = 1;
        const int InverseRate = 4;
        const int OpenedColumnCount = 2;

        var parameters = new LongfellowLigeroParameters(WitnessCount, QuadraticConstraintCount, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalar, InRange);

        using LongfellowLigeroProof proof = BuildSyntheticProof(parameters, OpenedColumnCount);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        int size = LongfellowLigeroProofSerializer.SerializedSize(proof, profile, codec);
        byte[] buffer = new byte[size];
        int written = LongfellowLigeroProofSerializer.Write(proof, profile, codec, buffer);
        Assert.AreEqual(size, written, "Write must consume exactly the computed serialized size.");

        using LongfellowLigeroProof? parsed = LongfellowLigeroProofSerializer.Read(parameters, profile, codec, BaseMemoryPool.Shared, buffer, out int read);

        Assert.IsNotNull(parsed, "Read must parse the bytes our Write produced.");
        Assert.AreEqual(written, read, "Read must consume exactly the bytes Write produced.");

        AssertProofFieldsEqual(proof, parsed, parameters, OpenedColumnCount);
    }


    //Commits a small Fp256 witness set (8 witnesses, one quadratic triple W[2] = W[0]·W[1]) with an
    //optional one-bit witness flip, writing the root. The random source draws below p so of_bytes_field
    //accepts every draw; subfield_boundary = 0, so no subfield draw is made.
    private static void Commit(int witnessFlipIndex, Span<byte> root)
    {
        const int WitnessCount = 8;
        const int QuadraticConstraintCount = 1;
        const int InverseRate = 4;
        const int OpenedColumnCount = 2;

        var parameters = new LongfellowLigeroParameters(WitnessCount, QuadraticConstraintCount, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(witnesses, witnessFlipIndex);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];

        Fp256RealFft fft = NewFft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalar, InRange);

        LongfellowRandomByteSource random = NewBelowModulusSource();
        LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, LongfellowFp256Encoding.SignatureSubFieldBytes, LongfellowFp256Encoding.SignatureSubfieldBoundary,
            random, encoderFactory, profile, Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None, root, BaseMemoryPool.Shared);

        witnesses.Clear();
    }


    //W[i] = of_scalar(i + 1), then W[2] = W[0]·W[1] to satisfy the one quadratic constraint. An optional
    //flip index XORs one low bit of a witness, after which W[2] is recomputed so the only difference is
    //the perturbed input propagating into the codeword.
    private static void BuildWitnesses(Span<byte> witnesses, int witnessFlipIndex)
    {
        int witnessCount = witnesses.Length / ScalarSize;
        for(int i = 0; i < witnessCount; i++)
        {
            OfScalar((uint)(i + 1), witnesses.Slice(i * ScalarSize, ScalarSize));
        }

        if(witnessFlipIndex >= 0)
        {
            witnesses[(witnessFlipIndex * ScalarSize) + ScalarSize - 1] ^= 0x01;
        }

        Multiply(witnesses[..ScalarSize], witnesses.Slice(ScalarSize, ScalarSize), witnesses.Slice(2 * ScalarSize, ScalarSize), CurveParameterSet.None);
    }


    //A synthetic proof whose response rows and opened columns hold Fp256 elements below p (so
    //to_bytes_field / of_bytes_field round-trip without rejection); nonces and the Merkle path are raw
    //bytes. The path length is nreq, the minimum the reader accepts. Used to drive the run-length
    //serializer over the Fp256 codec without the full prover.
    private static LongfellowLigeroProof BuildSyntheticProof(LongfellowLigeroParameters parameters, int openedColumnCount)
    {
        const int NonceSize = 32;
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int randomCount = parameters.RandomCount;
        int quadHigh = dblock - block;
        int rowCount = parameters.RowCount;
        int pathLength = openedColumnCount;

        IMemoryOwner<byte> responseOwner = BaseMemoryPool.Shared.Rent(LongfellowLigeroProof.ResponseBufferSize(parameters));
        IMemoryOwner<byte> openedColumnsOwner = BaseMemoryPool.Shared.Rent(rowCount * openedColumnCount * ScalarSize);
        IMemoryOwner<byte> indicesOwner = BaseMemoryPool.Shared.Rent(openedColumnCount * sizeof(int));
        IMemoryOwner<byte> nonceOwner = BaseMemoryPool.Shared.Rent(openedColumnCount * NonceSize);
        IMemoryOwner<byte> pathOwner = BaseMemoryPool.Shared.Rent(pathLength * DigestSize);

        Span<byte> responses = responseOwner.Memory.Span[..LongfellowLigeroProof.ResponseBufferSize(parameters)];
        int responseElements = block + dblock + randomCount + quadHigh;
        for(int i = 0; i < responseElements; i++)
        {
            OfScalar((uint)((i * 13) + 1), responses.Slice(i * ScalarSize, ScalarSize));
        }

        Span<byte> openedColumns = openedColumnsOwner.Memory.Span[..(rowCount * openedColumnCount * ScalarSize)];
        for(int i = 0; i < rowCount * openedColumnCount; i++)
        {
            OfScalar((uint)((i * 7) + 3), openedColumns.Slice(i * ScalarSize, ScalarSize));
        }

        indicesOwner.Memory.Span[..(openedColumnCount * sizeof(int))].Clear();

        Span<byte> nonces = nonceOwner.Memory.Span[..(openedColumnCount * NonceSize)];
        for(int i = 0; i < nonces.Length; i++)
        {
            nonces[i] = (byte)((i * 17) + 5);
        }

        Span<byte> path = pathOwner.Memory.Span[..(pathLength * DigestSize)];
        for(int i = 0; i < path.Length; i++)
        {
            path[i] = (byte)((i * 11) + 2);
        }

        return new LongfellowLigeroProof(parameters, responseOwner, openedColumnsOwner, indicesOwner, nonceOwner, pathOwner, pathLength);
    }


    //Asserts the response rows, opened columns, nonces and Merkle path are identical between two proofs.
    //The parsed proof's column indices are zeroed by Read (idx is not transmitted), so they are excluded.
    private static void AssertProofFieldsEqual(LongfellowLigeroProof expected, LongfellowLigeroProof actual, LongfellowLigeroParameters parameters, int openedColumnCount)
    {
        Assert.IsTrue(actual.LowDegreeResponse.SequenceEqual(expected.LowDegreeResponse), "y_ldt must round-trip.");
        Assert.IsTrue(actual.DotResponse.SequenceEqual(expected.DotResponse), "y_dot must round-trip.");
        Assert.IsTrue(actual.QuadraticResponseLow.SequenceEqual(expected.QuadraticResponseLow), "y_quad_0 must round-trip.");
        Assert.IsTrue(actual.QuadraticResponseHigh.SequenceEqual(expected.QuadraticResponseHigh), "y_quad_2 must round-trip.");

        int columnBytes = parameters.RowCount * openedColumnCount * ScalarSize;
        Assert.IsTrue(actual.OpenedColumns[..columnBytes].SequenceEqual(expected.OpenedColumns[..columnBytes]), "The opened columns must round-trip through the Fp256 run codec.");

        for(int j = 0; j < openedColumnCount; j++)
        {
            Assert.IsTrue(actual.Nonce(j).SequenceEqual(expected.Nonce(j)), $"Nonce {j} must round-trip.");
        }

        Assert.AreEqual(expected.MerklePathLength, actual.MerklePathLength, "The Merkle path length must round-trip.");
        for(int i = 0; i < expected.MerklePathLength; i++)
        {
            Assert.IsTrue(actual.PathDigest(i).SequenceEqual(expected.PathDigest(i)), $"Merkle path digest {i} must round-trip.");
        }
    }


    //A sample row: the first `dimension` slots hold of_scalar(i·i + 7), the rest are zero (the RS encoder
    //fills them). Mirrors the Fp256 RS anchor's polynomial seeding shape.
    private static byte[] BuildSampleRow(int dimension, int blockLength)
    {
        byte[] row = new byte[blockLength * ScalarSize];
        for(int i = 0; i < dimension; i++)
        {
            OfScalar((uint)((i * i) + 7), row.AsSpan(i * ScalarSize, ScalarSize));
        }

        return row;
    }


    private static Fp256RealFft NewFft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    //A deterministic source whose every draw is below p: the most significant little-endian byte is
    //zeroed, so the 32-byte integer is < 2^248 < p and of_bytes_field accepts it.
    private static LongfellowRandomByteSource NewBelowModulusSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)((counter * 31) + 7);
                counter++;
            }

            if(destination.Length == Fp256ElementBytes)
            {
                destination[^1] = 0;
            }
        };
    }


    //of_scalar(u): the integer u reduced mod p as a canonical big-endian scalar.
    private static void OfScalar(uint coordinate, Span<byte> destination) =>
        Canonical(new BigInteger(coordinate) % Prime).CopyTo(destination);


    //fits(an): the canonical big-endian integer is below the modulus.
    private static bool InRange(ReadOnlySpan<byte> canonical) => ReadCanonicalBigEndian(canonical) < Prime;


    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        SHA256.HashData(input, output);


    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        foreach(byte b in value)
        {
            if(b != 0)
            {
                return false;
            }
        }

        return true;
    }


    private static byte[] Canonical(BigInteger value)
    {
        byte[] canonical = new byte[ScalarSize];
        value.TryWriteBytes(canonical, out int written, isUnsigned: true, isBigEndian: true);
        if(written < ScalarSize)
        {
            int shift = ScalarSize - written;
            canonical.AsSpan(0, written).CopyTo(canonical.AsSpan(shift));
            canonical.AsSpan(0, shift).Clear();
        }

        return canonical;
    }


    private static BigInteger ReadCanonicalBigEndian(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    //to_bytes_field for the test's own draws: the low 32 big-endian bytes reversed to little-endian.
    private static void WriteLittleEndian(BigInteger value, Span<byte> littleEndian)
    {
        byte[] canonical = Canonical(value);
        for(int i = 0; i < Fp256ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }
}
