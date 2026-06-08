using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// Gates the Ligero tableau build and its column Merkle commitment (LF.4b.2)
/// over the small Mersenne-prime field. The structural properties checked are
/// the ones the protocol responses will rely on: the witness and quadratic
/// operand values land in the systematic columns the layout assigns them, the
/// IQUAD witness block is zero and the IDOT witness block sums to zero, the
/// prover rejects an unsatisfied multiplication constraint, the root is
/// deterministic in the prover randomness, and every committed column
/// authenticates against that root (including the zero-padding when the
/// extension width is not a power of two).
/// </summary>
[TestClass]
internal sealed class LigeroTableauTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //A satisfying witness vector and its two multiplication constraints:
    //W[2] = W[0]·W[1] (6 = 2·3) and W[5] = W[3]·W[4] (20 = 4·5).
    private static readonly int[] WitnessValues = [2, 3, 6, 4, 5, 20];
    private static readonly LigeroQuadraticConstraint[] Constraints =
    [
        new LigeroQuadraticConstraint(0, 1, 2),
        new LigeroQuadraticConstraint(3, 4, 5),
    ];

    private const int WitnessCount = 6;
    private const int QuadraticCount = 2;
    private const int InverseRate = 2;
    private const int OpenedColumns = 2;

    //A fixed seed makes the prover randomness reproducible so two builds yield
    //byte-identical commitments.
    private static readonly byte[] RandomnessSeed = [0x4C, 0x46, 0x34, 0x62]; //"LF4b"

    private static readonly MerkleHashDelegate Blake3TwoToOne = HashTwoToOne;


    [TestMethod]
    public void WitnessRowCarriesTheWitnessValues()
    {
        //block=8 -> r=2, w=6: a single witness row holds all six witnesses in
        //columns [r, r+w).
        LigeroParameters parameters = new(WitnessCount, QuadraticCount, InverseRate, OpenedColumns, block: 8);
        using LigeroTableau tableau = BuildSatisfyingTableau(parameters);

        Span<byte> column = stackalloc byte[parameters.RowCount * ScalarSize];
        for(int k = 0; k < WitnessCount; k++)
        {
            tableau.GetColumn(parameters.RandomCount + k, column);
            BigInteger carried = ReadCanonical(column.Slice(LigeroParameters.FirstWitnessRowIndex * ScalarSize, ScalarSize));
            Assert.AreEqual((BigInteger)WitnessValues[k], carried, $"Witness row column {k} must carry W[{k}].");
        }
    }


    [TestMethod]
    public void QuadraticRowsCarryTheOperandValues()
    {
        LigeroParameters parameters = new(WitnessCount, QuadraticCount, InverseRate, OpenedColumns, block: 8);
        using LigeroTableau tableau = BuildSatisfyingTableau(parameters);

        Span<byte> column = stackalloc byte[parameters.RowCount * ScalarSize];
        for(int c = 0; c < QuadraticCount; c++)
        {
            LigeroQuadraticConstraint constraint = Constraints[c];

            tableau.GetColumn(parameters.RandomCount + c, column);
            BigInteger x = ReadCanonical(column.Slice(parameters.FirstQuadraticXRowIndex * ScalarSize, ScalarSize));
            BigInteger y = ReadCanonical(column.Slice(parameters.FirstQuadraticYRowIndex * ScalarSize, ScalarSize));
            BigInteger z = ReadCanonical(column.Slice(parameters.FirstQuadraticZRowIndex * ScalarSize, ScalarSize));

            Assert.AreEqual((BigInteger)WitnessValues[constraint.XIndex], x, $"Constraint {c} x-operand must be W[{constraint.XIndex}].");
            Assert.AreEqual((BigInteger)WitnessValues[constraint.YIndex], y, $"Constraint {c} y-operand must be W[{constraint.YIndex}].");
            Assert.AreEqual((BigInteger)WitnessValues[constraint.ZIndex], z, $"Constraint {c} z-operand must be W[{constraint.ZIndex}].");
        }
    }


    [TestMethod]
    public void QuadraticRowWitnessBlockIsZeroInTheBlindingRow()
    {
        LigeroParameters parameters = new(WitnessCount, QuadraticCount, InverseRate, OpenedColumns, block: 8);
        using LigeroTableau tableau = BuildSatisfyingTableau(parameters);

        //The IQUAD blinding row's witness columns [r, r+w) must be zero so the
        //quadratic test's blinding contributes nothing to the witness block.
        Span<byte> column = stackalloc byte[parameters.RowCount * ScalarSize];
        for(int k = 0; k < parameters.WitnessPerRow; k++)
        {
            tableau.GetColumn(parameters.RandomCount + k, column);
            BigInteger entry = ReadCanonical(column.Slice(LigeroParameters.QuadraticRowIndex * ScalarSize, ScalarSize));
            Assert.AreEqual(BigInteger.Zero, entry, $"IQUAD witness column {k} must be zero.");
        }
    }


    [TestMethod]
    public void DotRowWitnessBlockSumsToZero()
    {
        LigeroParameters parameters = new(WitnessCount, QuadraticCount, InverseRate, OpenedColumns, block: 8);
        using LigeroTableau tableau = BuildSatisfyingTableau(parameters);

        //The IDOT blinding row's witness columns [r, r+w) must sum to the
        //field's zero so the dot-product value check is unbiased.
        Span<byte> column = stackalloc byte[parameters.RowCount * ScalarSize];
        BigInteger sum = BigInteger.Zero;
        for(int k = 0; k < parameters.WitnessPerRow; k++)
        {
            tableau.GetColumn(parameters.RandomCount + k, column);
            sum += ReadCanonical(column.Slice(LigeroParameters.DotRowIndex * ScalarSize, ScalarSize));
        }

        Assert.AreEqual(BigInteger.Zero, sum % SmallPrimeFieldScalars.FieldOrder, "The IDOT witness block must sum to zero modulo the field order.");
    }


    [TestMethod]
    public void RejectsAnUnsatisfiedQuadraticConstraint()
    {
        LigeroParameters parameters = new(WitnessCount, QuadraticCount, InverseRate, OpenedColumns, block: 8);

        //Flip W[2] so 7 != 2·3; the prover must refuse to build the tableau.
        int[] brokenValues = [2, 3, 7, 4, 5, 20];
        Assert.ThrowsExactly<InvalidOperationException>(() => BuildTableau(parameters, brokenValues, Constraints).Dispose());
    }


    [TestMethod]
    public void RootIsDeterministicInTheProverRandomness()
    {
        LigeroParameters parameters = new(WitnessCount, QuadraticCount, InverseRate, OpenedColumns, block: 8);

        using LigeroTableau first = BuildSatisfyingTableau(parameters);
        using MerkleTree firstTree = CommitColumns(first);
        Span<byte> firstRoot = stackalloc byte[DigestSizeBytes];
        firstTree.Root.AsReadOnlySpan().CopyTo(firstRoot);

        using LigeroTableau second = BuildSatisfyingTableau(parameters);
        using MerkleTree secondTree = CommitColumns(second);

        Assert.IsTrue(firstRoot.SequenceEqual(secondTree.Root.AsReadOnlySpan()), "The same prover randomness must yield the same commitment root.");
    }


    [TestMethod]
    [DataRow(8, "extension width already a power of two")]
    [DataRow(6, "extension width padded up to a power of two")]
    public void EveryCommittedColumnAuthenticatesAgainstTheRoot(int block, string scenario)
    {
        LigeroParameters parameters = new(WitnessCount, QuadraticCount, InverseRate, OpenedColumns, block);
        using LigeroTableau tableau = BuildSatisfyingTableau(parameters);
        using MerkleTree tree = CommitColumns(tableau);

        Span<byte> column = stackalloc byte[parameters.RowCount * ScalarSize];
        Span<byte> leaf = stackalloc byte[DigestSizeBytes];
        for(int j = 0; j < parameters.BlockExtension; j++)
        {
            tableau.GetColumn(parameters.DoubleBlock + j, column);
            Blake3.Hash(column, leaf);

            using MerkleAuthenticationPath path = tree.BuildPath(j, SensitiveMemoryPool<byte>.Shared);
            bool authenticated = path.Verify(tree.Root, j, leaf, Blake3TwoToOne);

            Assert.IsTrue(authenticated, $"Committed column {j} must authenticate against the root ({scenario}).");
        }
    }


    private static LigeroTableau BuildSatisfyingTableau(LigeroParameters parameters) =>
        BuildTableau(parameters, WitnessValues, Constraints);


    private static LigeroTableau BuildTableau(LigeroParameters parameters, ReadOnlySpan<int> witnessValues, ReadOnlySpan<LigeroQuadraticConstraint> constraints)
    {
        Span<byte> witnesses = stackalloc byte[witnessValues.Length * ScalarSize];
        for(int i = 0; i < witnessValues.Length; i++)
        {
            WriteCanonical(witnessValues[i], witnesses.Slice(i * ScalarSize, ScalarSize));
        }

        SmallFieldDeterministicRandom random = new(RandomnessSeed);
        return LigeroTableau.Build(
            parameters,
            witnesses,
            constraints,
            random.AsDelegate(),
            SmallPrimeFieldScalars.GetAdd(),
            SmallPrimeFieldScalars.GetSubtract(),
            SmallPrimeFieldScalars.GetMultiply(),
            SmallPrimeFieldScalars.GetInvert(),
            CurveParameterSet.None,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static MerkleTree CommitColumns(LigeroTableau tableau) =>
        tableau.CommitColumns(
            Blake3FiatShamirBackend.GetHash(),
            WellKnownHashAlgorithms.Blake3,
            Blake3TwoToOne,
            SensitiveMemoryPool<byte>.Shared);


    //Wires BLAKE3 as the two-to-one Merkle compression over concatenated children.
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private static BigInteger ReadCanonical(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    //A reproducible small-field prover-randomness source: each call hashes
    //seed ‖ counter through BLAKE3-XOF and reduces the wide output modulo the
    //small prime field order. Test-only; production draws from a CSPRNG.
    private sealed class SmallFieldDeterministicRandom
    {
        private readonly byte[] seed;
        private int counter;


        public SmallFieldDeterministicRandom(ReadOnlySpan<byte> seed)
        {
            this.seed = seed.ToArray();
            counter = 0;
        }


        public ScalarRandomDelegate AsDelegate() => Fill;


        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);

            BigInteger value = new(wide, isUnsigned: true, isBigEndian: true);
            BigInteger reduced = value % SmallPrimeFieldScalars.FieldOrder;
            WriteCanonical(reduced, destination);

            return inboundTag;
        }
    }
}
