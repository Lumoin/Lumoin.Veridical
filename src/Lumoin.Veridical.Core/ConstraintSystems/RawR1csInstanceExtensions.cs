using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Satisfaction-check extension on <see cref="RawR1csInstance"/>.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class RawR1csInstanceExtensions
{
    extension(RawR1csInstance instance)
    {
        /// <summary>
        /// Returns <see cref="R1csSatisfaction.Satisfied"/> when
        /// <paramref name="witness"/> satisfies every constraint of
        /// <paramref name="instance"/>; otherwise the first failing
        /// constraint surfaces as <see cref="R1csSatisfaction.Violated"/>.
        /// </summary>
        public R1csSatisfaction CheckSatisfiedBy(
            RawR1csWitness witness,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMul,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMul);
            ArgumentNullException.ThrowIfNull(pool);

            if(instance.Curve.Code != witness.Curve.Code)
            {
                throw new ArgumentException(
                    $"Instance ({instance.Curve}) and witness ({witness.Curve}) must share a curve.");
            }

            int scalarSize = R1csMatrix.GetValueByteSize(instance.Curve);
            int n = instance.A.ColumnCount;
            int m = instance.A.RowCount;

            int expectedWitnessLength = (n - 1 - instance.PublicInputCount) * scalarSize;
            if(witness.GetWitnessBytes().Length != expectedWitnessLength)
            {
                throw new ArgumentException(
                    $"Witness byte length {witness.GetWitnessBytes().Length} must equal {expectedWitnessLength} ({n - 1 - instance.PublicInputCount} × {scalarSize}).");
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.R1csCheckSatisfaction, instance.Curve);

            //Build z = (1, publicInputs, witness).
            using IMemoryOwner<byte> zOwner = pool.Rent(n * scalarSize);
            Span<byte> z = zOwner.Memory.Span[..(n * scalarSize)];
            z.Clear();
            z[scalarSize - 1] = 0x01;
            instance.GetPublicInputsBytes().CopyTo(z[scalarSize..]);
            int witnessOffset = (1 + instance.PublicInputCount) * scalarSize;
            witness.GetWitnessBytes().CopyTo(z[witnessOffset..]);

            using IMemoryOwner<byte> azOwner = pool.Rent(m * scalarSize);
            using IMemoryOwner<byte> bzOwner = pool.Rent(m * scalarSize);
            using IMemoryOwner<byte> czOwner = pool.Rent(m * scalarSize);
            Span<byte> az = azOwner.Memory.Span[..(m * scalarSize)];
            Span<byte> bz = bzOwner.Memory.Span[..(m * scalarSize)];
            Span<byte> cz = czOwner.Memory.Span[..(m * scalarSize)];

            instance.A.MatrixVectorProduct(z, az, scalarAdd, scalarMul, pool);
            instance.B.MatrixVectorProduct(z, bz, scalarAdd, scalarMul, pool);
            instance.C.MatrixVectorProduct(z, cz, scalarAdd, scalarMul, pool);

            using IMemoryOwner<byte> productOwner = pool.Rent(scalarSize);
            Span<byte> product = productOwner.Memory.Span[..scalarSize];

            for(int row = 0; row < m; row++)
            {
                ReadOnlySpan<byte> azRow = az.Slice(row * scalarSize, scalarSize);
                ReadOnlySpan<byte> bzRow = bz.Slice(row * scalarSize, scalarSize);
                ReadOnlySpan<byte> czRow = cz.Slice(row * scalarSize, scalarSize);

                scalarMul(azRow, bzRow, product, instance.Curve);
                if(!product.SequenceEqual(czRow))
                {
                    return BuildViolatedResult(instance, row, product, czRow, pool);
                }
            }


            return new R1csSatisfaction.Satisfied();
        }


        /// <summary>
        /// Prepares a raw R1CS instance for proving by producing the
        /// equivalent relaxed R1CS instance with <c>u = 1</c> and the
        /// Hyrax commitment to the zero error vector. Forwards to the
        /// delegate-free <see cref="Prepare(RawR1csInstance, SensitiveMemoryPool{byte})"/>;
        /// the commitment key and the scalar-random and G1-MSM delegates
        /// are retained on this signature for API stability across
        /// future commitment-scheme variants but are not consulted,
        /// because preparation is deterministic (see the delegate-free
        /// overload's remarks).
        /// </summary>
        /// <param name="provider">The commitment provider a real (non-zero) error commitment would use. Not consulted.</param>
        /// <param name="scalarRandom">Scalar-random backend a hiding commitment would draw per-row blinding from. Not consulted.</param>
        /// <param name="g1Msm">G1 multi-scalar multiplication a real commit would invoke. Not consulted.</param>
        /// <param name="pool">Pool for the relaxed instance's allocations.</param>
        /// <returns>The prepared relaxed instance with <c>u = 1</c> and a zero-error commitment.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the R1CS row count is not a power of two.</exception>
        [SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "provider, scalarRandom, and g1Msm are retained for API stability across future commitment-scheme variants; preparation is deterministic (the zero-error commitment is the G1 identity, which both prover and verifier must reproduce), so they are not consulted. See the delegate-free Prepare overload.")]
        public RelaxedR1csInstance Prepare(
            PolynomialCommitmentProvider provider,
            ScalarRandomDelegate scalarRandom,
            G1MultiScalarMultiplyDelegate g1Msm,
            SensitiveMemoryPool<byte> pool)
        {
            return instance.Prepare(pool);
        }


        /// <summary>
        /// Prepares a raw R1CS instance for proving or verifying by
        /// producing the equivalent relaxed R1CS instance with
        /// <c>u = 1</c> and the Hyrax commitment to the zero error
        /// vector. The relaxed form is what the unified Spartan prover
        /// and verifier consume natively.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Preparation is fully deterministic and needs no algebraic
        /// delegates: the zero error vector commits to the G1 identity
        /// element (every term in the multi-exponentiation is zero
        /// times a basis element), so the error commitment is the
        /// identity regardless of the commitment scheme. This is also
        /// why preparation <em>must</em> be deterministic — the prover
        /// and verifier independently prepare the same raw instance and
        /// have to reach the identical error commitment. A real
        /// (non-zero) error commitment with blinding only ever arises
        /// from a folding step (Nova), never from preparation.
        /// </para>
        /// <para>
        /// Requires power-of-two row count, matching the constraint
        /// Spartan and Hyrax already place on R1CS dimensions elsewhere.
        /// </para>
        /// </remarks>
        /// <param name="pool">Pool for the relaxed instance's allocations.</param>
        /// <returns>The prepared relaxed instance with <c>u = 1</c> and a zero-error commitment.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the R1CS row count is not a power of two.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The cloned matrices and the identity error commitment transfer ownership to RelaxedR1csInstance.Create, whose returned instance disposes them through its own Dispose chain.")]
        public RelaxedR1csInstance Prepare(SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(pool);

            int m = instance.A.RowCount;
            if(!BitOperations.IsPow2(m))
            {
                throw new ArgumentException(
                    $"Prepare requires power-of-two row count m; received {m}.");
            }

            int variableCount = BitOperations.Log2((uint)m);
            HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(variableCount);

            //Identity Hyrax commitment to the zero error vector:
            //rowCount × g1Size bytes, each row the curve's canonical
            //compressed G1 identity (gnark/BLS infinity encoding differs
            //per curve, so it is read from WellKnownCurves, not hardcoded).
            //This is the deterministic commitment to zero that a hiding,
            //pairing-based scheme uses; both prover and verifier reproduce it
            //without randomness.
            int rowCount = dimensions.RowCount;
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(instance.Curve);
            ReadOnlySpan<byte> identityPoint = WellKnownCurves.GetG1IdentityCompressed(instance.Curve);
            using IMemoryOwner<byte> identityOwner = pool.Rent(rowCount * g1Size);
            Span<byte> identityCommitmentBytes = identityOwner.Memory.Span[..(rowCount * g1Size)];
            identityCommitmentBytes.Clear();
            for(int i = 0; i < rowCount; i++)
            {
                identityPoint.CopyTo(identityCommitmentBytes.Slice(i * g1Size, g1Size));
            }

            //The identity error commitment carries scheme-agnostic bytes (the
            //compressed-G1 identity per row); it is tagged with the only wired
            //scheme. A future scheme would thread its own identity here.
            PolynomialCommitment errorCommitment = PolynomialCommitment.FromBytes(
                identityCommitmentBytes, instance.Curve, CommitmentScheme.Hyrax, pool);

            return CreateRelaxedFromRaw(instance, errorCommitment, pool);
        }


        /// <summary>
        /// Prepares a raw R1CS instance for proving or verifying under a
        /// <em>transparent, deterministic-commit</em> scheme (BaseFold) by
        /// committing the zero error vector through <paramref name="pcs"/>. The
        /// resulting error commitment is the scheme's own commitment to zero (a
        /// Merkle root for BaseFold), not a pairing-group identity.
        /// </summary>
        /// <remarks>
        /// Use this overload only when <paramref name="pcs"/>'s commitment is a
        /// deterministic function of the polynomial (no per-commitment blinding),
        /// so the prover and verifier independently reproduce the identical
        /// error commitment. For a hiding scheme (Hyrax) use the delegate-free
        /// <see cref="Prepare(RawR1csInstance, SensitiveMemoryPool{byte})"/>,
        /// whose zero-error commitment is the deterministic group identity.
        /// </remarks>
        /// <param name="pcs">The transparent commitment provider used to commit the zero error vector.</param>
        /// <param name="pool">Pool for the relaxed instance's allocations.</param>
        /// <returns>The prepared relaxed instance with <c>u = 1</c> and a scheme-shaped zero-error commitment.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the R1CS row count is not a power of two.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The committed error commitment transfers ownership to CreateRelaxedFromRaw, which transfers it to RelaxedR1csInstance.Create (disposed through its Dispose chain) or disposes it on the failure path.")]
        public RelaxedR1csInstance Prepare(PolynomialCommitmentProvider pcs, SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(pcs);
            ArgumentNullException.ThrowIfNull(pool);

            int m = instance.A.RowCount;
            if(!BitOperations.IsPow2(m))
            {
                throw new ArgumentException(
                    $"Prepare requires power-of-two row count m; received {m}.");
            }

            int variableCount = BitOperations.Log2((uint)m);

            //Commit the zero error vector through the provider. For a transparent
            //hash-based scheme this is deterministic, so prover and verifier reach
            //the identical commitment. The placeholder blind is discarded — the
            //raw instance has no hiding randomness.
            using MultilinearExtension zeroError = MultilinearExtension.Zero(variableCount, instance.Curve, pool);
            (PolynomialCommitment errorCommitment, PolynomialCommitmentBlind blind) = pcs.Commit(zeroError, pool);
            blind.Dispose();

            return CreateRelaxedFromRaw(instance, errorCommitment, pool);
        }
    }


    //Builds the relaxed instance shell (u = 1, cloned matrices, public inputs)
    //around an already-built zero-error commitment, whose ownership it takes.
    //Shared by both Prepare overloads so the matrix-clone and u handling live
    //once; the overloads differ only in how they form the zero-error commitment.
    [SuppressMessage("Reliability", "CA2000", Justification = "Cloned matrices and the error commitment transfer to RelaxedR1csInstance.Create; on any failure path each is disposed before rethrow.")]
    private static RelaxedR1csInstance CreateRelaxedFromRaw(
        RawR1csInstance instance,
        PolynomialCommitment errorCommitment,
        SensitiveMemoryPool<byte> pool)
    {
        int scalarSize = R1csMatrix.GetValueByteSize(instance.Curve);

        //u = 1: canonical big-endian scalar 0x00...0001.
        Span<byte> uBytes = stackalloc byte[scalarSize];
        uBytes.Clear();
        uBytes[scalarSize - 1] = 0x01;

        R1csMatrix aClone = CloneMatrix(instance.A, pool);
        R1csMatrix bClone;
        R1csMatrix cClone;
        try
        {
            bClone = CloneMatrix(instance.B, pool);
        }
        catch
        {
            aClone.Dispose();
            errorCommitment.Dispose();
            throw;
        }

        try
        {
            cClone = CloneMatrix(instance.C, pool);
        }
        catch
        {
            aClone.Dispose();
            bClone.Dispose();
            errorCommitment.Dispose();
            throw;
        }

        try
        {
            return RelaxedR1csInstance.Create(
                aClone, bClone, cClone,
                instance.GetPublicInputsBytes(),
                uBytes,
                errorCommitment,
                pool);
        }
        catch
        {
            aClone.Dispose();
            bClone.Dispose();
            cClone.Dispose();
            errorCommitment.Dispose();
            throw;
        }
    }


    private static R1csMatrix CloneMatrix(R1csMatrix source, SensitiveMemoryPool<byte> pool)
    {
        int nnz = source.NonzeroCount;
        int[] rows = new int[nnz];
        int[] columns = new int[nnz];
        for(int i = 0; i < nnz; i++)
        {
            (int row, int column) = source.GetTriplePosition(i);
            rows[i] = row;
            columns[i] = column;
        }

        return R1csMatrix.FromSortedTriples(
            rows, columns, source.GetValuesBytes(),
            source.RowCount, source.ColumnCount, source.Curve, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The scalars take ownership of their pool-rented buffers and are returned to the caller through R1csSatisfaction.Violated; the caller's Dispose chains through.")]
    private static R1csSatisfaction.Violated BuildViolatedResult(
        RawR1csInstance instance,
        int row,
        ReadOnlySpan<byte> lhsBytes,
        ReadOnlySpan<byte> rhsBytes,
        SensitiveMemoryPool<byte> pool)
    {
        var lhs = Scalar.FromCanonical(lhsBytes, instance.Curve, pool);
        var rhs = Scalar.FromCanonical(rhsBytes, instance.Curve, pool);

        return new R1csSatisfaction.Violated(
            new R1csConstraintIndex(row),
            lhs,
            rhs,
            CollectInvolvedVariables(instance, row));
    }


    /// <summary>
    /// Returns the sorted unique variable indices that appear in row
    /// <paramref name="row"/> of any of <paramref name="instance"/>'s
    /// matrices. Used for diagnostic narrowing in
    /// <see cref="R1csSatisfaction.Violated"/>.
    /// </summary>
    private static List<R1csVariableIndex> CollectInvolvedVariables(RawR1csInstance instance, int row)
    {
        var variables = new SortedSet<int>();
        CollectFromRow(instance.A, row, variables);
        CollectFromRow(instance.B, row, variables);
        CollectFromRow(instance.C, row, variables);

        var result = new List<R1csVariableIndex>(variables.Count);
        foreach(int column in variables)
        {
            result.Add(new R1csVariableIndex(column));
        }


        return result;
    }


    private static void CollectFromRow(R1csMatrix matrix, int row, SortedSet<int> destination)
    {
        for(int i = 0; i < matrix.NonzeroCount; i++)
        {
            int currentRow = BinaryPrimitives.ReadInt32BigEndian(matrix.GetRowIndicesBytes().Slice(i * sizeof(int), sizeof(int)));
            if(currentRow == row)
            {
                int column = BinaryPrimitives.ReadInt32BigEndian(matrix.GetColumnIndicesBytes().Slice(i * sizeof(int), sizeof(int)));
                destination.Add(column);
            }
            else if(currentRow > row)
            {
                //Triples are sorted, so we can stop at the first row past the target.
                return;
            }
        }
    }
}