using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The Nova-style fold step for relaxed R1CS: combines two satisfied
/// relaxed instance–witness pairs (the running accumulator and one
/// incoming statement) under a Fiat-Shamir challenge <c>r</c> into a
/// new satisfied relaxed pair, plus the folded error-commitment
/// opening witness.
/// </summary>
/// <remarks>
/// <para>
/// Both pairs share the coefficient matrices <c>A</c>, <c>B</c>,
/// <c>C</c> (the same constraint system). With <c>z = (u, public,
/// witness)</c> the fold is the linear combination
/// </para>
/// <list type="bullet">
///   <item><description><c>u₃ = u₁ + r · u₂</c></description></item>
///   <item><description><c>z₃ = z₁ + r · z₂</c> (so public and witness fold component-wise)</description></item>
///   <item><description><c>E₃ = E₁ + r · T + r² · E₂</c></description></item>
/// </list>
/// <para>
/// where the cross-term
/// <c>T = (A z₁) ∘ (B z₂) + (A z₂) ∘ (B z₁) − u₁ · (C z₂) − u₂ · (C z₁)</c>
/// captures the bilinear interaction between the two instances. The
/// algebra makes <c>(A z₃) ∘ (B z₃) = u₃ · (C z₃) + E₃</c> hold by
/// construction, so the folded pair is again a satisfied relaxed
/// instance and can be folded again.
/// </para>
/// <para>
/// The prover commits <c>T</c> under Hyrax (over the same row
/// variables as the error commitment); the verifier-chosen challenge
/// <c>r</c> is squeezed after the cross-term commitment is absorbed.
/// The folded error commitment and its opening witness combine
/// homomorphically:
/// <c>Comm(E₃) = Comm(E₁) + r · Comm(T) + r² · Comm(E₂)</c> and
/// <c>r_{E₃} = r_{E₁} + r · r_T + r² · r_{E₂}</c>, so the folded
/// commitment opens to the folded error vector with no recommitment.
/// </para>
/// </remarks>
public static class RelaxedR1csFold
{
    /// <summary>
    /// Folds <paramref name="left"/> (the accumulator) and
    /// <paramref name="right"/> (the incoming statement) into a new
    /// relaxed instance–witness pair plus the folded error-commitment
    /// opening witness. The caller owns the disposal of all three
    /// returned objects.
    /// </summary>
    /// <param name="left">The left (accumulator) relaxed instance.</param>
    /// <param name="leftWitness">The left witness.</param>
    /// <param name="leftErrorOpeningWitness">The left error-commitment opening witness (per-row blinding).</param>
    /// <param name="right">The right (incoming) relaxed instance.</param>
    /// <param name="rightWitness">The right witness.</param>
    /// <param name="rightErrorOpeningWitness">The right error-commitment opening witness.</param>
    /// <param name="provider">The commitment provider used to commit the cross-term (shared with the error commitments).</param>
    /// <param name="transcript">The fold transcript. The fold absorbs both instances' fold parameters and the cross-term commitment, then squeezes <c>r</c>.</param>
    /// <param name="hash">Fixed-output hash backend.</param>
    /// <param name="squeeze">XOF squeeze backend.</param>
    /// <param name="scalarReduce">Scalar-reduce backend.</param>
    /// <param name="scalarAdd">Scalar-add backend.</param>
    /// <param name="scalarSubtract">Scalar-subtract backend.</param>
    /// <param name="scalarMultiply">Scalar-multiply backend.</param>
    /// <param name="scalarRandom">Scalar-random backend (cross-term commitment blinding).</param>
    /// <param name="g1Add">G1-add backend (homomorphic commitment combination).</param>
    /// <param name="g1ScalarMultiply">G1 scalar-multiply backend.</param>
    /// <param name="g1Msm">G1 MSM backend (cross-term commitment).</param>
    /// <param name="pool">The pool to rent every buffer from.</param>
    /// <returns>The folded instance, witness, and error-commitment opening witness.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the two pairs disagree on curve, dimensions, or public-input count.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Intermediate disposables use using declarations; the three returned objects transfer ownership to the caller. The cross-term commitment/witness are disposed after their bytes are combined into the folded outputs.")]
    public static (RelaxedR1csInstance Instance, RelaxedR1csWitness Witness, PolynomialCommitmentBlind ErrorOpeningWitness) Fold(
        RelaxedR1csInstance left,
        RelaxedR1csWitness leftWitness,
        PolynomialCommitmentBlind leftErrorOpeningWitness,
        RelaxedR1csInstance right,
        RelaxedR1csWitness rightWitness,
        PolynomialCommitmentBlind rightErrorOpeningWitness,
        PolynomialCommitmentProvider provider,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate scalarReduce,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarRandomDelegate scalarRandom,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1MultiScalarMultiplyDelegate g1Msm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(leftWitness);
        ArgumentNullException.ThrowIfNull(leftErrorOpeningWitness);
        ArgumentNullException.ThrowIfNull(right);
        ArgumentNullException.ThrowIfNull(rightWitness);
        ArgumentNullException.ThrowIfNull(rightErrorOpeningWitness);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarSubtract);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Msm);
        ArgumentNullException.ThrowIfNull(pool);

        ValidateFoldable(left, leftWitness, right, rightWitness);

        CurveParameterSet curve = left.Curve;
        int scalarSize = R1csMatrix.GetValueByteSize(curve);
        int m = left.A.RowCount;
        int n = left.A.ColumnCount;
        int publicInputCount = left.PublicInputCount;
        int witnessCount = leftWitness.WitnessVariableCount;
        int rowVariableCount = System.Numerics.BitOperations.Log2((uint)m);

        CryptographicOperationCounters.Increment(CryptographicOperationKind.RelaxedR1csFold, curve);

        //Full assignment vectors z = (u, public, witness) for both sides.
        using IMemoryOwner<byte> z1Owner = pool.Rent(n * scalarSize);
        using IMemoryOwner<byte> z2Owner = pool.Rent(n * scalarSize);
        Span<byte> z1 = z1Owner.Memory.Span[..(n * scalarSize)];
        Span<byte> z2 = z2Owner.Memory.Span[..(n * scalarSize)];
        BuildAssignment(left, leftWitness, z1, scalarSize);
        BuildAssignment(right, rightWitness, z2, scalarSize);

        //Matrix-vector products for both sides.
        using IMemoryOwner<byte> az1Owner = pool.Rent(m * scalarSize);
        using IMemoryOwner<byte> bz1Owner = pool.Rent(m * scalarSize);
        using IMemoryOwner<byte> cz1Owner = pool.Rent(m * scalarSize);
        using IMemoryOwner<byte> az2Owner = pool.Rent(m * scalarSize);
        using IMemoryOwner<byte> bz2Owner = pool.Rent(m * scalarSize);
        using IMemoryOwner<byte> cz2Owner = pool.Rent(m * scalarSize);
        Span<byte> az1 = az1Owner.Memory.Span[..(m * scalarSize)];
        Span<byte> bz1 = bz1Owner.Memory.Span[..(m * scalarSize)];
        Span<byte> cz1 = cz1Owner.Memory.Span[..(m * scalarSize)];
        Span<byte> az2 = az2Owner.Memory.Span[..(m * scalarSize)];
        Span<byte> bz2 = bz2Owner.Memory.Span[..(m * scalarSize)];
        Span<byte> cz2 = cz2Owner.Memory.Span[..(m * scalarSize)];
        left.A.MatrixVectorProduct(z1, az1, scalarAdd, scalarMultiply, pool);
        left.B.MatrixVectorProduct(z1, bz1, scalarAdd, scalarMultiply, pool);
        left.C.MatrixVectorProduct(z1, cz1, scalarAdd, scalarMultiply, pool);
        right.A.MatrixVectorProduct(z2, az2, scalarAdd, scalarMultiply, pool);
        right.B.MatrixVectorProduct(z2, bz2, scalarAdd, scalarMultiply, pool);
        right.C.MatrixVectorProduct(z2, cz2, scalarAdd, scalarMultiply, pool);

        ReadOnlySpan<byte> u1 = left.GetUBytes();
        ReadOnlySpan<byte> u2 = right.GetUBytes();

        //Cross-term T[i] = az1·bz2 + az2·bz1 − u1·cz2 − u2·cz1.
        using IMemoryOwner<byte> tOwner = pool.Rent(m * scalarSize);
        Span<byte> tBytes = tOwner.Memory.Span[..(m * scalarSize)];
        ComputeCrossTerm(az1, bz1, cz1, az2, bz2, cz2, u1, u2, m, scalarSize, curve, tBytes, scalarAdd, scalarSubtract, scalarMultiply, pool);

        //Commit the cross-term over the row variables.
        using MultilinearExtension tMle = MultilinearExtension.FromEvaluations(tBytes, rowVariableCount, curve, pool);
        (PolynomialCommitment crossCommitment, PolynomialCommitmentBlind crossOpeningWitness) =
            provider.Commit(tMle, pool);

        using(crossCommitment)
        using(crossOpeningWitness)
        {
            //Absorb both instances' fold parameters and the cross-term
            //commitment, then squeeze the fold challenge r.
            AbsorbFoldParameters(transcript, WellKnownFoldingTranscriptLabels.LeftParameters, left, scalarSize, hash, pool);
            AbsorbFoldParameters(transcript, WellKnownFoldingTranscriptLabels.RightParameters, right, scalarSize, hash, pool);
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownFoldingTranscriptLabels.CrossTermCommitment),
                crossCommitment.AsReadOnlySpan(),
                hash);

            using Scalar r = transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownFoldingTranscriptLabels.Challenge),
                squeeze, hash, scalarReduce, curve, pool);
            ReadOnlySpan<byte> rBytes = r.AsReadOnlySpan();

            using IMemoryOwner<byte> rSquaredOwner = pool.Rent(scalarSize);
            Span<byte> rSquared = rSquaredOwner.Memory.Span[..scalarSize];
            scalarMultiply(rBytes, rBytes, rSquared, curve);

            //u3 = u1 + r·u2.
            using IMemoryOwner<byte> u3Owner = pool.Rent(scalarSize);
            Span<byte> u3 = u3Owner.Memory.Span[..scalarSize];
            CombineLinear(u1, u2, rBytes, u3, curve, scalarAdd, scalarMultiply);

            //public3 = public1 + r·public2 (component-wise).
            using IMemoryOwner<byte> public3Owner = pool.Rent(Math.Max(1, publicInputCount * scalarSize));
            Span<byte> public3 = public3Owner.Memory.Span[..(publicInputCount * scalarSize)];
            CombineVector(left.GetPublicInputsBytes(), right.GetPublicInputsBytes(), rBytes, publicInputCount, scalarSize, curve, public3, scalarAdd, scalarMultiply, pool);

            //witness3 = witness1 + r·witness2 (component-wise).
            using IMemoryOwner<byte> witness3Owner = pool.Rent(witnessCount * scalarSize);
            Span<byte> witness3 = witness3Owner.Memory.Span[..(witnessCount * scalarSize)];
            CombineVector(leftWitness.GetWitnessBytes(), rightWitness.GetWitnessBytes(), rBytes, witnessCount, scalarSize, curve, witness3, scalarAdd, scalarMultiply, pool);

            //E3 = E1 + r·T + r²·E2 (component-wise).
            using IMemoryOwner<byte> e3Owner = pool.Rent(m * scalarSize);
            Span<byte> e3 = e3Owner.Memory.Span[..(m * scalarSize)];
            CombineErrorVector(leftWitness.GetErrorBytes(), tBytes, rightWitness.GetErrorBytes(), rBytes, rSquared, m, scalarSize, curve, e3, scalarAdd, scalarMultiply, pool);

            //Homomorphic folded error commitment and opening witness. The
            //cross commitment carries rowCount compressed-G1 rows, so its byte
            //length divided by the G1 size recovers the row count.
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
            int rowCount = crossCommitment.AsReadOnlySpan().Length / g1Size;
            using IMemoryOwner<byte> foldedCommitmentOwner = pool.Rent(rowCount * g1Size);
            Span<byte> foldedCommitment = foldedCommitmentOwner.Memory.Span[..(rowCount * g1Size)];
            CombineCommitment(left.ErrorCommitment.AsReadOnlySpan(), crossCommitment.AsReadOnlySpan(), right.ErrorCommitment.AsReadOnlySpan(), rBytes, rSquared, rowCount, curve, foldedCommitment, g1Add, g1ScalarMultiply);

            using IMemoryOwner<byte> foldedBlindingOwner = pool.Rent(rowCount * scalarSize);
            Span<byte> foldedBlinding = foldedBlindingOwner.Memory.Span[..(rowCount * scalarSize)];
            CombineCommitment(leftErrorOpeningWitness.AsReadOnlySpan(), crossOpeningWitness.AsReadOnlySpan(), rightErrorOpeningWitness.AsReadOnlySpan(), rBytes, rSquared, rowCount, curve, foldedBlinding, scalarAdd, scalarMultiply);

            PolynomialCommitment foldedErrorCommitment = PolynomialCommitment.FromBytes(
                foldedCommitment, curve, provider.Scheme, pool);

            R1csMatrix aClone = CloneMatrix(left.A, pool);
            R1csMatrix bClone;
            R1csMatrix cClone;
            try
            {
                bClone = CloneMatrix(left.B, pool);
            }
            catch
            {
                aClone.Dispose();
                foldedErrorCommitment.Dispose();
                throw;
            }

            try
            {
                cClone = CloneMatrix(left.C, pool);
            }
            catch
            {
                aClone.Dispose();
                bClone.Dispose();
                foldedErrorCommitment.Dispose();
                throw;
            }

            RelaxedR1csInstance foldedInstance;
            try
            {
                foldedInstance = RelaxedR1csInstance.Create(aClone, bClone, cClone, public3, u3, foldedErrorCommitment, pool);
            }
            catch
            {
                aClone.Dispose();
                bClone.Dispose();
                cClone.Dispose();
                foldedErrorCommitment.Dispose();
                throw;
            }

            RelaxedR1csWitness foldedWitness;
            try
            {
                foldedWitness = RelaxedR1csWitness.FromCanonical(witness3, e3, curve, pool);
            }
            catch
            {
                foldedInstance.Dispose();
                throw;
            }

            try
            {
                PolynomialCommitmentBlind foldedErrorOpeningWitness = PolynomialCommitmentBlind.FromCanonical(foldedBlinding, curve, provider.Scheme, pool);

                return (foldedInstance, foldedWitness, foldedErrorOpeningWitness);
            }
            catch
            {
                foldedInstance.Dispose();
                foldedWitness.Dispose();
                throw;
            }
        }
    }


    private static void ValidateFoldable(
        RelaxedR1csInstance left,
        RelaxedR1csWitness leftWitness,
        RelaxedR1csInstance right,
        RelaxedR1csWitness rightWitness)
    {
        if(left.Curve.Code != right.Curve.Code
            || left.Curve.Code != leftWitness.Curve.Code
            || right.Curve.Code != rightWitness.Curve.Code)
        {
            throw new ArgumentException("Fold inputs must all share a curve.");
        }

        if(left.A.RowCount != right.A.RowCount || left.A.ColumnCount != right.A.ColumnCount)
        {
            throw new ArgumentException(
                $"Fold inputs must share dimensions; left is {left.A.RowCount}×{left.A.ColumnCount}, right is {right.A.RowCount}×{right.A.ColumnCount}.");
        }

        if(left.PublicInputCount != right.PublicInputCount)
        {
            throw new ArgumentException(
                $"Fold inputs must share public-input count; left has {left.PublicInputCount}, right has {right.PublicInputCount}.");
        }

        if(leftWitness.WitnessVariableCount != rightWitness.WitnessVariableCount)
        {
            throw new ArgumentException(
                $"Fold witnesses must share variable count; left has {leftWitness.WitnessVariableCount}, right has {rightWitness.WitnessVariableCount}.");
        }

        if(leftWitness.ErrorLength != left.A.RowCount || rightWitness.ErrorLength != right.A.RowCount)
        {
            throw new ArgumentException("Fold witness error lengths must equal the constraint count m.");
        }
    }


    private static void BuildAssignment(RelaxedR1csInstance instance, RelaxedR1csWitness witness, Span<byte> z, int scalarSize)
    {
        z.Clear();
        instance.GetUBytes().CopyTo(z[..scalarSize]);
        instance.GetPublicInputsBytes().CopyTo(z[scalarSize..]);
        int witnessOffset = (1 + instance.PublicInputCount) * scalarSize;
        witness.GetWitnessBytes().CopyTo(z[witnessOffset..]);
    }


    private static void ComputeCrossTerm(
        ReadOnlySpan<byte> az1, ReadOnlySpan<byte> bz1, ReadOnlySpan<byte> cz1,
        ReadOnlySpan<byte> az2, ReadOnlySpan<byte> bz2, ReadOnlySpan<byte> cz2,
        ReadOnlySpan<byte> u1, ReadOnlySpan<byte> u2,
        int m, int scalarSize, CurveParameterSet curve, Span<byte> tBytes,
        ScalarAddDelegate scalarAdd, ScalarSubtractDelegate scalarSubtract, ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> term = termOwner.Memory.Span[..scalarSize];

        for(int i = 0; i < m; i++)
        {
            int o = i * scalarSize;
            Span<byte> ti = tBytes.Slice(o, scalarSize);

            //ti = az1·bz2
            scalarMultiply(az1.Slice(o, scalarSize), bz2.Slice(o, scalarSize), ti, curve);
            //ti += az2·bz1
            scalarMultiply(az2.Slice(o, scalarSize), bz1.Slice(o, scalarSize), term, curve);
            scalarAdd(ti, term, ti, curve);
            //ti -= u1·cz2
            scalarMultiply(u1, cz2.Slice(o, scalarSize), term, curve);
            scalarSubtract(ti, term, ti, curve);
            //ti -= u2·cz1
            scalarMultiply(u2, cz1.Slice(o, scalarSize), term, curve);
            scalarSubtract(ti, term, ti, curve);
        }
    }


    private static void AbsorbFoldParameters(
        FiatShamirTranscript transcript, string label, RelaxedR1csInstance instance, int scalarSize,
        FiatShamirHashDelegate hash, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> uBytes = instance.GetUBytes();
        ReadOnlySpan<byte> publicBytes = instance.GetPublicInputsBytes();
        ReadOnlySpan<byte> commitmentBytes = instance.ErrorCommitment.AsReadOnlySpan();

        int size = uBytes.Length + publicBytes.Length + commitmentBytes.Length;
        using IMemoryOwner<byte> bufferOwner = pool.Rent(size);
        Span<byte> buffer = bufferOwner.Memory.Span[..size];
        uBytes.CopyTo(buffer);
        publicBytes.CopyTo(buffer[uBytes.Length..]);
        commitmentBytes.CopyTo(buffer[(uBytes.Length + publicBytes.Length)..]);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(label), buffer, hash);
    }


    //out = a + r·b.
    private static void CombineLinear(
        ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> r, Span<byte> output,
        CurveParameterSet curve, ScalarAddDelegate scalarAdd, ScalarMultiplyDelegate scalarMultiply)
    {
        scalarMultiply(r, b, output, curve);
        scalarAdd(a, output, output, curve);
    }


    //out[i] = a[i] + r·b[i] for count elements.
    private static void CombineVector(
        ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> r, int count, int scalarSize,
        CurveParameterSet curve, Span<byte> output, ScalarAddDelegate scalarAdd, ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> term = termOwner.Memory.Span[..scalarSize];
        for(int i = 0; i < count; i++)
        {
            int o = i * scalarSize;
            scalarMultiply(r, b.Slice(o, scalarSize), term, curve);
            scalarAdd(a.Slice(o, scalarSize), term, output.Slice(o, scalarSize), curve);
        }
    }


    //out[i] = e1[i] + r·t[i] + r²·e2[i] for count elements.
    private static void CombineErrorVector(
        ReadOnlySpan<byte> e1, ReadOnlySpan<byte> t, ReadOnlySpan<byte> e2, ReadOnlySpan<byte> r, ReadOnlySpan<byte> rSquared,
        int count, int scalarSize, CurveParameterSet curve, Span<byte> output,
        ScalarAddDelegate scalarAdd, ScalarMultiplyDelegate scalarMultiply, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> term = termOwner.Memory.Span[..scalarSize];
        for(int i = 0; i < count; i++)
        {
            int o = i * scalarSize;
            Span<byte> outI = output.Slice(o, scalarSize);
            scalarMultiply(r, t.Slice(o, scalarSize), term, curve);
            scalarAdd(e1.Slice(o, scalarSize), term, outI, curve);
            scalarMultiply(rSquared, e2.Slice(o, scalarSize), term, curve);
            scalarAdd(outI, term, outI, curve);
        }
    }


    //Group version: out[i] = c1[i] + r·ct[i] + r²·c2[i] per 48-byte G1 row.
    private static void CombineCommitment(
        ReadOnlySpan<byte> c1, ReadOnlySpan<byte> ct, ReadOnlySpan<byte> c2, ReadOnlySpan<byte> r, ReadOnlySpan<byte> rSquared,
        int rowCount, CurveParameterSet curve, Span<byte> output, G1AddDelegate g1Add, G1ScalarMultiplyDelegate g1ScalarMultiply)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        Span<byte> term = stackalloc byte[g1Size];
        for(int i = 0; i < rowCount; i++)
        {
            int o = i * g1Size;
            Span<byte> outI = output.Slice(o, g1Size);
            g1ScalarMultiply(ct.Slice(o, g1Size), r, term, curve);
            g1Add(c1.Slice(o, g1Size), term, outI, curve);
            g1ScalarMultiply(c2.Slice(o, g1Size), rSquared, term, curve);
            g1Add(outI, term, outI, curve);
        }
    }


    //Scalar version: out[i] = b1[i] + r·bt[i] + r²·b2[i] per 32-byte blinding row.
    private static void CombineCommitment(
        ReadOnlySpan<byte> b1, ReadOnlySpan<byte> bt, ReadOnlySpan<byte> b2, ReadOnlySpan<byte> r, ReadOnlySpan<byte> rSquared,
        int rowCount, CurveParameterSet curve, Span<byte> output, ScalarAddDelegate scalarAdd, ScalarMultiplyDelegate scalarMultiply)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> term = stackalloc byte[scalarSize];
        for(int i = 0; i < rowCount; i++)
        {
            int o = i * scalarSize;
            Span<byte> outI = output.Slice(o, scalarSize);
            scalarMultiply(r, bt.Slice(o, scalarSize), term, curve);
            scalarAdd(b1.Slice(o, scalarSize), term, outI, curve);
            scalarMultiply(rSquared, b2.Slice(o, scalarSize), term, curve);
            scalarAdd(outI, term, outI, curve);
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The cloned matrix transfers ownership to the caller (RelaxedR1csInstance.Create), whose Dispose chain releases it.")]
    private static R1csMatrix CloneMatrix(R1csMatrix source, BaseMemoryPool pool)
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
}