using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// One polynomial's wires, the reference's <c>MLDSAVerify::RqW</c>: 256 field-element wires
/// declared without bitness assertions.
/// </summary>
internal sealed class LongfellowMlDsaPolynomialWires
{
    /// <summary>The coefficient wires.</summary>
    public int[] Coefficients { get; } = new int[LongfellowMlDsaParameters.CoefficientCount];


    /// <summary>The reference's <c>RqW::input</c>: declares one element wire per coefficient.</summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    public void Input(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            Coefficients[i] = logic.InputElement();
        }
    }
}


/// <summary>
/// The expanded matrix's wires, the reference's <c>MLDSAVerify::MatrixAW</c>: one polynomial per
/// position, declared row-major.
/// </summary>
internal sealed class LongfellowMlDsaMatrixWires
{
    /// <summary>The matrix positions, indexed row then column.</summary>
    public LongfellowMlDsaPolynomialWires[][] Rows { get; }


    /// <summary>Allocates the matrix for a parameter set.</summary>
    /// <param name="parameters">The parameter set.</param>
    public LongfellowMlDsaMatrixWires(LongfellowMlDsaParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        Rows = new LongfellowMlDsaPolynomialWires[parameters.RowCount][];
        for(int row = 0; row < parameters.RowCount; row++)
        {
            Rows[row] = new LongfellowMlDsaPolynomialWires[parameters.ColumnCount];
            for(int column = 0; column < parameters.ColumnCount; column++)
            {
                Rows[row][column] = new LongfellowMlDsaPolynomialWires();
            }
        }
    }


    /// <summary>The reference's <c>MatrixAW::input</c>: declares every position row-major.</summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    public void Input(LongfellowLogic logic)
    {
        for(int row = 0; row < Rows.Length; row++)
        {
            for(int column = 0; column < Rows[row].Length; column++)
            {
                Rows[row][column].Input(logic);
            }
        }
    }
}


/// <summary>
/// The public key's wires, the reference's <c>MLDSAVerify::Pk</c>: the expanded matrix, the scaled
/// rounded vector in the NTT domain, and the public-key hash bytes.
/// </summary>
internal sealed class LongfellowMlDsaPublicKeyWires
{
    /// <summary>The expanded matrix (the reference's <c>a_hat</c>).</summary>
    public LongfellowMlDsaMatrixWires MatrixA { get; }

    /// <summary>The scaled rounded vector in the NTT domain (the reference's <c>nttt1</c>).</summary>
    public LongfellowMlDsaPolynomialWires[] NttT1 { get; }

    /// <summary>The 64 public-key hash bytes (the reference's <c>tr</c>).</summary>
    public LongfellowBitWire[][] Tr { get; } = new LongfellowBitWire[LongfellowMlDsaReference.PublicKeyHashBytes][];


    /// <summary>Allocates the bundle for a parameter set.</summary>
    /// <param name="parameters">The parameter set.</param>
    public LongfellowMlDsaPublicKeyWires(LongfellowMlDsaParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        MatrixA = new LongfellowMlDsaMatrixWires(parameters);
        NttT1 = NewPolynomials(parameters.RowCount);
    }


    /// <summary>The reference's <c>Pk::input</c>: the matrix, the vector, then the hash bytes.</summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    public void Input(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        MatrixA.Input(logic);
        for(int i = 0; i < NttT1.Length; i++)
        {
            NttT1[i].Input(logic);
        }

        for(int i = 0; i < Tr.Length; i++)
        {
            Tr[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }
    }


    /// <summary>Allocates one polynomial bundle per index.</summary>
    /// <param name="count">The polynomial count.</param>
    /// <returns>The bundles.</returns>
    internal static LongfellowMlDsaPolynomialWires[] NewPolynomials(int count)
    {
        var polynomials = new LongfellowMlDsaPolynomialWires[count];
        for(int i = 0; i < count; i++)
        {
            polynomials[i] = new LongfellowMlDsaPolynomialWires();
        }

        return polynomials;
    }
}


/// <summary>
/// The signature's wires, the reference's <c>MLDSAVerify::SignatureW</c>: the commitment hash
/// bytes, the response vector with its shifted bit decompositions, and the hint polynomials.
/// </summary>
internal sealed class LongfellowMlDsaSignatureWires
{
    /// <summary>The commitment hash bytes (the reference's <c>c_tilde</c>).</summary>
    public LongfellowBitWire[][] CommitmentHash { get; }

    /// <summary>The response vector (the reference's <c>z</c>).</summary>
    public LongfellowMlDsaPolynomialWires[] Z { get; }

    /// <summary>The shifted response-coefficient bits (the reference's <c>z_bits</c>), indexed column then coefficient.</summary>
    public LongfellowBitWire[][][] ZBits { get; }

    /// <summary>The hint polynomials (the reference's <c>h</c>).</summary>
    public LongfellowMlDsaPolynomialWires[] Hints { get; }

    private readonly LongfellowMlDsaParameters parameters;


    /// <summary>Allocates the bundle for a parameter set.</summary>
    /// <param name="parameters">The parameter set.</param>
    public LongfellowMlDsaSignatureWires(LongfellowMlDsaParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        this.parameters = parameters;
        CommitmentHash = new LongfellowBitWire[parameters.CommitmentBytes][];
        Z = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.ColumnCount);
        ZBits = new LongfellowBitWire[parameters.ColumnCount][][];
        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            ZBits[i] = new LongfellowBitWire[LongfellowMlDsaParameters.CoefficientCount][];
        }

        Hints = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.RowCount);
    }


    /// <summary>The reference's <c>SignatureW::input</c>: the hash bytes, the vector, the bit decompositions, then the hints.</summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    public void Input(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        for(int i = 0; i < parameters.CommitmentBytes; i++)
        {
            CommitmentHash[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }

        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            Z[i].Input(logic);
        }

        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                ZBits[i][j] = logic.InputVector(parameters.ResponseBitWidth);
            }
        }

        for(int i = 0; i < parameters.RowCount; i++)
        {
            Hints[i].Input(logic);
        }
    }
}


/// <summary>
/// The SampleInBall witness's wires, the reference's <c>MLDSAVerify::SampleInBallWitness</c>: the
/// accepted samples with their stream indices, the sponge witness, and the shuffle position trace.
/// </summary>
internal sealed class LongfellowMlDsaSampleInBallWitnessWires
{
    /// <summary>The sponge witness of the SampleInBall hash (the reference's <c>shake_bws</c>).</summary>
    public LongfellowSha3BlockWitnessWires BlockWitness { get; } = new();

    /// <summary>The accepted samples (the reference's <c>j_vals</c>).</summary>
    public LongfellowBitWire[][] JValues { get; }

    /// <summary>The stream index of each accepted sample (the reference's <c>j_k_indices</c>).</summary>
    public LongfellowBitWire[][] JIndices { get; }

    /// <summary>The shuffle position trace (the reference's <c>position_trace</c>): step <c>s</c> holds <c>s + 1</c> positions.</summary>
    public LongfellowBitWire[][][] PositionTrace { get; }

    private readonly LongfellowMlDsaParameters parameters;


    /// <summary>Allocates the bundle for a parameter set.</summary>
    /// <param name="parameters">The parameter set.</param>
    public LongfellowMlDsaSampleInBallWitnessWires(LongfellowMlDsaParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        this.parameters = parameters;
        JValues = new LongfellowBitWire[parameters.ChallengeWeight][];
        JIndices = new LongfellowBitWire[parameters.ChallengeWeight][];
        PositionTrace = new LongfellowBitWire[parameters.ChallengeWeight][][];
        for(int s = 0; s < parameters.ChallengeWeight; s++)
        {
            PositionTrace[s] = new LongfellowBitWire[s + 1][];
        }
    }


    /// <summary>The reference's <c>SampleInBallWitness::input</c>: the interleaved samples and indices, the sponge witness, then the trace.</summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    public void Input(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        for(int i = 0; i < parameters.ChallengeWeight; i++)
        {
            JValues[i] = logic.InputVector(LongfellowLogic.BitWidth8);
            JIndices[i] = logic.InputVector(LongfellowLogic.BitWidth16);
        }

        BlockWitness.Input(logic);

        for(int s = 0; s < parameters.ChallengeWeight; s++)
        {
            for(int k = 0; k <= s; k++)
            {
                PositionTrace[s][k] = logic.InputVector(LongfellowLogic.BitWidth8);
            }
        }
    }
}


/// <summary>
/// The prover witness's wires, the reference's <c>MLDSAVerify::Witness</c>: the SampleInBall
/// witness, the challenge, the per-row UseHint values, the NTT-domain values, the packed high
/// bits, the commitment sponge witnesses, and the hint-weight sum.
/// </summary>
/// <remarks>
/// The commitment sponge witness count is a construction argument, mirroring the reference's
/// resize-before-<c>input</c> convention: the full-statement and ctilde shapes size it to the block
/// count, and the use-hint shape leaves it empty.
/// </remarks>
internal sealed class LongfellowMlDsaWitnessWires
{
    /// <summary>The SampleInBall witness (the reference's <c>sample_in_ball_</c>).</summary>
    public LongfellowMlDsaSampleInBallWitnessWires SampleInBall { get; }

    /// <summary>The challenge polynomial (the reference's <c>c_</c>).</summary>
    public LongfellowMlDsaPolynomialWires Challenge { get; } = new();

    /// <summary>The approximate commitment recomputation (the reference's <c>w_prime_approx_</c>).</summary>
    public LongfellowMlDsaPolynomialWires[] WPrimeApprox { get; }

    /// <summary>The unhinted high bits (the reference's <c>w1_</c>).</summary>
    public LongfellowMlDsaPolynomialWires[] W1 { get; }

    /// <summary>The unhinted high bits' decompositions (the reference's <c>w1_bits_</c>).</summary>
    public LongfellowBitWire[][][] W1Bits { get; }

    /// <summary>The interval-shift auxiliary bits (the reference's <c>hint_aux_bits_</c>).</summary>
    public LongfellowBitWire[][][] HintAuxBits { get; }

    /// <summary>The hinted high bits (the reference's <c>w_prime_1_</c>).</summary>
    public LongfellowMlDsaPolynomialWires[] WPrime1 { get; }

    /// <summary>The hinted high bits' decompositions (the reference's <c>w_prime_1_bits_</c>).</summary>
    public LongfellowBitWire[][][] WPrime1Bits { get; }

    /// <summary>The response vector in the NTT domain (the reference's <c>nttz_</c>).</summary>
    public LongfellowMlDsaPolynomialWires[] NttZ { get; }

    /// <summary>The challenge polynomial in the NTT domain (the reference's <c>nttc_</c>).</summary>
    public LongfellowMlDsaPolynomialWires NttC { get; } = new();

    /// <summary>The packed high-bits bytes (the reference's <c>w1_tilde_</c>).</summary>
    public LongfellowBitWire[][] W1Tilde { get; }

    /// <summary>The commitment sponge witnesses (the reference's <c>c_prime_tilde_bws_</c>).</summary>
    public LongfellowSha3BlockWitnessWires[] CommitmentBlockWitnesses { get; }

    /// <summary>The hint-weight sum bits (the reference's <c>h_sum_bits_</c>); assignable because the evaluation harness interns its value directly, as the reference's converters write the struct field.</summary>
    public LongfellowBitWire[] HintSumBits { get; set; } = [];

    private readonly LongfellowMlDsaParameters parameters;


    /// <summary>Allocates the bundle for a parameter set and a commitment sponge witness count.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="commitmentBlockCount">The commitment sponge witness count (zero for shapes that never hash the commitment).</param>
    public LongfellowMlDsaWitnessWires(LongfellowMlDsaParameters parameters, int commitmentBlockCount)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        this.parameters = parameters;
        SampleInBall = new LongfellowMlDsaSampleInBallWitnessWires(parameters);
        WPrimeApprox = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.RowCount);
        W1 = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.RowCount);
        W1Bits = NewBitGrid(parameters.RowCount);
        HintAuxBits = NewBitGrid(parameters.RowCount);
        WPrime1 = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.RowCount);
        WPrime1Bits = NewBitGrid(parameters.RowCount);
        NttZ = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.ColumnCount);
        W1Tilde = new LongfellowBitWire[parameters.RowCount * parameters.HighBitsBytes][];
        CommitmentBlockWitnesses = new LongfellowSha3BlockWitnessWires[commitmentBlockCount];
        for(int i = 0; i < commitmentBlockCount; i++)
        {
            CommitmentBlockWitnesses[i] = new LongfellowSha3BlockWitnessWires();
        }
    }


    /// <summary>The reference's <c>Witness::input</c>: every region in the reference's declaration order.</summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    public void Input(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        SampleInBall.Input(logic);
        Challenge.Input(logic);
        for(int i = 0; i < parameters.RowCount; i++)
        {
            WPrimeApprox[i].Input(logic);
            W1[i].Input(logic);
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                W1Bits[i][j] = logic.InputVector(parameters.HighBitsWidth);
            }

            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                HintAuxBits[i][j] = logic.InputVector(parameters.LowBitsWidth + 1);
            }

            WPrime1[i].Input(logic);
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                WPrime1Bits[i][j] = logic.InputVector(parameters.HighBitsWidth);
            }
        }

        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            NttZ[i].Input(logic);
        }

        NttC.Input(logic);
        for(int i = 0; i < W1Tilde.Length; i++)
        {
            W1Tilde[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }

        for(int i = 0; i < CommitmentBlockWitnesses.Length; i++)
        {
            CommitmentBlockWitnesses[i].Input(logic);
        }

        HintSumBits = logic.InputVector(parameters.HintWeightBitWidth);
    }


    /// <summary>Allocates one 256-entry bit-vector grid per row.</summary>
    /// <param name="rowCount">The row count.</param>
    /// <returns>The grid.</returns>
    private static LongfellowBitWire[][][] NewBitGrid(int rowCount)
    {
        var grid = new LongfellowBitWire[rowCount][][];
        for(int i = 0; i < rowCount; i++)
        {
            grid[i] = new LongfellowBitWire[LongfellowMlDsaParameters.CoefficientCount][];
        }

        return grid;
    }
}


/// <summary>
/// The ML-DSA signature verification circuit, a faithful port of google/longfellow-zk's
/// <c>MLDSAVerify</c> (<c>circuits/tests/pq/ml_dsa/ml_dsa_circuit.h</c>, FIPS 204): the constrained
/// SampleInBall shuffle, the NTT consistency assertions, the interval-shifting UseHint check, the
/// infinity-norm range checks, the high-bits packing, and the SHAKE256 commitment binding, composed
/// by <see cref="AssertValidSignatureOnMu"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every gadget emits wires in the reference's exact order because the wire creation order shapes
/// the compiled circuit's scheduling and elimination counters. The UseHint interval shift ports the
/// reference's <em>code</em>, whose shift constant is <c>γ2</c> even where its narrative comment
/// says <c>γ2 − 1</c>.
/// </para>
/// <para>
/// The reference marks its ML-DSA circuit as an experimental research implementation, not vetted
/// for production; this port carries the same status until the statements it serves are themselves
/// production-gated.
/// </para>
/// </remarks>
internal sealed class LongfellowMlDsaVerifyCircuit
{
    /// <summary>The SHAKE256 sponge rate in bytes.</summary>
    private const int Rate = 136;

    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>One lane's bit width.</summary>
    private const int LaneBits = 64;

    /// <summary>The single-byte SHAKE padding (the <c>1111</c> domain suffix, pad-start and pad-end bits in one byte).</summary>
    private const byte ShakePadSingle = 0x9F;

    /// <summary>The SHAKE suffix-and-first-padding byte.</summary>
    private const byte ShakePadFirst = 0x1F;

    /// <summary>The final padding byte.</summary>
    private const byte PadLast = 0x80;

    private readonly LongfellowLogic logic;
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowLogicFieldOperations field;
    private readonly LongfellowMlDsaParameters parameters;
    private readonly int subfieldBitCount;


    /// <summary>
    /// Constructs the circuit over a gadget layer for a parameter set.
    /// </summary>
    /// <param name="logic">The gadget layer to build on.</param>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="subfieldBitCount">The field's subfield bit width, forwarded to the SHAKE256 gadget's re-anchoring assertion split.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public LongfellowMlDsaVerifyCircuit(LongfellowLogic logic, LongfellowMlDsaParameters parameters, int subfieldBitCount)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentNullException.ThrowIfNull(parameters);

        this.logic = logic;
        backend = logic.Backend;
        field = logic.Field;
        this.parameters = parameters;
        this.subfieldBitCount = subfieldBitCount;
    }


    /// <summary>The reference's <c>matrix_vector_mul</c>: <c>y = A·x</c> coefficient-wise in the NTT domain, accumulated from a zero constant.</summary>
    /// <param name="matrix">The matrix.</param>
    /// <param name="x">The input vector.</param>
    /// <param name="y">Receives the product.</param>
    public void MatrixVectorMultiply(LongfellowMlDsaMatrixWires matrix, LongfellowMlDsaPolynomialWires[] x, LongfellowMlDsaPolynomialWires[] y)
    {
        ArgumentNullException.ThrowIfNull(matrix);
        ArgumentNullException.ThrowIfNull(x);
        ArgumentNullException.ThrowIfNull(y);

        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int c = 0; c < LongfellowMlDsaParameters.CoefficientCount; c++)
            {
                y[i].Coefficients[c] = backend.Constant(field.Compiler.Zero.Span);
            }

            for(int j = 0; j < parameters.ColumnCount; j++)
            {
                for(int c = 0; c < LongfellowMlDsaParameters.CoefficientCount; c++)
                {
                    y[i].Coefficients[c] = backend.Add(y[i].Coefficients[c], backend.Mul(matrix.Rows[i][j].Coefficients[c], x[j].Coefficients[c]));
                }
            }
        }
    }


    /// <summary>The reference's <c>scalar_vector_mul</c>: <c>y = c∘x</c> coefficient-wise in the NTT domain.</summary>
    /// <param name="c">The scalar polynomial.</param>
    /// <param name="x">The input vector.</param>
    /// <param name="y">Receives the product.</param>
    public void ScalarVectorMultiply(LongfellowMlDsaPolynomialWires c, LongfellowMlDsaPolynomialWires[] x, LongfellowMlDsaPolynomialWires[] y)
    {
        ArgumentNullException.ThrowIfNull(c);
        ArgumentNullException.ThrowIfNull(x);
        ArgumentNullException.ThrowIfNull(y);

        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                y[i].Coefficients[k] = backend.Mul(c.Coefficients[k], x[i].Coefficients[k]);
            }
        }
    }


    /// <summary>
    /// The reference's <c>assert_ntt</c>: recomputes the Cooley-Tukey butterflies (FIPS 204
    /// Algorithm 41) over the input's wires with constant twiddles and asserts the result equals
    /// the claimed transform.
    /// </summary>
    /// <param name="c">The coefficient-domain polynomial.</param>
    /// <param name="cPrime">The claimed transform.</param>
    public void AssertNtt(LongfellowMlDsaPolynomialWires c, LongfellowMlDsaPolynomialWires cPrime)
    {
        ArgumentNullException.ThrowIfNull(c);
        ArgumentNullException.ThrowIfNull(cPrime);

        var p = new int[LongfellowMlDsaParameters.CoefficientCount];
        c.Coefficients.CopyTo(p, 0);

        int k = 1;
        int length = LongfellowMlDsaParameters.CoefficientCount / 2;
        while(length > 0)
        {
            for(int start = 0; start < LongfellowMlDsaParameters.CoefficientCount; start += 2 * length)
            {
                ReadOnlyMemory<byte> zeta = field.OfScalar(LongfellowMlDsaConstants.NttZetas[k]);
                ReadOnlyMemory<byte> negatedZeta = field.Negate(zeta.Span);
                k++;
                for(int j = start; j < start + length; j++)
                {
                    int t = backend.Axpy(p[j], zeta.Span, p[j + length]);
                    p[j + length] = backend.Axpy(p[j], negatedZeta.Span, p[j + length]);
                    p[j] = t;
                }
            }

            length /= 2;
        }

        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            _ = logic.AssertEqual(p[i], cPrime.Coefficients[i]);
        }
    }


    /// <summary>
    /// The reference's <c>assert_inverse_ntt</c>: recomputes the Gentleman-Sande butterflies (FIPS
    /// 204 Algorithm 42) with descending constant twiddles, scales by the
    /// <see cref="LongfellowMlDsaParameters.InverseTransformScale"/> constant wire, and asserts the
    /// result equals the claimed inverse transform.
    /// </summary>
    /// <param name="c">The NTT-domain polynomial.</param>
    /// <param name="cPrime">The claimed inverse transform.</param>
    public void AssertInverseNtt(LongfellowMlDsaPolynomialWires c, LongfellowMlDsaPolynomialWires cPrime)
    {
        ArgumentNullException.ThrowIfNull(c);
        ArgumentNullException.ThrowIfNull(cPrime);

        var p = new int[LongfellowMlDsaParameters.CoefficientCount];
        c.Coefficients.CopyTo(p, 0);

        int k = LongfellowMlDsaParameters.CoefficientCount;
        int length = 1;
        while(length < LongfellowMlDsaParameters.CoefficientCount)
        {
            for(int start = 0; start < LongfellowMlDsaParameters.CoefficientCount; start += 2 * length)
            {
                k--;
                ReadOnlyMemory<byte> negatedZeta = field.Negate(field.OfScalar(LongfellowMlDsaConstants.NttZetas[k]).Span);
                for(int j = start; j < start + length; j++)
                {
                    int t = p[j];
                    p[j] = backend.Add(t, p[j + length]);
                    int difference = backend.Sub(t, p[j + length]);
                    p[j + length] = backend.MultiplyScaled(negatedZeta.Span, difference);
                }
            }

            length *= 2;
        }

        int scale = backend.Constant(field.OfScalar(LongfellowMlDsaParameters.InverseTransformScale).Span);
        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            p[i] = backend.Mul(scale, p[i]);
            _ = logic.AssertEqual(p[i], cPrime.Coefficients[i]);
        }
    }


    /// <summary>
    /// The reference's <c>assert_use_hint_single</c>: validates one coefficient's UseHint (FIPS 204
    /// Algorithm 40) through the interval-shifting optimization — one range check on the shifted
    /// remainder, a sign bit constrained to the remainder's half-interval, and the cubic congruence
    /// binding the hinted high bits to the raw high bits plus the shift.
    /// </summary>
    /// <param name="hintWire">The hint bit's element wire.</param>
    /// <param name="rWire">The approximate coefficient's wire.</param>
    /// <param name="rawHighWire">The claimed unhinted high bits.</param>
    /// <param name="rawHighBits">The unhinted high bits' decomposition.</param>
    /// <param name="hintRemainderBits">The shifted remainder's decomposition with the sign bit on top.</param>
    /// <param name="hintedHighWire">The claimed hinted high bits.</param>
    /// <param name="hintedHighBits">The hinted high bits' decomposition.</param>
    public void AssertUseHintSingle(
        int hintWire,
        int rWire,
        int rawHighWire,
        LongfellowBitWire[] rawHighBits,
        LongfellowBitWire[] hintRemainderBits,
        int hintedHighWire,
        LongfellowBitWire[] hintedHighBits)
    {
        ArgumentNullException.ThrowIfNull(rawHighBits);
        ArgumentNullException.ThrowIfNull(hintRemainderBits);
        ArgumentNullException.ThrowIfNull(hintedHighBits);

        int twoGamma2 = backend.Constant(field.OfScalar(2UL * parameters.RoundingRange).Span);
        int shiftValue = backend.Constant(field.OfScalar(parameters.RoundingRange).Span);
        int zero = backend.Constant(field.Compiler.Zero.Span);

        _ = logic.AssertIsBit(hintWire);

        int rawHighReconstructed = logic.AsScalar(rawHighBits);
        _ = logic.AssertEqual(rawHighWire, rawHighReconstructed);
        LongfellowBitWire[] highBound = logic.BitVector(parameters.HighBitsWidth, parameters.HintModulus - 1);
        LongfellowBitWire isRawHighValid = logic.LessThanOrEqual(rawHighBits, highBound);
        _ = logic.AssertOne(isRawHighValid);

        int shiftedRemainder = logic.AsScalar(LongfellowLogic.Slice(hintRemainderBits, 0, parameters.LowBitsWidth));

        LongfellowBitWire[] remainderBound = logic.BitVector(parameters.LowBitsWidth, 2UL * parameters.RoundingRange);
        LongfellowBitWire isRemainderBounded = logic.LessThanOrEqual(LongfellowLogic.Slice(hintRemainderBits, 0, parameters.LowBitsWidth), remainderBound);
        _ = logic.AssertOne(isRemainderBounded);

        LongfellowBitWire signBit = hintRemainderBits[parameters.LowBitsWidth];

        LongfellowBitWire[] shiftedRemainderBits = LongfellowLogic.Slice(hintRemainderBits, 0, parameters.LowBitsWidth);
        LongfellowBitWire isLowHalf = logic.LessThanOrEqual(shiftedRemainderBits, parameters.RoundingRange);
        _ = logic.AssertEqual(logic.Eval(signBit), logic.Eval(isLowHalf));

        int negatedHint = backend.Sub(zero, hintWire);
        int shiftIndicator = logic.Mux(signBit, negatedHint, hintWire);

        int delta = backend.Sub(shiftedRemainder, shiftValue);

        int highTerm = backend.Mul(rawHighWire, twoGamma2);
        int reconstructed = backend.Add(highTerm, delta);
        _ = logic.AssertEqual(rWire, reconstructed);

        int hintedHighReconstructed = logic.AsScalar(hintedHighBits);
        _ = logic.AssertEqual(hintedHighWire, hintedHighReconstructed);
        LongfellowBitWire isHintedHighValid = logic.LessThanOrEqual(hintedHighBits, highBound);
        _ = logic.AssertOne(isHintedHighValid);

        int difference = backend.Sub(rawHighWire, hintedHighWire);
        int shiftDifference = backend.Add(difference, shiftIndicator);

        int hintModulus = backend.Constant(field.OfScalar(parameters.HintModulus).Span);
        int differenceMinusModulus = backend.Sub(shiftDifference, hintModulus);
        int differencePlusModulus = backend.Add(shiftDifference, hintModulus);

        int product = backend.Mul(shiftDifference, differenceMinusModulus);
        product = backend.Mul(product, differencePlusModulus);
        _ = logic.AssertZero(product);
    }


    /// <summary>
    /// The reference's <c>assert_use_hint</c>: the per-coefficient UseHint validation over the full
    /// vector, plus the hint-weight bound <c>Σh ≤ ω</c> through the witnessed sum bits.
    /// </summary>
    /// <param name="hints">The hint polynomials.</param>
    /// <param name="wPrimeApprox">The approximate commitment recomputation.</param>
    /// <param name="w1">The unhinted high bits.</param>
    /// <param name="w1Bits">The unhinted high bits' decompositions.</param>
    /// <param name="hintAuxBits">The interval-shift auxiliary bits.</param>
    /// <param name="wPrime1">The hinted high bits.</param>
    /// <param name="wPrime1Bits">The hinted high bits' decompositions.</param>
    /// <param name="hintSumBits">The hint-weight sum bits.</param>
    public void AssertUseHint(
        LongfellowMlDsaPolynomialWires[] hints,
        LongfellowMlDsaPolynomialWires[] wPrimeApprox,
        LongfellowMlDsaPolynomialWires[] w1,
        LongfellowBitWire[][][] w1Bits,
        LongfellowBitWire[][][] hintAuxBits,
        LongfellowMlDsaPolynomialWires[] wPrime1,
        LongfellowBitWire[][][] wPrime1Bits,
        LongfellowBitWire[] hintSumBits)
    {
        ArgumentNullException.ThrowIfNull(hints);
        ArgumentNullException.ThrowIfNull(wPrimeApprox);
        ArgumentNullException.ThrowIfNull(w1);
        ArgumentNullException.ThrowIfNull(w1Bits);
        ArgumentNullException.ThrowIfNull(hintAuxBits);
        ArgumentNullException.ThrowIfNull(wPrime1);
        ArgumentNullException.ThrowIfNull(wPrime1Bits);
        ArgumentNullException.ThrowIfNull(hintSumBits);

        int sum = backend.Constant(field.Compiler.Zero.Span);
        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                AssertUseHintSingle(
                    hints[i].Coefficients[k],
                    wPrimeApprox[i].Coefficients[k],
                    w1[i].Coefficients[k],
                    w1Bits[i][k],
                    hintAuxBits[i][k],
                    wPrime1[i].Coefficients[k],
                    wPrime1Bits[i][k]);
                sum = backend.Add(sum, hints[i].Coefficients[k]);
            }
        }

        LongfellowBitWire isValidWeight = logic.LessThanOrEqual(hintSumBits, (ulong)parameters.HintWeightBound);
        _ = logic.AssertOne(isValidWeight);

        int reconstructedSum = logic.AsScalar(hintSumBits);
        _ = logic.AssertEqual(sum, reconstructedSum);
    }


    /// <summary>
    /// The reference's <c>assert_infty_norm</c>: asserts every coefficient lies in
    /// <c>[−bound, bound − 1]</c> by binding its shifted value to the witnessed decomposition and
    /// bounding the decomposition by <c>2·bound − 2</c>.
    /// </summary>
    /// <param name="vector">The polynomials to bound.</param>
    /// <param name="vectorBits">The shifted coefficients' decompositions.</param>
    /// <param name="bound">The strict infinity-norm bound.</param>
    public void AssertInfinityNorm(LongfellowMlDsaPolynomialWires[] vector, LongfellowBitWire[][][] vectorBits, ulong bound)
    {
        ArgumentNullException.ThrowIfNull(vector);
        ArgumentNullException.ThrowIfNull(vectorBits);

        for(int i = 0; i < vector.Length; i++)
        {
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                int reconstructed = logic.AsScalar(vectorBits[i][j]);

                int shifted = backend.Add(vector[i].Coefficients[j], backend.Constant(field.OfScalar(bound - 1).Span));
                _ = logic.AssertEqual(shifted, reconstructed);

                LongfellowBitWire isBounded = logic.LessThanOrEqual(vectorBits[i][j], logic.BitVector(vectorBits[i][j].Length, (2 * bound) - 2));
                _ = logic.AssertOne(isBounded);
            }
        }
    }


    /// <summary>
    /// The reference's <c>assert_w1_encode</c>: asserts the packed high-bits bytes equal the FIPS
    /// 204 Algorithm 28 packing of the hinted high bits' decompositions, with any residual bits of
    /// the final byte constrained to constant zero.
    /// </summary>
    /// <param name="wPrime1Bits">The hinted high bits' decompositions.</param>
    /// <param name="putativeW1Tilde">The claimed packed bytes.</param>
    public void AssertW1Encode(LongfellowBitWire[][][] wPrime1Bits, LongfellowBitWire[][] putativeW1Tilde)
    {
        ArgumentNullException.ThrowIfNull(wPrime1Bits);
        ArgumentNullException.ThrowIfNull(putativeW1Tilde);

        int bitsPerCoefficient = parameters.HighBitsWidth;
        int totalBytes = parameters.RowCount * parameters.HighBitsBytes;

        var allBits = new List<LongfellowBitWire>(parameters.RowCount * LongfellowMlDsaParameters.CoefficientCount * bitsPerCoefficient);
        for(int k = 0; k < parameters.RowCount; k++)
        {
            for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
            {
                for(int b = 0; b < bitsPerCoefficient; b++)
                {
                    allBits.Add(wPrime1Bits[k][i][b]);
                }
            }
        }

        for(int i = 0; i < totalBytes; i++)
        {
            var packedByte = new LongfellowBitWire[LongfellowLogic.BitWidth8];
            for(int b = 0; b < LongfellowLogic.BitWidth8; b++)
            {
                packedByte[b] = (i * LongfellowLogic.BitWidth8) + b < allBits.Count ? allBits[(i * LongfellowLogic.BitWidth8) + b] : logic.Bit(0);
            }

            logic.AssertEqual(putativeW1Tilde[i], packedByte);
        }
    }


    /// <summary>
    /// The reference's <c>assert_sample_in_ball</c>: validates the challenge generation (FIPS 204
    /// Algorithm 29) — the SHAKE256 stream, the rejection-sampling walk with its skipped-byte
    /// justifications, the parallel Fisher-Yates position trace, and the final polynomial
    /// construction from the trace's sign contributions.
    /// </summary>
    /// <param name="rho">The commitment hash bytes seeding the sampler.</param>
    /// <param name="cPrime">The claimed challenge polynomial.</param>
    /// <param name="witness">The SampleInBall witness.</param>
    public void AssertSampleInBall(LongfellowBitWire[][] rho, LongfellowMlDsaPolynomialWires cPrime, LongfellowMlDsaSampleInBallWitnessWires witness)
    {
        ArgumentNullException.ThrowIfNull(rho);
        ArgumentNullException.ThrowIfNull(cPrime);
        ArgumentNullException.ThrowIfNull(witness);

        var sha3 = new LongfellowSha3Circuit(logic, subfieldBitCount);
        LongfellowBitWire[][] stream = sha3.AssertShake256(rho, LongfellowMlDsaReference.SampleInBallHashBytes, [witness.BlockWitness]);

        LongfellowBitWire[] previousIndex = logic.BitVector(LongfellowLogic.BitWidth16, LongfellowMlDsaReference.SampleInBallStreamStart);

        for(int s = 0; s < parameters.ChallengeWeight; s++)
        {
            int i = LongfellowMlDsaParameters.CoefficientCount - parameters.ChallengeWeight + s;
            LongfellowBitWire[] j = witness.JValues[s];
            LongfellowBitWire[] streamIndex = witness.JIndices[s];

            LongfellowBitWire isInBounds = logic.LessThanOrEqual(streamIndex, (ulong)(stream.Length - 1));
            _ = logic.AssertOne(isInBounds);

            LongfellowBitWire isIncreasing = logic.LessThanOrEqual(previousIndex, streamIndex);
            _ = logic.AssertOne(isIncreasing);

            LongfellowBitWire[] jExtended = logic.BitVector(LongfellowLogic.BitWidth16, 0);
            for(int b = 0; b < LongfellowLogic.BitWidth8; b++)
            {
                jExtended[b] = j[b];
            }

            LongfellowBitWire[] targetVector = logic.BitVector(LongfellowLogic.BitWidth16, (ulong)i);
            LongfellowBitWire isSampleValid = logic.LessThanOrEqual(jExtended, targetVector);
            _ = logic.AssertOne(isSampleValid);

            for(int k = 0; k < stream.Length; k++)
            {
                LongfellowBitWire[] currentIndex = logic.BitVector(LongfellowLogic.BitWidth16, (ulong)k);
                LongfellowBitWire isTarget = logic.Equal(currentIndex, streamIndex);

                LongfellowBitWire matchesSample = logic.Equal(stream[k], j);
                _ = logic.AssertImplies(isTarget, matchesSample);

                LongfellowBitWire atOrAfterPrevious = logic.LessThanOrEqual(previousIndex, currentIndex);
                LongfellowBitWire beforeTarget = logic.LessThan(currentIndex, streamIndex);
                LongfellowBitWire inSkippedRange = logic.And(atOrAfterPrevious, beforeTarget);

                LongfellowBitWire[] streamByteExtended = logic.BitVector(LongfellowLogic.BitWidth16, 0);
                for(int b = 0; b < LongfellowLogic.BitWidth8; b++)
                {
                    streamByteExtended[b] = stream[k][b];
                }

                LongfellowBitWire wasRejected = logic.LessThan(targetVector, streamByteExtended);
                _ = logic.AssertImplies(inSkippedRange, wasRejected);
            }

            previousIndex = logic.Add(streamIndex, 1UL);
        }

        logic.AssertEqual(witness.PositionTrace[0][0], witness.JValues[0]);

        for(int s = 1; s < parameters.ChallengeWeight; s++)
        {
            int i = LongfellowMlDsaParameters.CoefficientCount - parameters.ChallengeWeight + s;
            LongfellowBitWire[] j = witness.JValues[s];

            LongfellowBitWire[][] previousPositions = witness.PositionTrace[s - 1];
            LongfellowBitWire[][] currentPositions = witness.PositionTrace[s];

            logic.AssertEqual(currentPositions[s], j);

            for(int k = 0; k < s; k++)
            {
                LongfellowBitWire[] position = previousPositions[k];
                LongfellowBitWire isSwapped = logic.Equal(position, j);
                LongfellowBitWire[] targetIndex = logic.BitVector(LongfellowLogic.BitWidth8, (ulong)i);
                var expected = new LongfellowBitWire[LongfellowLogic.BitWidth8];
                for(int b = 0; b < LongfellowLogic.BitWidth8; b++)
                {
                    expected[b] = logic.Mux(isSwapped, targetIndex[b], position[b]);
                }

                logic.AssertEqual(currentPositions[k], expected);
            }
        }

        LongfellowBitWire[][] finalPositions = witness.PositionTrace[parameters.ChallengeWeight - 1];
        int one = backend.Constant(field.Compiler.One.Span);
        int minusOne = backend.Constant(field.Compiler.MinusOne.Span);
        int zero = backend.Constant(field.Compiler.Zero.Span);

        var traceValues = new int[parameters.ChallengeWeight];
        for(int s = 0; s < parameters.ChallengeWeight; s++)
        {
            LongfellowBitWire signBit = stream[s / LongfellowLogic.BitWidth8][s % LongfellowLogic.BitWidth8];
            traceValues[s] = logic.Mux(signBit, minusOne, one);
        }

        for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
        {
            LongfellowBitWire[] coefficientIndex = logic.BitVector(LongfellowLogic.BitWidth8, (ulong)k);

            int contribution = logic.Add(0, parameters.ChallengeWeight, s =>
            {
                LongfellowBitWire isMatch = logic.Equal(finalPositions[s], coefficientIndex);

                return logic.Mux(isMatch, traceValues[s], zero);
            });

            _ = logic.AssertEqual(cPrime.Coefficients[k], contribution);
        }
    }


    /// <summary>
    /// The reference's <c>prepare_mu_input</c>: concatenates the public-key hash and the bound
    /// message, then appends the SHAKE256 padding as constant bytes — the single-byte case when
    /// exactly one pad byte fits, otherwise the pad-start byte, the zero run, and the pad-end byte.
    /// </summary>
    /// <param name="tr">The public-key hash bytes.</param>
    /// <param name="message">The bound message bytes.</param>
    /// <returns>The padded sponge input, a whole number of blocks.</returns>
    /// <exception cref="InvalidOperationException">When the padding does not close a block (the reference's <c>check</c>).</exception>
    public List<LongfellowBitWire[]> PrepareMuInput(LongfellowBitWire[][] tr, ReadOnlySpan<LongfellowBitWire[]> message)
    {
        ArgumentNullException.ThrowIfNull(tr);

        var inputBytes = new List<LongfellowBitWire[]>(tr.Length + message.Length + 2);
        for(int i = 0; i < tr.Length; i++)
        {
            inputBytes.Add(tr[i]);
        }

        for(int i = 0; i < message.Length; i++)
        {
            inputBytes.Add(message[i]);
        }

        int originalLength = inputBytes.Count;
        int paddingLength = Rate - (originalLength % Rate);

        if(paddingLength == 1)
        {
            inputBytes.Add(logic.BitVector(LongfellowLogic.BitWidth8, ShakePadSingle));
        }
        else
        {
            inputBytes.Add(logic.BitVector(LongfellowLogic.BitWidth8, ShakePadFirst));

            for(int i = 0; i < paddingLength - 2; i++)
            {
                inputBytes.Add(logic.BitVector(LongfellowLogic.BitWidth8, 0));
            }

            inputBytes.Add(logic.BitVector(LongfellowLogic.BitWidth8, PadLast));
        }

        if(inputBytes.Count % Rate != 0)
        {
            throw new InvalidOperationException("Padding failed.");
        }

        return inputBytes;
    }


    /// <summary>
    /// The reference's <c>assert_mu</c>: a manual sponge over the pre-padded message representative
    /// input — zero state, per-block XOR-in and witnessed permutation, then a 64-byte squeeze
    /// asserted bit for bit against the claimed <c>mu</c>.
    /// </summary>
    /// <param name="tr">The public-key hash bytes.</param>
    /// <param name="message">The bound message bytes.</param>
    /// <param name="muBlockWitnesses">One sponge witness per absorbed block.</param>
    /// <param name="mu">The claimed message representative.</param>
    /// <exception cref="InvalidOperationException">When the witnesses cannot cover the blocks (the reference's <c>check</c>).</exception>
    public void AssertMu(
        LongfellowBitWire[][] tr,
        ReadOnlySpan<LongfellowBitWire[]> message,
        IReadOnlyList<LongfellowSha3BlockWitnessWires> muBlockWitnesses,
        LongfellowBitWire[][] mu)
    {
        ArgumentNullException.ThrowIfNull(muBlockWitnesses);
        ArgumentNullException.ThrowIfNull(mu);

        var sha3 = new LongfellowSha3Circuit(logic, subfieldBitCount);
        var state = new LongfellowBitWire[GridSize][][];
        for(int x = 0; x < GridSize; x++)
        {
            state[x] = new LongfellowBitWire[GridSize][];
            for(int y = 0; y < GridSize; y++)
            {
                state[x][y] = logic.BitVector(LaneBits, 0);
            }
        }

        List<LongfellowBitWire[]> inputBytes = PrepareMuInput(tr, message);
        int blockCount = inputBytes.Count / Rate;

        int inputIndex = 0;
        int witnessIndex = 0;

        for(int block = 0; block < blockCount; block++)
        {
            int x = 0;
            int y = 0;
            for(int i = 0; i < Rate; i += 8)
            {
                var lane = new LongfellowBitWire[LaneBits];
                for(int b = 0; b < 8; b++)
                {
                    for(int j = 0; j < LongfellowLogic.BitWidth8; j++)
                    {
                        if(i + b < Rate)
                        {
                            lane[(b * 8) + j] = inputBytes[inputIndex + i + b][j];
                        }
                    }
                }

                state[x][y] = logic.Xor(state[x][y], lane);
                x++;
                if(x == GridSize)
                {
                    y++;
                    x = 0;
                }
            }

            inputIndex += Rate;

            if(witnessIndex >= muBlockWitnesses.Count)
            {
                throw new InvalidOperationException("Not enough block witnesses for mu.");
            }

            sha3.KeccakF1600(state, muBlockWitnesses[witnessIndex++]);
        }

        var squeezed = new LongfellowBitWire[mu.Length][];
        int squeezeX = 0;
        int squeezeY = 0;
        for(int i = 0; i < mu.Length; i += 8)
        {
            for(int b = 0; b < 8; b++)
            {
                var squeezedByte = new LongfellowBitWire[LongfellowLogic.BitWidth8];
                for(int j = 0; j < LongfellowLogic.BitWidth8; j++)
                {
                    squeezedByte[j] = state[squeezeX][squeezeY][(b * 8) + j];
                }

                squeezed[i + b] = squeezedByte;
            }

            squeezeX++;
            if(squeezeX == GridSize)
            {
                squeezeY++;
                squeezeX = 0;
            }
        }

        for(int i = 0; i < mu.Length; i++)
        {
            for(int b = 0; b < LongfellowLogic.BitWidth8; b++)
            {
                _ = logic.AssertEqual(squeezed[i][b], mu[i][b]);
            }
        }
    }


    /// <summary>
    /// The reference's <c>assert_w_prime_approx</c>: binds the NTT-domain witness values to their
    /// coefficient-domain inputs, computes <c>A·ẑ − ĉ∘t̂1</c>, and binds its inverse transform to
    /// the claimed approximation.
    /// </summary>
    /// <param name="publicKey">The public-key wires.</param>
    /// <param name="signature">The signature wires.</param>
    /// <param name="witness">The witness wires.</param>
    public void AssertWPrimeApprox(LongfellowMlDsaPublicKeyWires publicKey, LongfellowMlDsaSignatureWires signature, LongfellowMlDsaWitnessWires witness)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(witness);

        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            AssertNtt(signature.Z[i], witness.NttZ[i]);
        }

        AssertNtt(witness.Challenge, witness.NttC);

        LongfellowMlDsaPolynomialWires[] az = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.RowCount);
        LongfellowMlDsaPolynomialWires[] ct1 = LongfellowMlDsaPublicKeyWires.NewPolynomials(parameters.RowCount);
        MatrixVectorMultiply(publicKey.MatrixA, witness.NttZ, az);
        ScalarVectorMultiply(witness.NttC, publicKey.NttT1, ct1);

        for(int i = 0; i < parameters.RowCount; i++)
        {
            var difference = new LongfellowMlDsaPolynomialWires();
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                difference.Coefficients[k] = backend.Sub(az[i].Coefficients[k], ct1[i].Coefficients[k]);
            }

            AssertInverseNtt(difference, witness.WPrimeApprox[i]);
        }
    }


    /// <summary>
    /// The reference's <c>assert_ctilde</c>: asserts the SHAKE256 hash of the message
    /// representative and the packed high bits equals the signature's commitment hash.
    /// </summary>
    /// <param name="mu">The message representative bytes.</param>
    /// <param name="w1TildeBytes">The packed high-bits bytes.</param>
    /// <param name="commitmentBlockWitnesses">The sponge witnesses.</param>
    /// <param name="commitmentHash">The signature's commitment hash bytes.</param>
    public void AssertCtilde(
        LongfellowBitWire[][] mu,
        LongfellowBitWire[][] w1TildeBytes,
        LongfellowSha3BlockWitnessWires[] commitmentBlockWitnesses,
        LongfellowBitWire[][] commitmentHash)
    {
        ArgumentNullException.ThrowIfNull(mu);
        ArgumentNullException.ThrowIfNull(w1TildeBytes);
        ArgumentNullException.ThrowIfNull(commitmentBlockWitnesses);
        ArgumentNullException.ThrowIfNull(commitmentHash);

        var sha3 = new LongfellowSha3Circuit(logic, subfieldBitCount);

        var inputBytes = new LongfellowBitWire[mu.Length + w1TildeBytes.Length][];
        mu.CopyTo(inputBytes, 0);
        w1TildeBytes.CopyTo(inputBytes, mu.Length);

        LongfellowBitWire[][] squeezed = sha3.AssertShake256(inputBytes, parameters.CommitmentBytes, commitmentBlockWitnesses);

        for(int i = 0; i < parameters.CommitmentBytes; i++)
        {
            logic.AssertEqual(squeezed[i], commitmentHash[i]);
        }
    }


    /// <summary>
    /// The reference's <c>assert_valid_signature_on_mu</c>: the full verification relation —
    /// challenge reconstruction, the NTT-domain commitment recomputation, the hinted rounding, the
    /// high-bits packing, the response norm bound, and the commitment hash binding.
    /// </summary>
    /// <param name="publicKey">The public-key wires.</param>
    /// <param name="signature">The signature wires.</param>
    /// <param name="mu">The message representative bytes.</param>
    /// <param name="witness">The witness wires.</param>
    public void AssertValidSignatureOnMu(
        LongfellowMlDsaPublicKeyWires publicKey,
        LongfellowMlDsaSignatureWires signature,
        LongfellowBitWire[][] mu,
        LongfellowMlDsaWitnessWires witness)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(mu);
        ArgumentNullException.ThrowIfNull(witness);

        AssertSampleInBall(signature.CommitmentHash, witness.Challenge, witness.SampleInBall);

        AssertWPrimeApprox(publicKey, signature, witness);

        AssertUseHint(
            signature.Hints,
            witness.WPrimeApprox,
            witness.W1,
            witness.W1Bits,
            witness.HintAuxBits,
            witness.WPrime1,
            witness.WPrime1Bits,
            witness.HintSumBits);

        AssertW1Encode(witness.WPrime1Bits, witness.W1Tilde);

        AssertInfinityNorm(signature.Z, signature.ZBits, parameters.MaskingBound - parameters.RejectionBound);

        AssertCtilde(mu, witness.W1Tilde, witness.CommitmentBlockWitnesses, signature.CommitmentHash);
    }
}
