using System;
using System.Collections.Generic;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The out-of-circuit ML-DSA witness generator, a faithful port of the reference's
/// <c>ml_dsa_witness</c> (<c>ml_dsa_witness.h</c>): decodes the key and signature, reruns the FIPS
/// 204 verification computation, and records every intermediate value the circuit's witness wires
/// consume, in the exact order the wire bundles declare them.
/// </summary>
/// <remarks>
/// <see cref="Compute"/> returns <see langword="null"/> exactly where the reference's
/// <c>compute_witness</c> returns false: an oversized context, a malformed signature encoding, an
/// exhausted SampleInBall stream, or a recomputed commitment hash that does not match the
/// signature's. The reference marks its ML-DSA implementation as experimental research code that is
/// not vetted for production; this port carries the same status.
/// </remarks>
internal sealed class LongfellowMlDsaWitness
{
    /// <summary>The largest context byte count FIPS 204 admits.</summary>
    private const int ContextByteBound = 255;

    /// <summary>The domain-separator byte prefixed to the context-bound message.</summary>
    private const byte PureDomainSeparator = 0;

    /// <summary>The context-bound message's header width: the domain separator and the context length prefix.</summary>
    private const int BoundMessageHeaderBytes = 2;

    /// <summary>The parameter set this witness was computed for.</summary>
    public LongfellowMlDsaParameters Parameters { get; }

    /// <summary>The 64-byte public-key hash (the reference's <c>tr_</c>).</summary>
    public byte[] Tr { get; private set; } = [];

    /// <summary>The signature's hash commitment (the reference's <c>c_tilde_</c>).</summary>
    public byte[] CommitmentHash { get; private set; } = [];

    /// <summary>The 64-byte message representative <c>mu = H(tr || M', 64)</c> (the reference's <c>mu_</c>).</summary>
    public byte[] Mu { get; private set; } = [];

    /// <summary>The packed high-bits byte string (the reference's <c>w1_tilde_</c>).</summary>
    public byte[] W1Tilde { get; private set; } = [];

    /// <summary>The recomputed commitment hash (the reference's <c>c_prime_tilde_</c>).</summary>
    public byte[] RecomputedCommitmentHash { get; private set; } = [];

    /// <summary>The sponge witnesses of the recomputed commitment hash (the reference's <c>c_prime_tilde_bws_</c>).</summary>
    public IReadOnlyList<LongfellowSha3BlockWitness> CommitmentBlockWitnesses { get; private set; } = [];

    /// <summary>The shifted response-coefficient bit values (the reference's <c>z_bits_</c>), indexed column, coefficient.</summary>
    public ulong[][] ZBits { get; }

    /// <summary>The hint vector's total weight (the reference's <c>h_sum_bits_</c>).</summary>
    public ulong HintSum { get; private set; }

    /// <summary>The sponge witness of the SampleInBall hash (the reference's <c>shake_bws_</c>).</summary>
    public LongfellowSha3BlockWitness SampleInBallBlockWitness { get; private set; } = new();

    /// <summary>The accepted rejection samples (the reference's <c>j_vals_</c>).</summary>
    public byte[] JValues { get; }

    /// <summary>The stream index where each accepted sample was found (the reference's <c>j_k_indices_</c>).</summary>
    public ushort[] JIndices { get; }

    /// <summary>The Fisher-Yates position trace (the reference's <c>position_trace_</c>): step <c>s</c> holds <c>s + 1</c> positions.</summary>
    public byte[][] PositionTrace { get; }

    /// <summary>The challenge polynomial in the coefficient domain (the reference's <c>c_coeffs_</c>).</summary>
    public uint[] ChallengeCoefficients { get; private set; } = [];

    /// <summary>The response vector in the NTT domain (the reference's <c>nttz_</c>), indexed column, coefficient.</summary>
    public uint[][] NttZ { get; }

    /// <summary>The challenge polynomial in the NTT domain (the reference's <c>nttc_</c>).</summary>
    public uint[] NttC { get; private set; } = [];

    /// <summary>The scaled rounded vector in the NTT domain (the reference's <c>nttt1_</c>), indexed row, coefficient.</summary>
    public uint[][] NttT1 { get; }

    /// <summary>The approximate commitment recomputation (the reference's <c>w_prime_approx_</c>), indexed row, coefficient.</summary>
    public uint[][] WPrimeApprox { get; }

    /// <summary>The unhinted high bits (the reference's <c>w1_</c>), indexed row, coefficient.</summary>
    public int[][] W1 { get; }

    /// <summary>The interval-shift auxiliary bit values (the reference's <c>hint_aux_bits_</c>), indexed row, coefficient.</summary>
    public ulong[][] HintAuxBits { get; }

    /// <summary>The hinted high bits (the reference's <c>w_prime_1_</c>), indexed row, coefficient.</summary>
    public int[][] WPrime1 { get; }

    /// <summary>The hinted high bits as bit values (the reference's <c>w_prime_1_bits_</c>), indexed row, coefficient.</summary>
    public ulong[][] WPrime1Bits { get; }

    /// <summary>The unhinted high bits as bit values (the reference's <c>w1_bits_</c>), indexed row, coefficient.</summary>
    public ulong[][] W1Bits { get; }

    /// <summary>The matrix-expansion seed (the reference's <c>rho_</c>).</summary>
    public byte[] Rho { get; private set; } = [];

    /// <summary>The decoded public key (the reference's <c>ref_pk_</c>).</summary>
    public LongfellowMlDsaPublicKey PublicKey { get; private set; } = new([], [], []);

    /// <summary>The decoded signature (the reference's <c>ref_sig_</c>).</summary>
    public LongfellowMlDsaSignature Signature { get; private set; } = new([], [], []);

    /// <summary>The signed message (the reference's <c>msg_</c>).</summary>
    public byte[] Message { get; private set; } = [];


    /// <summary>Allocates the fixed-shape regions for a parameter set; <see cref="Compute"/> fills them.</summary>
    /// <param name="parameters">The parameter set.</param>
    private LongfellowMlDsaWitness(LongfellowMlDsaParameters parameters)
    {
        Parameters = parameters;
        ZBits = NewRows(parameters.ColumnCount);
        JValues = new byte[parameters.ChallengeWeight];
        JIndices = new ushort[parameters.ChallengeWeight];
        PositionTrace = new byte[parameters.ChallengeWeight][];
        for(int s = 0; s < parameters.ChallengeWeight; s++)
        {
            PositionTrace[s] = new byte[s + 1];
        }

        NttZ = NewPolynomialRows(parameters.ColumnCount);
        NttT1 = NewPolynomialRows(parameters.RowCount);
        WPrimeApprox = NewPolynomialRows(parameters.RowCount);
        W1 = NewSignedRows(parameters.RowCount);
        HintAuxBits = NewRows(parameters.RowCount);
        WPrime1 = NewSignedRows(parameters.RowCount);
        WPrime1Bits = NewRows(parameters.RowCount);
        W1Bits = NewRows(parameters.RowCount);
    }


    /// <summary>
    /// The reference's <c>SymmetricReduce</c>: reduces a difference into the symmetric interval
    /// <c>(−q/2, q/2]</c> of its residue class.
    /// </summary>
    /// <param name="delta">The difference to reduce.</param>
    /// <returns>The symmetric representative.</returns>
    public static long SymmetricReduce(long delta)
    {
        delta %= LongfellowMlDsaParameters.Modulus;
        if(delta > LongfellowMlDsaParameters.Modulus / 2)
        {
            delta -= LongfellowMlDsaParameters.Modulus;
        }

        return delta;
    }


    /// <summary>
    /// The reference's <c>compute_witness</c>: decodes the inputs, reruns the FIPS 204 verification
    /// computation, and records every witness value.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="publicKey">The encoded public key.</param>
    /// <param name="signature">The encoded signature.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="context">The signing context, at most 255 bytes.</param>
    /// <returns>The computed witness, or <see langword="null"/> exactly where the reference returns false.</returns>
    public static LongfellowMlDsaWitness? Compute(
        LongfellowMlDsaParameters parameters,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> context)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if(context.Length > ContextByteBound)
        {
            return null;
        }

        var witness = new LongfellowMlDsaWitness(parameters);

        LongfellowMlDsaPublicKey decodedKey = LongfellowMlDsaReference.PublicKeyDecode(parameters, publicKey);
        witness.PublicKey = decodedKey;
        witness.Rho = publicKey[..32].ToArray();
        witness.Tr = decodedKey.Tr;

        LongfellowMlDsaSignature? decodedSignature = LongfellowMlDsaReference.SignatureDecode(parameters, signature);
        if(decodedSignature is null)
        {
            return null;
        }

        witness.Signature = decodedSignature;
        witness.CommitmentHash = decodedSignature.CommitmentHash;
        witness.Message = message.ToArray();

        ulong hintSum = 0;
        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                if(decodedSignature.Hints[i][k])
                {
                    hintSum++;
                }
            }
        }

        witness.HintSum = hintSum;

        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            uint[] zRow = decodedSignature.Z[i];
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                int value = (int)zRow[j];
                if(value > (int)LongfellowMlDsaParameters.Modulus / 2)
                {
                    value -= (int)LongfellowMlDsaParameters.Modulus;
                }

                int bound = (int)(parameters.MaskingBound - parameters.RejectionBound);
                int shifted = value + bound - 1;
                witness.ZBits[i][j] = (ulong)shifted;
            }

            zRow.CopyTo(witness.NttZ[i], 0);
            LongfellowMlDsaReference.NumberTheoreticTransform(witness.NttZ[i]);
        }

        witness.ChallengeCoefficients = LongfellowMlDsaReference.SampleInBall(parameters, decodedSignature.CommitmentHash);
        witness.NttC = (uint[])witness.ChallengeCoefficients.Clone();
        LongfellowMlDsaReference.NumberTheoreticTransform(witness.NttC);

        IReadOnlyList<LongfellowSha3BlockWitness> shakeWitnesses = LongfellowSha3Witness.ComputeWitnessShake256(
            decodedSignature.CommitmentHash, LongfellowMlDsaReference.SampleInBallHashBytes);
        witness.SampleInBallBlockWitness = shakeWitnesses[0];

        Span<byte> sampleStream = stackalloc byte[LongfellowMlDsaReference.SampleInBallHashBytes];
        LongfellowSha3Witness.Shake256Hash(decodedSignature.CommitmentHash, sampleStream);

        int count = 0;
        int streamIndex = LongfellowMlDsaReference.SampleInBallStreamStart;
        for(int i = LongfellowMlDsaParameters.CoefficientCount - parameters.ChallengeWeight; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            byte j;
            do
            {
                //The reference documents the same small completeness error: when 136 bytes cannot
                //supply the samples, witness generation fails rather than resqueezing.
                if(streamIndex >= sampleStream.Length)
                {
                    return null;
                }

                j = sampleStream[streamIndex++];
            }
            while(j > i);

            witness.JValues[count] = j;
            witness.JIndices[count] = (ushort)(streamIndex - 1);
            count++;
        }

        var currentPositions = new List<byte>(parameters.ChallengeWeight);
        for(int s = 0; s < parameters.ChallengeWeight; s++)
        {
            byte j = witness.JValues[s];
            byte i = (byte)(LongfellowMlDsaParameters.CoefficientCount - parameters.ChallengeWeight + s);

            for(int p = 0; p < currentPositions.Count; p++)
            {
                if(currentPositions[p] == j)
                {
                    currentPositions[p] = i;

                    break;
                }
            }

            currentPositions.Add(j);
            for(int p = 0; p <= s; p++)
            {
                witness.PositionTrace[s][p] = currentPositions[p];
            }
        }

        uint scaleFactor = 1u << LongfellowMlDsaParameters.DroppedBits;
        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                witness.NttT1[i][j] = LongfellowMlDsaReference.MultiplyModQ(decodedKey.T1[i][j], scaleFactor);
            }

            LongfellowMlDsaReference.NumberTheoreticTransform(witness.NttT1[i]);
        }

        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                uint az = 0;
                for(int j = 0; j < parameters.ColumnCount; j++)
                {
                    az = LongfellowMlDsaReference.AddModQ(az, LongfellowMlDsaReference.MultiplyModQ(decodedKey.MatrixA[i][j][k], witness.NttZ[j][k]));
                }

                uint ct1 = LongfellowMlDsaReference.MultiplyModQ(witness.NttC[k], witness.NttT1[i][k]);
                witness.WPrimeApprox[i][k] = LongfellowMlDsaReference.SubtractModQ(az, ct1);
            }

            LongfellowMlDsaReference.InverseNumberTheoreticTransform(witness.WPrimeApprox[i]);
        }

        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                int value = (int)witness.WPrimeApprox[i][k];
                (int highPart, _) = LongfellowMlDsaReference.Decompose(parameters, value);

                bool hintBit = decodedSignature.Hints[i][k];
                witness.WPrime1[i][k] = (int)LongfellowMlDsaReference.UseHint(parameters, hintBit, value);
                witness.W1[i][k] = highPart;

                long gamma2 = parameters.RoundingRange;
                long delta = value - (highPart * 2L * gamma2);
                delta = SymmetricReduce(delta);

                ulong shiftedRemainder = (ulong)(delta + gamma2);
                ulong signBit = delta > 0 ? 0UL : 1UL;

                ulong auxBits = shiftedRemainder | (signBit << parameters.LowBitsWidth);
                witness.HintAuxBits[i][k] = NormalizeModQ((long)auxBits);

                witness.WPrime1Bits[i][k] = NormalizeModQ(witness.WPrime1[i][k]);
                witness.W1Bits[i][k] = NormalizeModQ(witness.W1[i][k]);
            }
        }

        var highBits = new uint[parameters.RowCount][];
        for(int i = 0; i < parameters.RowCount; i++)
        {
            highBits[i] = new uint[LongfellowMlDsaParameters.CoefficientCount];
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                highBits[i][j] = (uint)witness.WPrime1[i][j];
            }
        }

        witness.W1Tilde = LongfellowMlDsaReference.W1Encode(parameters, highBits);

        var muInput = new byte[witness.Tr.Length + BoundMessageHeaderBytes + context.Length + message.Length];
        int muCursor = 0;
        witness.Tr.CopyTo(muInput.AsSpan(muCursor));
        muCursor += witness.Tr.Length;
        muInput[muCursor++] = PureDomainSeparator;
        muInput[muCursor++] = (byte)context.Length;
        context.CopyTo(muInput.AsSpan(muCursor));
        muCursor += context.Length;
        message.CopyTo(muInput.AsSpan(muCursor));

        var mu = new byte[LongfellowMlDsaReference.PublicKeyHashBytes];
        LongfellowSha3Witness.Shake256Hash(muInput, mu);
        witness.Mu = mu;

        var commitmentInput = new byte[mu.Length + witness.W1Tilde.Length];
        mu.CopyTo(commitmentInput.AsSpan(0));
        witness.W1Tilde.CopyTo(commitmentInput.AsSpan(mu.Length));

        var recomputedCommitment = new byte[parameters.CommitmentBytes];
        LongfellowSha3Witness.Shake256Hash(commitmentInput, recomputedCommitment);
        witness.RecomputedCommitmentHash = recomputedCommitment;

        witness.CommitmentBlockWitnesses = LongfellowSha3Witness.ComputeWitnessShake256(commitmentInput, parameters.CommitmentBytes);

        if(!recomputedCommitment.AsSpan().SequenceEqual(witness.CommitmentHash))
        {
            return null;
        }

        return witness;
    }


    /// <summary>
    /// The reference's <c>fill_pk</c>: the public column region — the matrix, the scaled rounded
    /// vector in the NTT domain, and the public-key hash bits.
    /// </summary>
    /// <param name="field">The field bundle supplying the elements.</param>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor, advanced past the region.</param>
    public void FillPublicKey(LongfellowLogicFieldOperations field, Span<byte> destination, ref int cursor)
    {
        ArgumentNullException.ThrowIfNull(field);

        for(int i = 0; i < Parameters.RowCount; i++)
        {
            for(int j = 0; j < Parameters.ColumnCount; j++)
            {
                for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
                {
                    WriteElement(field, destination, ref cursor, PublicKey.MatrixA[i][j][k]);
                }
            }
        }

        for(int i = 0; i < Parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                WriteElement(field, destination, ref cursor, NttT1[i][k]);
            }
        }

        for(int i = 0; i < Tr.Length; i++)
        {
            WriteBits(field, destination, ref cursor, Tr[i], LongfellowLogic.BitWidth8);
        }
    }


    /// <summary>
    /// The reference's <c>fill_witness</c>: the full column — the public region, the signature
    /// region, and the private witness region, in the exact order the wire bundles declare them.
    /// </summary>
    /// <param name="field">The field bundle supplying the elements.</param>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor, advanced past the region.</param>
    public void FillWitness(LongfellowLogicFieldOperations field, Span<byte> destination, ref int cursor)
    {
        FillPublicKey(field, destination, ref cursor);

        for(int i = 0; i < Parameters.CommitmentBytes; i++)
        {
            WriteBits(field, destination, ref cursor, CommitmentHash[i], LongfellowLogic.BitWidth8);
        }

        for(int i = 0; i < Parameters.ColumnCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                WriteElement(field, destination, ref cursor, Signature.Z[i][k]);
            }
        }

        for(int i = 0; i < Parameters.ColumnCount; i++)
        {
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                WriteBits(field, destination, ref cursor, ZBits[i][j], Parameters.ResponseBitWidth);
            }
        }

        for(int i = 0; i < Parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                WriteElement(field, destination, ref cursor, Signature.Hints[i][k] ? 1UL : 0UL);
            }
        }

        for(int i = 0; i < Parameters.ChallengeWeight; i++)
        {
            WriteBits(field, destination, ref cursor, JValues[i], LongfellowLogic.BitWidth8);
            WriteBits(field, destination, ref cursor, JIndices[i], LongfellowLogic.BitWidth16);
        }

        LongfellowSha3Witness.FillWitness(field, [SampleInBallBlockWitness], destination, ref cursor);

        for(int s = 0; s < Parameters.ChallengeWeight; s++)
        {
            for(int k = 0; k <= s; k++)
            {
                WriteBits(field, destination, ref cursor, PositionTrace[s][k], LongfellowLogic.BitWidth8);
            }
        }

        for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
        {
            WriteElement(field, destination, ref cursor, ChallengeCoefficients[k]);
        }

        for(int i = 0; i < Parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                WriteElement(field, destination, ref cursor, WPrimeApprox[i][k]);
            }

            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                int value = W1[i][k];
                if(value < 0)
                {
                    value += (int)LongfellowMlDsaParameters.Modulus;
                }

                WriteElement(field, destination, ref cursor, (ulong)value);
            }

            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                WriteBits(field, destination, ref cursor, W1Bits[i][j], Parameters.HighBitsWidth);
            }

            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                WriteBits(field, destination, ref cursor, HintAuxBits[i][j], Parameters.LowBitsWidth + 1);
            }

            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                WriteElement(field, destination, ref cursor, (ulong)WPrime1[i][k]);
            }

            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                WriteBits(field, destination, ref cursor, WPrime1Bits[i][j], Parameters.HighBitsWidth);
            }
        }

        for(int i = 0; i < Parameters.ColumnCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                WriteElement(field, destination, ref cursor, NttZ[i][k]);
            }
        }

        for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
        {
            WriteElement(field, destination, ref cursor, NttC[k]);
        }

        for(int i = 0; i < W1Tilde.Length; i++)
        {
            WriteBits(field, destination, ref cursor, W1Tilde[i], LongfellowLogic.BitWidth8);
        }

        LongfellowSha3Witness.FillWitness(field, CommitmentBlockWitnesses, destination, ref cursor);

        WriteBits(field, destination, ref cursor, HintSum, Parameters.HintWeightBitWidth);
    }


    /// <summary>Writes one field element into the column at the cursor.</summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="value">The scalar to embed.</param>
    private static void WriteElement(LongfellowLogicFieldOperations field, Span<byte> destination, ref int cursor, ulong value)
    {
        field.OfScalar(value).Span.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
        cursor++;
    }


    /// <summary>Writes a value's bits into the column as bit elements, least significant first (the reference filler's <c>push_back(v, n, f)</c>).</summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="value">The value whose bits are written.</param>
    /// <param name="bitCount">The bit count.</param>
    private static void WriteBits(LongfellowLogicFieldOperations field, Span<byte> destination, ref int cursor, ulong value, int bitCount)
    {
        for(int bit = 0; bit < bitCount; bit++)
        {
            ReadOnlyMemory<byte> element = ((value >> bit) & 1UL) != 0UL ? field.Compiler.One : field.Compiler.Zero;
            element.Span.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
            cursor++;
        }
    }


    /// <summary>The reference's <c>normalize</c> lambda: reduces a signed value into the canonical range <c>[0, q)</c>.</summary>
    /// <param name="value">The value to reduce.</param>
    /// <returns>The canonical representative.</returns>
    private static ulong NormalizeModQ(long value)
    {
        long reduced = value % LongfellowMlDsaParameters.Modulus;
        if(reduced < 0)
        {
            reduced += LongfellowMlDsaParameters.Modulus;
        }

        return (ulong)reduced;
    }


    /// <summary>Allocates one 256-entry unsigned row per index.</summary>
    /// <param name="rowCount">The row count.</param>
    /// <returns>The rows.</returns>
    private static ulong[][] NewRows(int rowCount)
    {
        var rows = new ulong[rowCount][];
        for(int i = 0; i < rowCount; i++)
        {
            rows[i] = new ulong[LongfellowMlDsaParameters.CoefficientCount];
        }

        return rows;
    }


    /// <summary>Allocates one 256-entry polynomial per index.</summary>
    /// <param name="rowCount">The row count.</param>
    /// <returns>The polynomials.</returns>
    private static uint[][] NewPolynomialRows(int rowCount)
    {
        var rows = new uint[rowCount][];
        for(int i = 0; i < rowCount; i++)
        {
            rows[i] = new uint[LongfellowMlDsaParameters.CoefficientCount];
        }

        return rows;
    }


    /// <summary>Allocates one 256-entry signed row per index.</summary>
    /// <param name="rowCount">The row count.</param>
    /// <returns>The rows.</returns>
    private static int[][] NewSignedRows(int rowCount)
    {
        var rows = new int[rowCount][];
        for(int i = 0; i < rowCount; i++)
        {
            rows[i] = new int[LongfellowMlDsaParameters.CoefficientCount];
        }

        return rows;
    }
}
