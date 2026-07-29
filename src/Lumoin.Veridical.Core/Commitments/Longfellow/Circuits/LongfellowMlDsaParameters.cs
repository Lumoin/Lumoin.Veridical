namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// One ML-DSA parameter set, a faithful port of the reference's <c>MLDsaParams</c> template
/// (<c>ml_dsa_shared.h</c>): the FIPS 204 Section 4 Table 1 values the circuit, the witness
/// generator and the host reference share, with the reference's derived quantities computed the
/// same way.
/// </summary>
/// <remarks>
/// The two wired sets are <see cref="MlDsa44"/> and <see cref="MlDsa65"/>. The shared constants
/// (<see cref="Modulus"/>, <see cref="CoefficientCount"/>, <see cref="DroppedBits"/>) live here as
/// constants because every parameter set shares them, exactly as the reference keeps them at
/// namespace scope.
/// </remarks>
internal sealed class LongfellowMlDsaParameters
{
    /// <summary>The FIPS 204 prime <c>q = 2^23 − 2^13 + 1</c> (the reference's <c>Q</c>).</summary>
    public const uint Modulus = 8380417;

    /// <summary>The polynomial degree bound (the reference's <c>N</c>).</summary>
    public const int CoefficientCount = 256;

    /// <summary>The number of dropped bits in the public key's rounding (FIPS 204's <c>d</c>, the reference's <c>D</c>).</summary>
    public const int DroppedBits = 13;

    /// <summary>The inverse-NTT normalizer <c>256^{-1} mod q</c> the reference multiplies by after the Gentleman-Sande butterflies.</summary>
    public const uint InverseTransformScale = 8347681;

    /// <summary>The matrix A's row count (the reference's <c>K</c>).</summary>
    public int RowCount { get; }

    /// <summary>The matrix A's column count (the reference's <c>L</c>).</summary>
    public int ColumnCount { get; }

    /// <summary>The challenge polynomial's nonzero-coefficient count (FIPS 204's <c>τ</c>).</summary>
    public int ChallengeWeight { get; }

    /// <summary>The hint vector's maximum one count (FIPS 204's <c>ω</c>).</summary>
    public int HintWeightBound { get; }

    /// <summary>The hash commitment's byte count (the reference's <c>c_tilde_bytes</c>, two lambda bits).</summary>
    public int CommitmentBytes { get; }

    /// <summary>The masking vector's coefficient range (FIPS 204's <c>γ1</c>).</summary>
    public uint MaskingBound { get; }

    /// <summary>The low-order rounding range (FIPS 204's <c>γ2</c>).</summary>
    public uint RoundingRange { get; }

    /// <summary>The rejection bound <c>τ·η</c> (FIPS 204's <c>β</c>).</summary>
    public uint RejectionBound { get; }

    /// <summary>The circuit's bit width for a shifted response coefficient (the reference's <c>z_bits</c>).</summary>
    public int ResponseBitWidth { get; }

    /// <summary>The bit width of one hinted high-bits coefficient (the reference's <c>r1_bits</c>).</summary>
    public int HighBitsWidth { get; }

    /// <summary>The byte count one packed high-bits polynomial encodes into (the reference's <c>w1_bytes</c>).</summary>
    public int HighBitsBytes { get; }

    /// <summary>The packing width of one signature response coefficient (the reference's derived <c>z_coeff_bits = bitlen(2·γ1 − 1)</c>).</summary>
    public int ResponseCoefficientBits { get; }

    /// <summary>The bit width of one shifted low-bits remainder (the reference's derived <c>r0_bits</c>).</summary>
    public int LowBitsWidth { get; }

    /// <summary>The hinted high-bits modulus <c>(q − 1) / (2·γ2)</c> (the reference's derived <c>M</c>).</summary>
    public uint HintModulus { get; }

    /// <summary>The bit width of the hint-weight sum (the circuit's <c>kOmegaBits = bit_width(ω)</c>).</summary>
    public int HintWeightBitWidth { get; }

    /// <summary>The ML-DSA-44 parameter set (FIPS 204 Section 4 Table 1).</summary>
    public static LongfellowMlDsaParameters MlDsa44 { get; } = new(
        rowCount: 4,
        columnCount: 4,
        challengeWeight: 39,
        hintWeightBound: 80,
        commitmentBytes: 32,
        maskingBound: 131072,
        roundingRange: 95232,
        rejectionBound: 78,
        responseBitWidth: 19,
        highBitsWidth: 6,
        highBitsBytes: 192);

    /// <summary>The ML-DSA-65 parameter set (FIPS 204 Section 4 Table 1).</summary>
    public static LongfellowMlDsaParameters MlDsa65 { get; } = new(
        rowCount: 6,
        columnCount: 5,
        challengeWeight: 49,
        hintWeightBound: 55,
        commitmentBytes: 48,
        maskingBound: 524288,
        roundingRange: 261888,
        rejectionBound: 196,
        responseBitWidth: 20,
        highBitsWidth: 4,
        highBitsBytes: 128);


    /// <summary>
    /// Constructs a parameter set and computes the reference's derived quantities.
    /// </summary>
    /// <param name="rowCount">The matrix A's row count.</param>
    /// <param name="columnCount">The matrix A's column count.</param>
    /// <param name="challengeWeight">The challenge polynomial's nonzero-coefficient count.</param>
    /// <param name="hintWeightBound">The hint vector's maximum one count.</param>
    /// <param name="commitmentBytes">The hash commitment's byte count.</param>
    /// <param name="maskingBound">The masking vector's coefficient range.</param>
    /// <param name="roundingRange">The low-order rounding range.</param>
    /// <param name="rejectionBound">The rejection bound.</param>
    /// <param name="responseBitWidth">The circuit's bit width for a shifted response coefficient.</param>
    /// <param name="highBitsWidth">The bit width of one hinted high-bits coefficient.</param>
    /// <param name="highBitsBytes">The byte count one packed high-bits polynomial encodes into.</param>
    private LongfellowMlDsaParameters(
        int rowCount,
        int columnCount,
        int challengeWeight,
        int hintWeightBound,
        int commitmentBytes,
        uint maskingBound,
        uint roundingRange,
        uint rejectionBound,
        int responseBitWidth,
        int highBitsWidth,
        int highBitsBytes)
    {
        const uint MlDsa44RoundingRange = 95232;
        const int MlDsa44LowBitsWidth = 18;
        const int OtherLowBitsWidth = 19;

        RowCount = rowCount;
        ColumnCount = columnCount;
        ChallengeWeight = challengeWeight;
        HintWeightBound = hintWeightBound;
        CommitmentBytes = commitmentBytes;
        MaskingBound = maskingBound;
        RoundingRange = roundingRange;
        RejectionBound = rejectionBound;
        ResponseBitWidth = responseBitWidth;
        HighBitsWidth = highBitsWidth;
        HighBitsBytes = highBitsBytes;
        ResponseCoefficientBits = BitLength((2UL * maskingBound) - 1UL);
        LowBitsWidth = roundingRange == MlDsa44RoundingRange ? MlDsa44LowBitsWidth : OtherLowBitsWidth;
        HintModulus = (Modulus - 1) / (2 * roundingRange);
        HintWeightBitWidth = BitLength((ulong)hintWeightBound);
    }


    /// <summary>The reference's <c>bitlen</c>/<c>bit_width</c>: the position of the highest set bit plus one, and zero for zero.</summary>
    /// <param name="value">The value to measure.</param>
    /// <returns>The bit length.</returns>
    public static int BitLength(ulong value)
    {
        int length = 0;
        while(value != 0)
        {
            length++;
            value >>= 1;
        }

        return length;
    }
}
