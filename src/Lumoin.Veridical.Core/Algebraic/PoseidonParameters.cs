using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The public parameter set of a Poseidon permutation (Grassi, Khovratovich,
/// Rechberger, Roy, Schofnegger, USENIX Security 2021) over a curve's scalar
/// field: the state width <c>t</c>, the full/partial round counts, the round
/// constants, and the MDS matrix. Every value is public protocol shape
/// (Poseidon has no secret parameters), carried as canonical big-endian
/// scalars.
/// </summary>
/// <remarks>
/// This container is the convention seam: the permutation consumes any
/// well-formed parameter set, and <see cref="PoseidonParameterGenerator"/>
/// is one producer (the circomlib-compatible Grain procedure, the only one
/// with in-repo ground truth). Another ecosystem's convention — a fixed
/// Cauchy matrix, the security-checked resampling of the updated reference
/// script, pasted constant tables — enters through the public constructor
/// without touching the generator, and every evaluation path stays the
/// single tested one.
/// </remarks>
public sealed class PoseidonParameters
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly byte[] roundConstants;
    private readonly byte[] mdsMatrix;


    /// <summary>The state width <c>t</c> (field elements per state).</summary>
    public int StateWidth { get; }

    /// <summary>The number of full rounds <c>R_F</c> (S-box on every lane), split evenly before and after the partial rounds.</summary>
    public int FullRounds { get; }

    /// <summary>The number of partial rounds <c>R_P</c> (S-box on lane 0 only).</summary>
    public int PartialRounds { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>
    /// Constructs a parameter set from externally produced values. The spans
    /// are copied; the instance is immutable.
    /// </summary>
    /// <param name="stateWidth">The state width <c>t</c>; at least 2.</param>
    /// <param name="fullRounds">The full round count <c>R_F</c>; positive and even.</param>
    /// <param name="partialRounds">The partial round count <c>R_P</c>; positive.</param>
    /// <param name="roundConstants">The <c>(R_F + R_P) · t</c> round constants, concatenated canonical scalars in round-major lane order.</param>
    /// <param name="mdsMatrix">The <c>t × t</c> MDS matrix, concatenated canonical scalars in row-major order.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the declared shape.</exception>
    public PoseidonParameters(
        int stateWidth,
        int fullRounds,
        int partialRounds,
        ReadOnlySpan<byte> roundConstants,
        ReadOnlySpan<byte> mdsMatrix,
        CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(stateWidth, 2);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fullRounds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(partialRounds);
        if((fullRounds & 1) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(fullRounds), "The full rounds split evenly around the partial rounds; the count must be even.");
        }

        int expectedConstantBytes = (fullRounds + partialRounds) * stateWidth * ScalarSize;
        if(roundConstants.Length != expectedConstantBytes)
        {
            throw new ArgumentException($"The round constants must be exactly {expectedConstantBytes} bytes for the declared shape; received {roundConstants.Length}.", nameof(roundConstants));
        }

        int expectedMdsBytes = stateWidth * stateWidth * ScalarSize;
        if(mdsMatrix.Length != expectedMdsBytes)
        {
            throw new ArgumentException($"The MDS matrix must be exactly {expectedMdsBytes} bytes for the declared shape; received {mdsMatrix.Length}.", nameof(mdsMatrix));
        }

        StateWidth = stateWidth;
        FullRounds = fullRounds;
        PartialRounds = partialRounds;
        this.roundConstants = roundConstants.ToArray();
        this.mdsMatrix = mdsMatrix.ToArray();
        Curve = curve;
    }


    /// <summary>Returns the round constant for <paramref name="round"/> (zero-based, over all <c>R_F + R_P</c> rounds) and state lane <paramref name="lane"/>.</summary>
    public ReadOnlySpan<byte> GetRoundConstant(int round, int lane) =>
        roundConstants.AsSpan(((round * StateWidth) + lane) * ScalarSize, ScalarSize);


    /// <summary>
    /// Returns the MDS matrix entry <c>M[row][column]</c>. The matrix is
    /// whatever the producer constructed (the Grain generator's Cauchy points
    /// are stream-sampled, so the matrix is NOT symmetric); the permutation
    /// applies it as <c>new[i] = Σ_j M[i][j] · state[j]</c>, and the
    /// orientation is pinned by the known-answer tests.
    /// </summary>
    public ReadOnlySpan<byte> GetMdsEntry(int row, int column) =>
        mdsMatrix.AsSpan(((row * StateWidth) + column) * ScalarSize, ScalarSize);
}
