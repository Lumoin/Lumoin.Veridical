using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The dimensions and row layout of a Ligero tableau, derived from the witness
/// count, quadratic-constraint count, inverse code rate and number of opened
/// columns. Follows the layout of "Ligero: Lightweight Sublinear Arguments
/// Without a Trusted Setup" (Ames, Hazay, Ishai, Venkitasubramaniam, IACR
/// ePrint 2022/1608) — structural reference only, no code dependency.
/// </summary>
/// <remarks>
/// <para>
/// A tableau is a <see cref="RowCount"/> × <see cref="BlockEncoded"/> matrix of
/// field elements. Each row's first <see cref="Block"/> (or, for the IDOT/IQUAD
/// blinding rows, <see cref="DoubleBlock"/>) entries are an RS message; the row
/// is the systematic codeword extending those evaluations to
/// <see cref="BlockEncoded"/>. The columns <c>[DoubleBlock, BlockEncoded)</c> —
/// <see cref="BlockExtension"/> of them — are the Merkle-committed leaves, and
/// <see cref="OpenedColumnCount"/> of those are opened on challenge.
/// </para>
/// <para>
/// The block is parameterized directly (rather than back-solved from a target
/// proof size as the reference's deprecated constructor does): given
/// <c>block</c>, <c>inverseRate</c> and <c>nreq</c> with
/// <c>block ≥ 2·nreq</c>, the derived sizes are
/// <c>r = nreq</c>, <c>w = block − r</c>, <c>dblock = 2·block − 1</c>,
/// <c>blockExt = inverseRate·block</c> and
/// <c>blockEnc = dblock + blockExt = (2 + inverseRate)·block − 1</c>, the last
/// chosen so that <c>(blockEnc + 1) / (2 + inverseRate) = block</c> exactly.
/// The condition <c>block ≥ 2·nreq</c> gives <c>w ≥ r</c> (a witness block at
/// least half full), as Ligero requires for reasonable space use.
/// </para>
/// </remarks>
public sealed class LigeroParameters
{
    //The blinding rows and the first witness row sit at fixed positions in
    //every Ligero tableau — they are protocol invariants, not per-instance
    //layout. Only the rows below the witness block (the quadratic rows) move
    //with the witness count, so only those are instance-computed.

    /// <summary>The low-degree-test blinding row index (<c>ILDT = 0</c>).</summary>
    public const int LowDegreeRowIndex = 0;

    /// <summary>The dot-product (linear) test blinding row index (<c>IDOT = 1</c>).</summary>
    public const int DotRowIndex = 1;

    /// <summary>The quadratic test blinding row index (<c>IQUAD = 2</c>).</summary>
    public const int QuadraticRowIndex = 2;

    /// <summary>The first witness row index (<c>IW = 3</c>, just past the three blinding rows).</summary>
    public const int FirstWitnessRowIndex = 3;

    /// <summary>The total number of witnesses (<c>nw</c>).</summary>
    public int WitnessCount { get; }

    /// <summary>The total number of quadratic constraints <c>W[x]·W[y] = W[z]</c> (<c>nq</c>).</summary>
    public int QuadraticConstraintCount { get; }

    /// <summary>The inverse rate of the Reed–Solomon code (<c>rateinv</c>); at least 1.</summary>
    public int InverseRate { get; }

    /// <summary>The number of columns opened on challenge (<c>nreq</c>); the soundness query count.</summary>
    public int OpenedColumnCount { get; }

    /// <summary>The block size <c>BLOCK</c> — the RS message length of a witness row.</summary>
    public int Block { get; }

    /// <summary>The number of random blinding entries in a block (<c>r = nreq</c>).</summary>
    public int RandomCount { get; }

    /// <summary>The number of witness entries in a block (<c>w = block − r</c>).</summary>
    public int WitnessPerRow { get; }

    /// <summary><c>DBLOCK = 2·block − 1</c>: the degree bound of a product of two block-degree polynomials.</summary>
    public int DoubleBlock { get; }

    /// <summary><c>BLOCK_EXT = blockEnc − dblock = inverseRate·block</c>: the number of Merkle leaves (extension columns).</summary>
    public int BlockExtension { get; }

    /// <summary><c>BLOCK_ENC</c>: the total number of elements per row.</summary>
    public int BlockEncoded { get; }

    /// <summary>The number of witness rows (<c>nwrow = ceil(nw / w)</c>).</summary>
    public int WitnessRowCount { get; }

    /// <summary>The number of quadratic-constraint row triples (<c>nqtriples = ceil(nq / w)</c>).</summary>
    public int QuadraticTripleCount { get; }

    /// <summary>The number of witness-and-quadratic rows (<c>nwqrow = nwrow + 3·nqtriples</c>).</summary>
    public int WitnessQuadraticRowCount { get; }

    /// <summary>The total number of rows (<c>nrow = nwqrow + 3 blinding rows</c>).</summary>
    public int RowCount { get; }

    /// <summary>The first quadratic row index (<c>IQ = FirstWitnessRowIndex + nwrow</c>).</summary>
    public int FirstQuadraticRowIndex => FirstWitnessRowIndex + WitnessRowCount;

    /// <summary>The first quadratic <c>x</c>-operand row (= <see cref="FirstQuadraticRowIndex"/>).</summary>
    public int FirstQuadraticXRowIndex => FirstQuadraticRowIndex;

    /// <summary>The first quadratic <c>y</c>-operand row.</summary>
    public int FirstQuadraticYRowIndex => FirstQuadraticRowIndex + QuadraticTripleCount;

    /// <summary>The first quadratic <c>z</c>-product row.</summary>
    public int FirstQuadraticZRowIndex => FirstQuadraticRowIndex + (2 * QuadraticTripleCount);


    /// <summary>
    /// Derives the layout from the user parameters and the block size.
    /// </summary>
    /// <param name="witnessCount">The number of witnesses (≥ 0).</param>
    /// <param name="quadraticConstraintCount">The number of quadratic constraints (≥ 0).</param>
    /// <param name="inverseRate">The inverse code rate (≥ 1).</param>
    /// <param name="openedColumnCount">The number of opened columns (≥ 1).</param>
    /// <param name="block">The block size; must be at least <c>2 · openedColumnCount</c>.</param>
    /// <exception cref="ArgumentOutOfRangeException">When a parameter is out of range.</exception>
    public LigeroParameters(int witnessCount, int quadraticConstraintCount, int inverseRate, int openedColumnCount, int block)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(witnessCount);
        ArgumentOutOfRangeException.ThrowIfNegative(quadraticConstraintCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(inverseRate, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(openedColumnCount, 1);

        //block >= 2·nreq is the W >= R condition (w = block − nreq >= nreq).
        ArgumentOutOfRangeException.ThrowIfLessThan(block, 2 * openedColumnCount);

        WitnessCount = witnessCount;
        QuadraticConstraintCount = quadraticConstraintCount;
        InverseRate = inverseRate;
        OpenedColumnCount = openedColumnCount;

        Block = block;
        RandomCount = openedColumnCount;
        WitnessPerRow = block - openedColumnCount;
        DoubleBlock = (2 * block) - 1;
        BlockExtension = inverseRate * block;
        BlockEncoded = DoubleBlock + BlockExtension;

        WitnessRowCount = CeilingDivide(witnessCount, WitnessPerRow);
        QuadraticTripleCount = CeilingDivide(quadraticConstraintCount, WitnessPerRow);
        WitnessQuadraticRowCount = WitnessRowCount + (3 * QuadraticTripleCount);
        RowCount = WitnessQuadraticRowCount + 3;

        //The opened columns are drawn from the BlockExtension Merkle leaves.
        if(OpenedColumnCount > BlockExtension)
        {
            throw new ArgumentOutOfRangeException(nameof(openedColumnCount), $"Opened columns ({OpenedColumnCount}) cannot exceed the {BlockExtension} extension columns.");
        }

        //Structural invariant: the quadratic rows fill out the row count exactly.
        if(RowCount != FirstQuadraticRowIndex + (3 * QuadraticTripleCount))
        {
            throw new InvalidOperationException("Ligero row layout is inconsistent.");
        }
    }


    private static int CeilingDivide(int numerator, int denominator) => (numerator + denominator - 1) / denominator;
}
