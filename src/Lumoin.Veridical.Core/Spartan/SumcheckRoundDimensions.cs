namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Carries the shape of a <see cref="SumcheckRound"/>: which round of the
/// protocol it represents and the algebraic degree of its round
/// polynomial.
/// </summary>
/// <param name="RoundIndex">The zero-based round index.</param>
/// <param name="Degree">The algebraic degree of the round polynomial; at least 2 for a Spartan sumcheck round.</param>
/// <remarks>
/// Surfaced as a value in the round's <see cref="Tag"/> so consumers
/// can read the shape without unwrapping the leaf type. The degree
/// is constant across all rounds of one sumcheck run.
/// </remarks>
public readonly record struct SumcheckRoundDimensions(int RoundIndex, int Degree);