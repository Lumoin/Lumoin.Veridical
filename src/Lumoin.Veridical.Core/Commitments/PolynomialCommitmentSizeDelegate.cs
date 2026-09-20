namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Returns the serialized byte length of the commitment this scheme produces for
/// a polynomial in <paramref name="variableCount"/> variables, without committing
/// anything. The companion to <see cref="PolynomialOpeningSizeDelegate"/>: a
/// composing protocol whose proof is a fixed-layout buffer needs the commitment
/// section's length at parse time from dimensions alone, exactly as it needs the
/// opening sections' lengths.
/// </summary>
/// <remarks>
/// <para>
/// This describes what <see cref="PolynomialCommitmentProvider.Commit"/> emits,
/// not what any other commitment on the provider emits. Where a scheme commits a
/// weight vector separately through
/// <see cref="PolynomialCommitmentProvider.CommitVector"/>, that commitment has
/// its own shape and is not what this reports: the Pedersen-family vector
/// commitment is a single group element regardless of the vector's length, while
/// the evaluation commitment covering the same polynomial is one group element
/// per row.
/// </para>
/// <para>
/// Without this a consumer must supply the length itself, which means knowing
/// both the scheme and how that provider was configured. The families answer
/// differently: a hash-tree commitment is one Merkle root, whose width is the
/// node width the scheme leaf-commits to and therefore the digest size the
/// provider was built with, while a Pedersen-family evaluation commitment is a
/// row of compressed points the variable count fixes. A consumer that reaches
/// for either figure directly is right only for the family it guessed.
/// </para>
/// <para>
/// The length must be a pure function of the variable count and the parameters
/// the provider was built with. Both scheme families satisfy this: a hash-tree
/// commitment is one root, constant in the variable count, and a Pedersen row
/// commitment is <c>2^⌈n/2⌉</c> compressed points, which the variable count fixes.
/// A scheme whose commitment length varies with the committed values or any
/// randomness cannot supply this and leaves it <see langword="null"/>.
/// </para>
/// </remarks>
/// <param name="variableCount">The committed polynomial's variable count.</param>
/// <returns>The commitment's serialized byte length.</returns>
public delegate int PolynomialCommitmentSizeDelegate(int variableCount);
