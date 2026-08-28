namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Returns the serialized byte length of the evaluation opening this scheme
/// produces for a polynomial in <paramref name="variableCount"/> variables,
/// without committing or opening anything. A composing protocol whose proof is
/// a fixed-layout buffer needs each section's length before it has the section,
/// and needs the same length again at parse time from dimensions alone.
/// </summary>
/// <remarks>
/// <para>
/// This exists so a consumer can size a scheme's openings without knowing which
/// scheme it is. The alternative — reading a bag of scheme-specific figures off
/// the provider and reassembling the arithmetic at the call site — forces every
/// consumer to learn every scheme, and silently produces wrong offsets for a
/// scheme whose length is not a function of those particular figures. WHIR is
/// exactly that case: its query count varies per round, so no single repetition
/// count describes it, and its length additionally depends on the folding
/// parameter, the soundness target and the regime.
/// </para>
/// <para>
/// The length must be a pure function of the variable count and the parameters
/// the provider was built with. A scheme whose opening length varies with the
/// committed values, the evaluation point, or any randomness cannot supply this
/// and leaves it <see langword="null"/>.
/// </para>
/// </remarks>
/// <param name="variableCount">The committed polynomial's variable count.</param>
/// <returns>The opening's serialized byte length.</returns>
public delegate int PolynomialOpeningSizeDelegate(int variableCount);
