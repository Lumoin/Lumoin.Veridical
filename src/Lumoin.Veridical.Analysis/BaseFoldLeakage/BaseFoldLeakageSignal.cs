namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// The outcome of a BaseFold leakage experiment: whether witness information was
/// found to leak through the proof.
/// </summary>
public enum BaseFoldLeakageSignal
{
    /// <summary>
    /// No leakage detected at the tested scale. This is not a proof of
    /// zero-knowledge — only that this particular, deliberately simple
    /// investigation did not surface a signal. A more sophisticated attack might.
    /// </summary>
    NotDetected = 0,

    /// <summary>
    /// Leakage detected empirically: the statistical test rejected the
    /// no-leakage null, or the classifier predicted a witness property from the
    /// proof materially above chance.
    /// </summary>
    Detected = 1,

    /// <summary>
    /// Leakage is structurally certain, independent of any statistical detection:
    /// the proof contains a commitment that is a deterministic function of the
    /// witness, so a candidate witness can be confirmed by recomputation. This is
    /// the definitive sense in which BaseFold is binding but not hiding.
    /// </summary>
    StructurallyCertain = 2
}
