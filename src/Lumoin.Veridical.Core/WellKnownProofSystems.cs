using System;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Well-known proof system identifiers and predicates.
/// </summary>
/// <remarks>
/// <para>
/// A proof system is the outer construction that produces and verifies proofs.
/// Proof systems are parameterised over a polynomial commitment scheme and
/// optionally over a lookup argument; the same proof system can run over
/// multiple commitment schemes and curves.
/// </para>
/// <para>
/// The constants in this class are canonical names for the proof-system
/// constructions the library is designed to host. They appear in tags, log
/// messages, and identifier fields. Concrete proof-system implementations are
/// supplied by the application via delegates.
/// </para>
/// </remarks>
public static class WellKnownProofSystems
{
    /// <summary>
    /// Groth16 (Groth, 2016). Pairing-based zk-SNARK with the smallest known
    /// proof size; requires a per-circuit trusted setup.
    /// </summary>
    public const string Groth16 = "Groth16";

    /// <summary>
    /// PLONK (Gabizon, Williamson, Ciobotaru, 2019). Universal-and-updatable
    /// SRS zk-SNARK; one trusted setup serves all circuits up to a chosen size.
    /// </summary>
    public const string Plonk = "PLONK";

    /// <summary>
    /// Nova (Kothapalli, Setty, Goldwasser, 2022). Folding scheme: each step
    /// produces a relaxed R1CS instance that folds into a running accumulator
    /// at constant per-step cost regardless of the number of accumulated steps.
    /// </summary>
    public const string Nova = "Nova";

    /// <summary>
    /// SuperNova. Generalisation of Nova that supports multiple circuit types
    /// per fold step; different operation types fold into the same accumulator.
    /// </summary>
    public const string SuperNova = "SuperNova";

    /// <summary>
    /// Halo2. PLONK-ish proof system with a built-in lookup argument and
    /// support for recursive composition without pairings.
    /// </summary>
    public const string Halo2 = "Halo2";

    /// <summary>
    /// STARK (Ben-Sasson et al., 2018). Hash-based, transparent (no trusted
    /// setup), post-quantum candidate, with proofs typically constructed over
    /// the FRI commitment scheme.
    /// </summary>
    public const string Stark = "STARK";

    /// <summary>
    /// Bulletproofs (Bünz et al., 2018). Logarithmic-size range and arithmetic
    /// proofs without a trusted setup, built over the inner-product argument.
    /// </summary>
    public const string Bulletproofs = "Bulletproofs";

    /// <summary>
    /// Marlin (Chiesa, Hu, Maller, Mishra, Vesely, Ward, 2020). Universal-SRS
    /// zk-SNARK with succinct verification.
    /// </summary>
    public const string Marlin = "Marlin";

    /// <summary>
    /// Spartan (Setty, 2020). Transparent zk-SNARK for R1CS without a trusted
    /// setup; can be instantiated over multiple polynomial commitment schemes.
    /// </summary>
    public const string Spartan = "Spartan";


    /// <summary>Determines whether the specified value identifies Groth16.</summary>
    public static bool IsGroth16(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Groth16, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies PLONK.</summary>
    public static bool IsPlonk(string? value) =>
        !string.IsNullOrEmpty(value)
            && (string.Equals(value, Plonk, StringComparison.OrdinalIgnoreCase)
                || string.Equals(value, "Plonk", StringComparison.OrdinalIgnoreCase));

    /// <summary>Determines whether the specified value identifies Nova.</summary>
    public static bool IsNova(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Nova, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies SuperNova.</summary>
    public static bool IsSuperNova(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, SuperNova, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Halo2.</summary>
    public static bool IsHalo2(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Halo2, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies STARK.</summary>
    public static bool IsStark(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Stark, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Bulletproofs.</summary>
    public static bool IsBulletproofs(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Bulletproofs, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Marlin.</summary>
    public static bool IsMarlin(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Marlin, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Spartan.</summary>
    public static bool IsSpartan(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Spartan, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Determines whether the specified proof system is a folding scheme.
    /// </summary>
    public static bool IsFoldingScheme(string? value) =>
        IsNova(value) || IsSuperNova(value);

    /// <summary>
    /// Determines whether the specified proof system natively supports recursive
    /// composition. A folding scheme also supports recursion in a different
    /// sense; this predicate identifies systems with full in-circuit verifier
    /// recursion as their primary mode.
    /// </summary>
    public static bool IsRecursiveByDesign(string? value) =>
        IsHalo2(value) || IsNova(value) || IsSuperNova(value);

    /// <summary>
    /// Determines whether the specified proof system targets post-quantum
    /// security. STARK constructions over hash-based commitments are
    /// post-quantum; pairing-based and discrete-log-based systems are not.
    /// </summary>
    public static bool IsPostQuantumByConstruction(string? value) =>
        IsStark(value);
}