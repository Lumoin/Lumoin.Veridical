using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Identifies which proof system family a circuit, key pair, or proof object
/// belongs to.
/// </summary>
/// <remarks>
/// <para>
/// The proof system determines the constraint encoding (R1CS, PLONKish,
/// AIR), the commitment scheme, the soundness assumptions, and the prover
/// and verifier algorithms. A <see cref="CommitmentScheme"/> identifier and
/// a <see cref="LookupArgument"/> identifier together describe how a
/// particular instance is parameterised; this enum identifies the system
/// family itself.
/// </para>
/// <para>
/// Predefined values cover the families this library plans to support:
/// <see cref="Groth16"/> and <see cref="Plonk"/> for SNARK construction
/// classics; <see cref="Nova"/> and <see cref="SuperNova"/> for incrementally
/// verifiable computation via folding; <see cref="Halo2"/> for the Plonk +
/// IPA + lookup combination; <see cref="Stark"/> for hash-based transparent
/// systems; <see cref="Bulletproofs"/> for short logarithmic-size proofs;
/// <see cref="Marlin"/> for universal SNARKs; and <see cref="Spartan"/> for
/// sumcheck-driven systems.
/// </para>
/// <para>
/// Use <see cref="Create"/> with codes above 1000 to register
/// application-specific or research-stage proof systems.
/// </para>
/// </remarks>
[DebuggerDisplay("{ProofSystemNames.GetName(this),nq}")]
public readonly struct ProofSystem: IEquatable<ProofSystem>
{
    /// <summary>Gets the numeric code for this proof system.</summary>
    public int Code { get; }


    private ProofSystem(int code) { Code = code; }


    /// <summary>No specific proof system selected.</summary>
    public static ProofSystem None { get; } = new(0);

    /// <summary>
    /// Groth16. Pairing-based SNARK with the smallest known proof size and
    /// fastest verification, at the cost of a per-circuit trusted setup.
    /// </summary>
    public static ProofSystem Groth16 { get; } = new(1);

    /// <summary>
    /// PLONK. Universal-setup SNARK with a single structured reference string
    /// reusable across circuits, paired with KZG polynomial commitments.
    /// </summary>
    public static ProofSystem Plonk { get; } = new(2);

    /// <summary>
    /// Nova. Folding scheme that compresses many R1CS instances into a single
    /// relaxed R1CS instance, enabling incrementally verifiable computation
    /// with constant per-step prover overhead.
    /// </summary>
    public static ProofSystem Nova { get; } = new(3);

    /// <summary>
    /// SuperNova. Generalisation of Nova to non-uniform computations: each
    /// step may run one of several distinct circuits, with the active circuit
    /// selected at each step.
    /// </summary>
    public static ProofSystem SuperNova { get; } = new(4);

    /// <summary>
    /// Halo2. Plonk-style proof system over the Pasta cycle with IPA
    /// commitments, recursive composition without pairings, and a lookup
    /// argument built in.
    /// </summary>
    public static ProofSystem Halo2 { get; } = new(5);

    /// <summary>
    /// STARK. Hash-based transparent proof system using AIR constraints and
    /// FRI commitments. Post-quantum resistant; no trusted setup.
    /// </summary>
    public static ProofSystem Stark { get; } = new(6);

    /// <summary>
    /// Bulletproofs. Logarithmic-size range and arithmetic-circuit proofs
    /// built on the inner-product argument, with no trusted setup.
    /// </summary>
    public static ProofSystem Bulletproofs { get; } = new(7);

    /// <summary>
    /// Marlin. Universal-and-updatable SNARK over R1CS, with a polynomial-IOP
    /// design that admits multiple commitment-scheme instantiations.
    /// </summary>
    public static ProofSystem Marlin { get; } = new(8);

    /// <summary>
    /// Spartan. Transparent SNARK based on the sumcheck protocol over R1CS,
    /// with sublinear verification when paired with sumcheck-friendly
    /// commitments.
    /// </summary>
    public static ProofSystem Spartan { get; } = new(9);


    private static readonly List<ProofSystem> proofSystems =
        [None, Groth16, Plonk, Nova, SuperNova, Halo2, Stark, Bulletproofs, Marlin, Spartan];


    /// <summary>Gets all registered proof system values.</summary>
    public static IReadOnlyList<ProofSystem> ProofSystems => proofSystems.AsReadOnly();


    /// <summary>
    /// Creates a new proof system value for application-specific extensions.
    /// </summary>
    /// <param name="code">The unique numeric code for this proof system.</param>
    /// <returns>The newly created proof system.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Use code values above 1000 to avoid collisions with future library
    /// additions. This method is not thread-safe; call it only during
    /// application startup before concurrent access begins.
    /// </remarks>
    public static ProofSystem Create(int code)
    {
        for(int i = 0; i < proofSystems.Count; ++i)
        {
            if(proofSystems[i].Code == code)
            {
                throw new ArgumentException($"Proof system code {code} already exists.");
            }
        }

        var created = new ProofSystem(code);
        proofSystems.Add(created);

        return created;
    }


    /// <inheritdoc/>
    public override string ToString() => ProofSystemNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ProofSystem other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ProofSystem other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(ProofSystem left, ProofSystem right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(ProofSystem left, ProofSystem right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="ProofSystem"/> values.</summary>
public static class ProofSystemNames
{
    /// <summary>Gets the name for the specified proof system.</summary>
    public static string GetName(ProofSystem system) => GetName(system.Code);

    /// <summary>Gets the name for the specified proof system code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == ProofSystem.None.Code => nameof(ProofSystem.None),
        var c when c == ProofSystem.Groth16.Code => nameof(ProofSystem.Groth16),
        var c when c == ProofSystem.Plonk.Code => nameof(ProofSystem.Plonk),
        var c when c == ProofSystem.Nova.Code => nameof(ProofSystem.Nova),
        var c when c == ProofSystem.SuperNova.Code => nameof(ProofSystem.SuperNova),
        var c when c == ProofSystem.Halo2.Code => nameof(ProofSystem.Halo2),
        var c when c == ProofSystem.Stark.Code => nameof(ProofSystem.Stark),
        var c when c == ProofSystem.Bulletproofs.Code => nameof(ProofSystem.Bulletproofs),
        var c when c == ProofSystem.Marlin.Code => nameof(ProofSystem.Marlin),
        var c when c == ProofSystem.Spartan.Code => nameof(ProofSystem.Spartan),
        _ => $"Custom ({code})"
    };
}