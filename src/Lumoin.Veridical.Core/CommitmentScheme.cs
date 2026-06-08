using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Identifies which polynomial commitment family a proof system uses to bind
/// the prover to a polynomial it will later open at challenge points.
/// </summary>
/// <remarks>
/// <para>
/// The choice of commitment scheme determines proof size, verification cost,
/// trusted-setup requirements, and post-quantum resistance. KZG-family
/// commitments give compact proofs and constant-time verification but require
/// a trusted setup and rely on pairing assumptions. IPA gives transparent
/// (no trusted setup) commitments at the cost of logarithmic proof size and
/// linear verification. FRI gives transparent post-quantum commitments at the
/// cost of polylogarithmic proofs and concrete prover overhead.
/// </para>
/// <para>
/// Predefined schemes cover the families this library plans to support:
/// <see cref="Kzg"/>, <see cref="HyperKzg"/>, and <see cref="Mercury"/> for
/// KZG variants; <see cref="Ipa"/> for the inner-product argument used by
/// Halo2 and Bulletproofs; <see cref="Fri"/> for the FRI commitment used by
/// STARKs; <see cref="Hyrax"/> for sumcheck-friendly multilinear commitments;
/// and <see cref="Pedersen"/> for the classic group-based commitment.
/// </para>
/// <para>
/// Use <see cref="Create"/> with codes above 1000 to register application-specific
/// or research-stage commitment schemes.
/// </para>
/// </remarks>
[DebuggerDisplay("{CommitmentSchemeNames.GetName(this),nq}")]
public readonly struct CommitmentScheme: IEquatable<CommitmentScheme>
{
    /// <summary>Gets the numeric code for this commitment scheme.</summary>
    public int Code { get; }


    private CommitmentScheme(int code) { Code = code; }


    /// <summary>No specific commitment scheme selected.</summary>
    public static CommitmentScheme None { get; } = new(0);

    /// <summary>
    /// KZG. Pairing-based univariate polynomial commitment with a structured
    /// reference string and constant-size openings. Requires a trusted setup.
    /// </summary>
    public static CommitmentScheme Kzg { get; } = new(1);

    /// <summary>
    /// HyperKZG. Multilinear extension of KZG that supports openings at
    /// boolean-hypercube points; pairs with sumcheck-based proof systems.
    /// </summary>
    public static CommitmentScheme HyperKzg { get; } = new(2);

    /// <summary>
    /// Mercury. KZG variant with linear-time prover and constant-size
    /// openings, designed for high-throughput proving of large traces.
    /// </summary>
    public static CommitmentScheme Mercury { get; } = new(3);

    /// <summary>
    /// IPA (inner-product argument). Transparent group-based commitment with
    /// logarithmic proof size and linear verification. Used by Halo2 and
    /// Bulletproofs.
    /// </summary>
    public static CommitmentScheme Ipa { get; } = new(4);

    /// <summary>
    /// FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity).
    /// Transparent, hash-based, post-quantum-resistant polynomial commitment
    /// used by STARKs.
    /// </summary>
    public static CommitmentScheme Fri { get; } = new(5);

    /// <summary>
    /// Hyrax. Sumcheck-friendly multilinear polynomial commitment with
    /// transparent setup and square-root proof size.
    /// </summary>
    public static CommitmentScheme Hyrax { get; } = new(6);

    /// <summary>
    /// Pedersen. Classic group-based binding-and-hiding commitment to a vector
    /// of scalars; used as a building block in many other schemes.
    /// </summary>
    public static CommitmentScheme Pedersen { get; } = new(7);

    /// <summary>
    /// BaseFold. Transparent, hash-based, post-quantum-resistant multilinear
    /// polynomial commitment built from a random foldable code; pairs with
    /// sumcheck-based proof systems and needs no trusted setup.
    /// </summary>
    public static CommitmentScheme BaseFold { get; } = new(8);


    private static readonly List<CommitmentScheme> commitmentSchemes =
        [None, Kzg, HyperKzg, Mercury, Ipa, Fri, Hyrax, Pedersen, BaseFold];


    /// <summary>Gets all registered commitment scheme values.</summary>
    public static IReadOnlyList<CommitmentScheme> CommitmentSchemes => commitmentSchemes.AsReadOnly();


    /// <summary>
    /// Creates a new commitment scheme value for application-specific extensions.
    /// </summary>
    /// <param name="code">The unique numeric code for this commitment scheme.</param>
    /// <returns>The newly created commitment scheme.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Use code values above 1000 to avoid collisions with future library
    /// additions. This method is not thread-safe; call it only during
    /// application startup before concurrent access begins.
    /// </remarks>
    public static CommitmentScheme Create(int code)
    {
        for(int i = 0; i < commitmentSchemes.Count; ++i)
        {
            if(commitmentSchemes[i].Code == code)
            {
                throw new ArgumentException($"Commitment scheme code {code} already exists.");
            }
        }

        var created = new CommitmentScheme(code);
        commitmentSchemes.Add(created);

        return created;
    }


    /// <inheritdoc/>
    public override string ToString() => CommitmentSchemeNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CommitmentScheme other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is CommitmentScheme other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(CommitmentScheme left, CommitmentScheme right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(CommitmentScheme left, CommitmentScheme right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="CommitmentScheme"/> values.</summary>
public static class CommitmentSchemeNames
{
    /// <summary>Gets the name for the specified commitment scheme.</summary>
    public static string GetName(CommitmentScheme scheme) => GetName(scheme.Code);

    /// <summary>Gets the name for the specified commitment scheme code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == CommitmentScheme.None.Code => nameof(CommitmentScheme.None),
        var c when c == CommitmentScheme.Kzg.Code => nameof(CommitmentScheme.Kzg),
        var c when c == CommitmentScheme.HyperKzg.Code => nameof(CommitmentScheme.HyperKzg),
        var c when c == CommitmentScheme.Mercury.Code => nameof(CommitmentScheme.Mercury),
        var c when c == CommitmentScheme.Ipa.Code => nameof(CommitmentScheme.Ipa),
        var c when c == CommitmentScheme.Fri.Code => nameof(CommitmentScheme.Fri),
        var c when c == CommitmentScheme.Hyrax.Code => nameof(CommitmentScheme.Hyrax),
        var c when c == CommitmentScheme.Pedersen.Code => nameof(CommitmentScheme.Pedersen),
        var c when c == CommitmentScheme.BaseFold.Code => nameof(CommitmentScheme.BaseFold),
        _ => $"Custom ({code})"
    };
}