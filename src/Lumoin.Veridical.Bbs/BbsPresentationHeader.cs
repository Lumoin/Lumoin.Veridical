using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A BBS+ presentation header: contextual bytes a Prover binds into
/// a single proof presentation alongside the disclosed messages. The
/// Verifier supplies the same bytes when validating the proof.
/// </summary>
/// <remarks>
/// <para>
/// The presentation header is distinct from the <see cref="BbsHeader"/>
/// (which the Signer binds into the signature at signing time). The
/// IETF draft draws this distinction explicitly: the header is fixed
/// per signature; the presentation header is chosen per proof. The
/// type system enforces the distinction so that swapping them at a
/// call site is a compile error rather than a silent verification
/// mismatch.
/// </para>
/// </remarks>
/// <param name="Bytes">The presentation-header bytes. May be empty.</param>
public readonly record struct BbsPresentationHeader(ReadOnlyMemory<byte> Bytes);