using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.DataIntegrity;

/// <summary>
/// Canonicalizes an RDF document into its canonical quad set — the sequence of
/// canonical N-Quads, each an opaque UTF-8 byte string — in the deterministic
/// order the canonicalization defines.
/// </summary>
/// <remarks>
/// <para>
/// This is the injection seam by which a caller supplies RDF handling that this
/// library deliberately does not contain. The parse, the RDFC-1.0 blank-node
/// labeling, and the canonical serialization are entirely the delegate's; the
/// library treats each returned quad as opaque bytes and never interprets RDF.
/// A consumer wires a real RDF canonicalizer here (the sibling data-integrity
/// library in production, an off-the-shelf RDF toolkit in tests) exactly as the
/// field, hash, and CBOR-walk seams are wired — keeping the serialization
/// firewall intact.
/// </para>
/// <para>
/// The returned quads are treated as an ordered set: their order is the
/// canonicalizer's canonical order, which the commitment binds, and the caller
/// is responsible for that order being canonical. Duplicates, if any, are
/// dropped when the set is committed.
/// </para>
/// </remarks>
/// <param name="rdfDocument">The RDF document to canonicalize, as opaque bytes in whatever serialization the delegate accepts.</param>
/// <returns>The canonical quad set: one opaque canonical N-Quads byte string per quad.</returns>
public delegate IReadOnlyList<ReadOnlyMemory<byte>> RdfCanonicalizeDelegate(ReadOnlyMemory<byte> rdfDocument);
