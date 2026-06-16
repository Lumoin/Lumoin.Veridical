using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A BBS+ header: contextual bytes a signer binds into a signature
/// alongside the messages. The verifier supplies the same header when
/// validating. Lightweight wrapper around
/// <see cref="ReadOnlyMemory{Byte}"/> for the same reasons as
/// <see cref="BbsMessage"/>.
/// </summary>
/// <param name="Bytes">The header bytes. May be empty.</param>
public readonly record struct BbsHeader(ReadOnlyMemory<byte> Bytes);