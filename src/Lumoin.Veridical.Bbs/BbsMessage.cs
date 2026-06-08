using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A single BBS+ message. Lightweight wrapper around
/// <see cref="ReadOnlyMemory{Byte}"/>; carries public application
/// data, not cryptographic material, so it is not pool-rented and
/// does not inherit from <c>SensitiveMemory</c>. The wrapper exists
/// to keep naked <c>ReadOnlySpan&lt;byte&gt;</c> arrays out of
/// <c>Sign</c> and <c>Verify</c>'s parameter lists.
/// </summary>
/// <param name="Bytes">The message bytes.</param>
public readonly record struct BbsMessage(ReadOnlyMemory<byte> Bytes);