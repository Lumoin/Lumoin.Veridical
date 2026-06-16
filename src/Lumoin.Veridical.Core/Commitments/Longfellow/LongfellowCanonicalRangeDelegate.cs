using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The field's <c>fits</c> predicate — google/longfellow-zk's <c>fp_generic.h fits(an) == an &lt; m_</c> —
/// applied to a canonical 32-byte big-endian scalar a freshly read <c>of_bytes_field</c> element produced.
/// The prime signature circuit closes this over a <c>&lt; p</c> comparison so an out-of-range wire draw is
/// rejected; the binary hash circuit needs no predicate (every 16-byte sequence is a valid element).
/// </summary>
/// <param name="canonical">The canonical 32-byte big-endian scalar to test.</param>
/// <returns><see langword="true"/> when the integer is below the field modulus, <see langword="false"/> when it reaches it.</returns>
internal delegate bool LongfellowCanonicalRangeDelegate(ReadOnlySpan<byte> canonical);
