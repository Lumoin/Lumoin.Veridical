using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// Extends one Ligero row's systematic Reed–Solomon codeword in place: on
/// entry the codeword's prefix holds the message evaluations at the nodes
/// <c>{0, …, messageLength − 1}</c>; on return every entry holds the
/// evaluation at its node, the prefix unchanged.
/// </summary>
/// <remarks>
/// A delegate instance is bound to one <c>(messageLength, codewordLength)</c>
/// shape by its <see cref="LigeroRowExtenderFactory"/>. Any implementation
/// must produce the byte-identical codeword of the barycentric reference path
/// — field arithmetic is exact, so equality of the mathematical map is
/// equality of the bytes — which is what lets a convolution engine swap in
/// under committed fixtures. Implementations may assume rows of one shape are
/// extended sequentially, never concurrently.
/// </remarks>
/// <param name="codeword">The row's codeword buffer, <c>codewordLength · 32</c> bytes, message prefix populated.</param>
public delegate void LigeroRowExtender(Span<byte> codeword);
