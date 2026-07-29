namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// Produces a per-shape <see cref="LigeroRowExtender"/> for the systematic
/// consecutive-integer Reed–Solomon extension, or <see langword="null"/> to
/// decline the shape — the caller then falls back to the barycentric
/// reference path. Declining is how an engine scopes itself to the fields and
/// sizes it accelerates without the encode sites hardcoding that knowledge.
/// </summary>
/// <param name="messageLength">The message length (the RS dimension); at least 1.</param>
/// <param name="codewordLength">The codeword length (the RS block length); at least <paramref name="messageLength"/>.</param>
/// <returns>The shape-bound extender, or <see langword="null"/> to use the barycentric path.</returns>
public delegate LigeroRowExtender? LigeroRowExtenderFactory(int messageLength, int codewordLength);
