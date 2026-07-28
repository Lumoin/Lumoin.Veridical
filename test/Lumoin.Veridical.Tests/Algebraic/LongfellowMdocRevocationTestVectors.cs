namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The span revocation test tuple transcribed from google/longfellow-zk
/// <c>circuits/tests/mdoc/mdoc_revocation_test.cc</c> (<c>span_tests[0]</c>) at the pinned
/// reference commit: a revocation authority key, a signed span whose identifier sits one below the
/// upper bound, and the signature scalars over the span digest.
/// </summary>
internal static class LongfellowMdocRevocationTestVectors
{
    /// <summary>One reference span tuple.</summary>
    /// <param name="PkX">The revocation authority public key's x coordinate.</param>
    /// <param name="PkY">The revocation authority public key's y coordinate.</param>
    /// <param name="Left">The span's lower bound <c>l</c>.</param>
    /// <param name="Right">The span's upper bound <c>r</c>.</param>
    /// <param name="Id">The credential identifier, strictly inside the span.</param>
    /// <param name="Epoch">The span's epoch.</param>
    /// <param name="E">The span digest the authority signed.</param>
    /// <param name="R">The span signature's <c>r</c>.</param>
    /// <param name="S">The span signature's <c>s</c>.</param>
    internal sealed record SpanVector(string PkX, string PkY, string Left, string Right, string Id, ulong Epoch, string E, string R, string S);


    /// <summary>The reference's single span tuple: <c>id = right − 1</c>, epoch 1025.</summary>
    public static SpanVector ReferenceSpan { get; } = new(
        PkX: "0x3cef945f99f65a1fd5d917a4783dc4fc6078a723aae8bfee0e472e10b43d3b91",
        PkY: "0x82480a801559d9bce4bf413e641178e64370ea80504f15f7b1efb1056a784789",
        Left: "0x7fff",
        Right: "0x2f6038b853cf3ae407fb1a9845ea98ca5251fb41d088bb0bce5667d25e9a1052",
        Id: "0x2f6038b853cf3ae407fb1a9845ea98ca5251fb41d088bb0bce5667d25e9a1051",
        Epoch: 1025,
        E: "0xa771beecd93838ed1a68e017b78a6d930153d2375158398ffe7cabf8e591044c",
        R: "0xc6e44683a459281f7cd07ce05a5c9d389659925aef90fa950a7007b08a0adec9",
        S: "0x35b3fc87f6e755acebc61efee92b1c6c6af68cdcb2c20ea9b1cbf8cd11aae4d9");
}
