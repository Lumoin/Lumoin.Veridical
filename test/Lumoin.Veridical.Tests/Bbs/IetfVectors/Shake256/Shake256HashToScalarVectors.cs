using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;

/// <summary>
/// Hash-to-scalar primitive vectors for the BLS12-381-SHAKE-256 ciphersuite.
/// </summary>
internal static class Shake256HashToScalarVectors
{
    /// <summary>
    /// Hash to scalar output.
    /// </summary>
    public static HashToScalarVector Vector001 { get; } = new(
        Id: "shake256-h2s-001",
        Description: "Hash to scalar output",
        Message: "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        Dst: "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4832535f",
        ExpectedScalar: "0500031f786fde5326aa9370dd7ffe9535ec7a52cf2b8f432cad5d9acfb73cd3");

    /// <summary>Every Shake256 hash-to-scalar primitive vector currently transcribed.</summary>
    public static IReadOnlyList<HashToScalarVector> All { get; } = new[] { Vector001 };
}