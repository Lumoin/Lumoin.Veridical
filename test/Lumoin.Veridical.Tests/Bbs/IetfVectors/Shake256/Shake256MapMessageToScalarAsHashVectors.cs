using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;

/// <summary>
/// Per-message hash-to-scalar (messages_to_scalars) primitive vectors
/// for the BLS12-381-SHAKE-256 ciphersuite.
/// </summary>
internal static class Shake256MapMessageToScalarAsHashVectors
{
    /// <summary>
    /// MapMessageToScalar fixture.
    /// </summary>
    public static MapMessageToScalarAsHashVector Vector001 { get; } = new(
        Id: "shake256-mapmsg-001",
        Description: "MapMessageToScalar fixture",
        Dst: "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4d41505f4d53475f544f5f5343414c41525f41535f484153485f",
        Cases: new MapMessageToScalarAsHashCase[]
        {
            new("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "1e0dea6c9ea8543731d331a0ab5f64954c188542b33c5bbc8ae5b3a830f2d99f"),
            new("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80", "3918a40fb277b4c796805d1371931e08a314a8bf8200a92463c06054d2c56a9f"),
            new("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73", "6642b981edf862adf34214d933c5d042bfa8f7ef343165c325131e2ffa32fa94"),
            new("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c", "33c021236956a2006f547e22ff8790c9d2d40c11770c18cce6037786c6f23512"),
            new("496694774c5604ab1b2544eababcf0f53278ff50", "52b249313abbe323e7d84230550f448d99edfb6529dec8c4e783dbd6dd2a8471"),
            new("515ae153e22aae04ad16f759e07237b4", "2a50bdcbe7299e47e1046100aadffe35b4247bf3f059d525f921537484dd54fc"),
            new("d183ddc6e2665aa4e2f088af", "0e92550915e275f8cfd6da5e08e334d8ef46797ee28fa29de40a1ebccd9d95d3"),
            new("ac55fb33a75909ed", "4c28f612e6c6f82f51f95e1e4faaf597547f93f6689827a6dcda3cb94971d356"),
            new("96012096", "1db51bedc825b85efe1dab3e3ab0274fa82bbd39732be3459525faf70f197650"),
            new("", "27878da72f7775e709bb693d81b819dc4e9fa60711f4ea927740e40073489e78"),
        });

    /// <summary>Every Shake256 messages-to-scalars primitive vector currently transcribed.</summary>
    public static IReadOnlyList<MapMessageToScalarAsHashVector> All { get; } = new[] { Vector001 };
}