using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind.Sha256;

/// <summary>
/// Blind-BBS commitment vectors for the BLS12-381-SHA-256
/// ciphersuite, transcribed verbatim from
/// <c>draft-irtf-cfrg-bbs-blind-signatures-02</c> Section 9.1.3
/// (still valid under -03; see
/// <see cref="BlindDraftRevision.CommitmentVectorSourceRevision"/>).
/// The property numbering matches the -02 draft's sub-section
/// numbering.
/// </summary>
internal static class Sha256BlindCommitmentVectors
{
    /// <summary>
    /// valid no committed messages commitment with proof (draft-irtf-cfrg-bbs-blind-signatures-02, §9.1.3.1).
    /// </summary>
    public static BlindCommitmentVector Vector001 { get; } = new(
        Id: "sha256-blind-commitment-001",
        Description: "valid no committed messages commitment with proof",
        DraftSection: "9.1.3.1",
        CommittedMessages: [],
        MockedScalarSeed: "332e313431353932363533353839373933323338343632363433333833323739",
        MockedScalarDst: "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f434f4d4d49545f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f",
        ProverBlind: "1b6f406b17aaf92dc7deb911c7cae49756a6623b5c385b5ae6214d7e3d9597f7",
        STilde: "0b71f3e3fc1517bd763b180dc4f6d269da8c96fb5307653b77205c31e40c521e",
        MTildes: [],
        CommitmentWithProof: "849d3cc626720202cbc1610fc01ab41ce32099af602def0c579f37dd18b485ef60719275a036bdd8120e7e938c8e1a3d4d0322587441ccc5caf186001b45dd09ee159713c3e3ea0f411f94a5d6665546562d09c093b687a129e464a57e18cdbf5306bcabf3e7cc95f5ba98cdd9bf3768");


    /// <summary>
    /// valid multiple committed messages commitment with proof (draft-irtf-cfrg-bbs-blind-signatures-02, §9.1.3.2).
    /// </summary>
    public static BlindCommitmentVector Vector002 { get; } = new(
        Id: "sha256-blind-commitment-002",
        Description: "valid multiple committed messages commitment with proof",
        DraftSection: "9.1.3.2",
        CommittedMessages:
        [
            "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
            "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
            "835889a40744813a892eff9deb1edaeb",
            "e1ca9729410dc6ba",
            "",
        ],
        MockedScalarSeed: "332e313431353932363533353839373933323338343632363433333833323739",
        MockedScalarDst: "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f434f4d4d49545f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f",
        ProverBlind: "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589",
        STilde: "2c78a955f6598824fc77bf6cb5a8b58204da0cadb499faf4bbee2d4fceadc0d1",
        MTildes:
        [
            "2b8c33fb06580d8dffdc72212967ae75838859096abeea973cc0d9e80ac1946c",
            "2b9e86176d6a4c5b63fcd4a4ace793316c0f7adccdc888b308b5408bd6a21b89",
            "005c784be3f30d47393996fe596adbbe30aeb1d3a8d888b5075aa56d3b2be35c",
            "6b64079fac7b8d026520647b5764c5dbbe8b5486efb7791f5742511129c36a87",
            "41cbd69ac7603928be8e96d29756fe6763e5de8103c68eb484744ebb29bd2a1b",
        ],
        CommitmentWithProof: "a2a3e178bcc77f98a3c07f8532134021ab5847326b5b3bfc3089ca73f1bc51cfe2c99163f4919525dd6bedc8a14ee39e30374643902017ca2e6fb8b5647c736e82d1d3c5b05de5c3021fa6f40d9f36dd22fa06e522411aa20377088ca9a15885d7a5044175f0168e927149ee71e2d257079e0100d6d96a7ddf5392dbc64267af8df7b4711cb5eeccb5e8901d0580b9e837f38337cb7260cffcf4f962154fafe5c98beaed7e4d2fc0f8e7eb1ba4eb04086f170aa4924894e2ab63054049c9ef5dfff4f90b48ef0dcf1f50699907301073270e4782d4d7628cfbe1444cea930928bb45004e41e0ad86a874ea03473845ce42f78ceb6f855ba8326a4d47732c5aed3968b396a07f079b22b5bf2139e51a03");

    /// <summary>Every Sha256-ciphersuite blind-commitment vector currently transcribed (covers -02 §9.1.3.{<i>n</i>}).</summary>
    public static IReadOnlyList<BlindCommitmentVector> All { get; } = new[] { Vector001, Vector002 };
}
