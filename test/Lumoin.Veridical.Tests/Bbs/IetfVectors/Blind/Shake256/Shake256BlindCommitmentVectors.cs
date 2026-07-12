using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind.Shake256;

/// <summary>
/// Blind-BBS commitment vectors for the BLS12-381-SHAKE-256
/// ciphersuite, transcribed verbatim from
/// <c>draft-irtf-cfrg-bbs-blind-signatures-02</c> Section 9.2.3
/// (still valid under -03; see
/// <see cref="BlindDraftRevision.CommitmentVectorSourceRevision"/>).
/// The property numbering matches the -02 draft's sub-section
/// numbering.
/// </summary>
internal static class Shake256BlindCommitmentVectors
{
    /// <summary>
    /// valid no committed messages commitment with proof (draft-irtf-cfrg-bbs-blind-signatures-02, §9.2.3.1).
    /// </summary>
    public static BlindCommitmentVector Vector001 { get; } = new(
        Id: "shake256-blind-commitment-001",
        Description: "valid no committed messages commitment with proof",
        DraftSection: "9.2.3.1",
        CommittedMessages: [],
        MockedScalarSeed: "332e313431353932363533353839373933323338343632363433333833323739",
        MockedScalarDst: "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f434f4d4d49545f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f",
        ProverBlind: "30bd5c9bd2b61c44dd169c92cf28bb607830c56073f10e7a800c857cb05ec249",
        STilde: "4ead1c3cc9624bf2b82d6ce2dc1e8e7b664521f22faa543a78fc47d86fb04df3",
        MTildes: [],
        CommitmentWithProof: "b6389b0fdf04b9c35165acb11685e02193c53c3c1bb8ef3a9404dcee1727a365a3ac6ba7fc32654101cc72cc0ee7d32b23d2018bd6dc2f932c71d4401e763d4ed9999ee6c98837aa7dbe823050697dd744b05920ad0b6393e94f9b86e92d419406945f1e79d4be58dbaf9dc95237c951");


    /// <summary>
    /// valid multiple committed messages commitment with proof (draft-irtf-cfrg-bbs-blind-signatures-02, §9.2.3.2).
    /// The -02 printed Trace block for this vector is stale — it
    /// repeats §9.2.3.1's s_tilde verbatim and prints an empty
    /// m_tildes list even though five committed messages are present.
    /// <see cref="BlindCommitmentVector.STilde"/> and
    /// <see cref="BlindCommitmentVector.MTildes"/> below are the
    /// fixture-recovered correct trace values (from the cfrg draft
    /// repo's fixture_data JSON, cross-checked byte-for-byte against
    /// the -02 text elsewhere); <see cref="BlindCommitmentVector.ProverBlind"/> and
    /// <see cref="BlindCommitmentVector.CommitmentWithProof"/> were never affected by the
    /// misprint and match the -02 text directly. See
    /// W2.4-BLIND-VECTORS.md defect (4) for the full analysis.
    /// </summary>
    public static BlindCommitmentVector Vector002 { get; } = new(
        Id: "shake256-blind-commitment-002",
        Description: "valid multiple committed messages commitment with proof",
        DraftSection: "9.2.3.2",
        CommittedMessages:
        [
            "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
            "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
            "835889a40744813a892eff9deb1edaeb",
            "e1ca9729410dc6ba",
            "",
        ],
        MockedScalarSeed: "332e313431353932363533353839373933323338343632363433333833323739",
        MockedScalarDst: "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f434f4d4d49545f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f",
        ProverBlind: "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649",
        STilde: "0112ae1812a605e7cb3506f3a467e643ab4b442336e9a25a6b1811ab425fea64",
        MTildes:
        [
            "0699b8ca325fb8cd89f8040966ad1211d62dce309950655f28e779bb46a2f141",
            "0ea55d602ce42955ca4b61f6e2b946f5408e9dc0ba6cea304a333aacf545e7cc",
            "5261a5f453128f2a7a02aa543a21a878c21f11cd54b19b740f28515369ab89d9",
            "4542e45da8c5a2f160b5d7a04c738e3d2db99e504c0aa29233cd3acfd417ce10",
            "65888b461d6bac4e8544377e58d37ec79029948eea0d719f5c6c9fd63e4f94a1",
        ],
        CommitmentWithProof: "85d8034b358566ebfd26f921211b257d30def9962ddf80dc7cbdbf96da2bf598a8bbdc03bdc311ff290673ab29edf4a642be726c577a1aaeb11d00d10c5a07c824bbf8e47af13042f570b6bfc05e42783d70fb3ee76ab7c2565fda74ed6536e14105adf9ae943736a6c96c1102d1dc4424eda4ee1961f0d450736d1cc9f6b3ad2f9f1bcd3b63ef5445798b65ad04806240edee143b5c7c57f61ab7fc9fd8f0b05d984e12cee674541b6a79202931e0ef11bcfc908660861b48cfd4ce0970c9726d9359b4bd0c853da78891e9c9db41f2029195279d92f6831b37b5c6d5ac28840e97c12f7962e65adac6705ae712daa61c0c0bda85a3da6850a8dce296797beff88b1c8e8459dba0730ecace09177f79");

    /// <summary>Every Shake256-ciphersuite blind-commitment vector currently transcribed (covers -02 §9.2.3.{<i>n</i>}).</summary>
    public static IReadOnlyList<BlindCommitmentVector> All { get; } = new[] { Vector001, Vector002 };
}
