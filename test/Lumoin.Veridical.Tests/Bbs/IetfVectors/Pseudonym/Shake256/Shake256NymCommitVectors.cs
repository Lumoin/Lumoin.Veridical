using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym.Shake256;

/// <summary>
/// CommitWithNym vectors for the BLS12-381-SHAKE-256 ciphersuite,
/// transcribed verbatim from
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section
/// 12.2.3, with the <see cref="NymCommitVector.ProverNym"/> field
/// recovered per that record's field doc (the draft prints it as
/// "undefined").
/// </summary>
internal static class Shake256NymCommitVectors
{
    /// <summary>
    /// valid no committed messages commitment with proof (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.2.3.1).
    /// </summary>
    public static NymCommitVector Vector001 { get; } = new(
        Id: "shake256-nym-commit-001",
        Description: "valid no committed messages commitment with proof",
        DraftSection: "12.2.3.1",
        CommittedMessages: [],
        MockedScalarSeed: "332e313431353932363533353839373933323338343632363433333833323739",
        MockedScalarDst: "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f434f4d4d49545f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        ProverBlind: "643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48",
        STilde: "40e7b7bc3a17cbd4fa61f81728b6f1224a934a34f8cd57000c360f1b301690b8",
        MTildes: [
            "43a77228890e6cf2c297292b8989751a6e0c9713caa592f39e61e23a997321cb",
        ],
        CommitmentWithProof: "990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a34714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f4acbc89bd5652414d5b8823a250ed40b");


    /// <summary>
    /// valid multiple committed messages commitment with proof (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.2.3.2).
    /// </summary>
    public static NymCommitVector Vector002 { get; } = new(
        Id: "shake256-nym-commit-002",
        Description: "valid multiple committed messages commitment with proof",
        DraftSection: "12.2.3.2",
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
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        ProverBlind: "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3",
        STilde: "4cdc5d3fdbe932953dd181851ebf6c134103666761013ff3db4e6dbe47d3992a",
        MTildes:
        [
            "3aca8b66d624ae8974e93fd1f654ddc5f071c9b026eb6eb116401a4cce87d699",
            "0eb04c03f3571cc6cfaf29f19126d032b85bc1e9ac0af917ec5dc8ba61ce2d28",
            "0824fe0cfae8bdb1d2c88cd0d8a4c1b432a48f7f12e35afe5494400a3caaa974",
            "05faf4555ddc6450e9f4b26ac7ed56ae57998c529d3a898f93f72406d9c63990",
            "253782ab563a180dcdb220d0b75ad1499c70c8e7da183c2720f313368cf001a3",
            "58ca8d9150a51f432c32e41bbfc4b630333ccd19fd8daa6d581ff651392dbece",
        ],
        CommitmentWithProof: "a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d139aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b09da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd141652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bce3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f832927c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a24bc398f84022dc0dc3a123971f7546c");

    /// <summary>Every Shake256-ciphersuite CommitWithNym vector currently transcribed (covers §12.2.3.{<i>n</i>}).</summary>
    public static IReadOnlyList<NymCommitVector> All { get; } = new[] { Vector001, Vector002 };
}
