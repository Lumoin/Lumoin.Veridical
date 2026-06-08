using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Text;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Internal-byte-stability leg of the masked Spartan2 correctness
/// gate: under a deterministic <see cref="ScalarRandomDelegate"/>
/// seed, two independent prove calls against the
/// <c>x · y = 15</c> instance produce byte-identical proofs, and
/// both match a captured-at-commit-time hex constant. Any future
/// change to the prover that alters the wire bytes for fixed
/// inputs trips this test, surfacing accidental wire-format drift
/// or hidden nondeterminism.
/// </summary>
[TestClass]
internal sealed class MaskedSpartanFixtureTests
{
    //Fixed seed for the deterministic RNG so the fixture is reproducible.
    //Distinct from the base prover's fixture seed to keep the two fixtures
    //independent regression detectors.
    private static byte[] FixtureRandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.masked-spartan.fixture.xy-equals-15.v1");

    //Captured at commit time by running the prover once with FixtureRandomSeed
    //and pasting the recorded bytes. Any future change to the masked prover
    //that alters the wire bytes for fixed inputs trips this constant.
    private const string ExpectedProofHex =
        "91B7A151DBAF292A1FE2C45D0949B1880753A5C55E97CB997B631879D53A001622B01FF43AE9A86F7C38AAE7446910B8" +
        "A7241968DCCD7DEA246D4C7C515E3C5A1E6EA3A65E88AC423F5547A6B14F55A5E307641FE2FA563033D37B125B36535A" +
        "A92BC0976617B5855B564C8EF6598E1AF079E8F9C28DDCAE55DF53287ED782E12E0FCE3F7CC89208B4C757152B2E24B7" +
        "989028A78CD11BCA94E4912F949C0F7924607424A0FE25E31750A21CD12A8BA3B1A98505329A0B80B9AF7406BC1BA834" +
        "5112EC54DC7B68A5E67D8CC80A3AA6AF5F8F88AB104F5C51F84C18544AFD6DBD32A0448F42A995E01BBC3E35CA1A6691" +
        "34E8282D60AA127A950E1AFC2C909A541A7037922F1095E4A3C0D988A3330F91D36539A628674F4D116CD853FAE41A8D" +
        "01AA1D3DA68E0763B0972EA5345A8D152CCCFD20936A5C86E16A945C536158F5018DDAA45F90FF4AA2C88B673AE20E05" +
        "F8419472EE88F3CB9E849187E2F488C754E4DBB13052D139AF4D6B7247C887D79EFD7668C69233900D1A6F74982EFBCC" +
        "46F544E6E5F61A7A801C10CADE1E1BD5B74AAEEB1249FE214E2056A754454F4D16A52B66E6A260D2CBC2F62C70D9BCCF" +
        "E4AEABBD48007BC96EA24317ACF2EF862D4A56CDCD44C1A59785EC58E1B3799FC95D577A9000F792DD44862F59E5DF0B" +
        "2A96887D24D3287B5F1AE32F0C5251A9ED090E29F8050683066FD5A6BAA48CA300000000000000000000000000000000" +
        "000000000000000000000000000000004877D9438DF3FBCA7DDBD261024CAD45F938650A5DE85C249AFFC79B3CBCE009" +
        "31EE5A1C0C621F1345B0575A94CF2D8C8CD72C190B448DD313797CEE5E6EB4376B770D2115C120F1641FD0265CB42618" +
        "6447F7F0F922063850CD77AB5A5A54C55AC73F9D005FAF8D7BEE0DBBA5C6A8A76B9B23AE4637AA74D1E8CC27B8F02143" +
        "558749DB259C03C5772313631E096EBF148AD9E9EADA33AD7A627EA3383516AEB43FCA4DAD63F4DD3503611A6B3517AE" +
        "CA8821A1AEC214CAA948A3D2983342CFF0D8BFBCF9B1ED1AC8C57A1BF8116C0900000000000000000000000000000000" +
        "00000000000000000000000000000000245B81039B21A784149B009BAA9C084B63946EC87DD44C0AEE03241712B93FCD" +
        "245B81039B21A784149B009BAA9C084B63946EC87DD44C0AEE03241712B93FCD98D90C92F97F48500280506810C238C5" +
        "57F671A8F56D4B56A736A8CE770BF56ADCA62519130673BC454CFC63023F94838B58DA2D1629AFC34797DCBB4B562BFF" +
        "9FBC1D548039CDB8520F75F73885848CF685A1AC1AEF2E557C13AFDFE5FEC07AAC81E001E73205FF116F49402315EDF8" +
        "F45005461B803E75C518371DF4F554F3DBD88A950A97B21CF41FCB7A5D194FE18FDFCC3DEE0DEBF01B27C4D404805601" +
        "180176CCC230E6C2DB4A8856494B23FE00EA93F93CFAB81D1E8952915F1EB03B9054CD281EFA1F419B661A6D3BF72311" +
        "9C36D2750AF5A4894A49AAF998ABA5773B70DE078BDB9CB69384573484EDE82D957CEA6984DBEDC9DD3170B380A95DAE" +
        "53DF8024E393409163568FBA3F9F272F870C6CC99496C3378AD9AB8F53B8980FB4FAE39E2035248848334B9DB4D2C336" +
        "B50E10872E221D0B6C322F41A045FCD2C02E8F6A8847E26CAAA5624818DF80CDB79741AAD136D9879250852C95786009" +
        "285B43B1B343DB1C9DB51243740D66C316AF3EB22B507F8FFDCF92D3BB5F9944B9EF6EA7CF62D2AAAEDC8104DD6E331C" +
        "A2CE07219006C84B39CF61AB576C60777A5C534B2544E056EB3F6A78EB4B527205C1F2FA29749B8B3A3C606DEC64F1AD" +
        "D24020DD8DD7ABD05B58BE56FA858AA153B142C3CEAE0616266C21873123021F6C9090BA208C3B7C56A4F5502E9BA81E" +
        "2C68D5E636A4B88CACA5CE14178539C47C2431B2F20FB9A991E10EEEE65F8BBCB84E9C8D63AE50A849389991D31CD2ED" +
        "DA33EA128C2B3495A7371DCA1A27DB481ADDA9DF65BCB493EDC4935CCB9962D3A449414B7D9E2E305E2A0FB4CE7BB9E3" +
        "6332F8C01C4920E174025235006CC003D972723EF9AE272BFBFD87262BAC022C90FDADBBBABA95EA2355136839620815" +
        "8761FF423F0631AB5F495D008B844C0D548FA39114CF01EF93B180F822983F5DA76D59C0280E95DC86C6EB19E3571897" +
        "8FBA597F16C1B96A94CDE5119A6429E849021FD782C4492CDEE6CF316DBB4335B21392E990DD989FEEAD4ADC62CF4A92" +
        "FEC2B704D1A65D2DE2D444F35DF5F5C7EABA2B9DBB0E14744A59F6307E93582AAFACE2D13F6D60CCDA5E06D3529E2613" +
        "452CB56D2F0C2576F943E07661F6A1558F7729F7B90A85D236A615C0FE4B47D8ACD6B392E2BAB56378A7C21D6272F2BD" +
        "A01FB92C7E5AA0B4DAEB6DA4726B5DD071D3E52C841364D36CC5B298D7AF1D6CA925CCC89D85B0B669AD0A0EF4FC1213" +
        "8C040881DFF226465EA6B56C5C752617C7B8ACE57D7FF8C2A28A5EB31FA45B5DA411095DBEF576F39B50EE1DE65BBE3C" +
        "F7371999F45E8A2B324F9898C85B2DB477067C1EB04D2D6C0CEE141653DAEA2444BC983CB4C0C03E4206F13CCBEAD6D2" +
        "DDE345B3D6424DBDD08CF215B1A004FF3F3C6F1871847451B62648B869C914E03AEDF712DF06811D2ED8D7D29D50BF83" +
        "4EA0D63216D83F294EE66F718CC650CA6838BABA9AFF226BEF7DEDC2B0DEE01A96E03D88EF8C48B017784560F635636E" +
        "F2011E4488E871FE99D3D7AD95AC1886067635882EB2CF934CECC52AE347C21FAEFA5ED3F8E14A5CE4B84D1F18E6D3ED" +
        "66613A679184CAA11E3106C8D787F455618D21AF01CC27F5F121AF54FB9503D0AE656F86EE9D69A69AE49007EA0EE289" +
        "C30EE78E6E445E853035377D21F3FD2EE45CE7623C0B1FFCBD1D9C5E60B7E0F96AAA4906F31E0E09E7C923E0E347BD5C" +
        "D9278D90A4EF0945F4CD27030E8818775F4DC63E8A27C4F934B7487DF5EA9DEBAC82E14C382C61F203021CDE71896FE3" +
        "6FA410B8357C31632F443B4E649A81A3C7F9C79F9ABA4B9CEEB8F203CEEC23D0";


    [TestMethod]
    public void XyEquals15UnderFixedSeedProducesCanonicalBytes()
    {
        byte[] firstProofBytes = ProduceProofBytes();
        byte[] secondProofBytes = ProduceProofBytes();

        Assert.IsTrue(
            firstProofBytes.AsSpan().SequenceEqual(secondProofBytes),
            "Two prove calls under the same DeterministicScalarRandom seed must produce byte-equal proofs. If this fails, randomness is leaking into the prover from a source other than the ScalarRandomDelegate — a regression in MaskedSpartanProver.Prove.");

        string actualHex = Convert.ToHexString(firstProofBytes);
        Assert.AreEqual(
            ExpectedProofHex,
            actualHex,
            $"Masked Spartan2 wire-format drift for xy=15. If the change is intentional, update ExpectedProofHex to:\n{actualHex}");

        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength: 2);
        using RawR1csInstance verifierInstance = BuildOneMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        using MaskedSpartanProof proof = RehydrateProof(firstProofBytes);
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(verified, "The captured xy=15 fixture proof must verify under the masked verifier.");
    }


    private static byte[] ProduceProofBytes()
    {
        //The prover's provider and the Prove call must draw blinding from the
        //same deterministic stream, so build the prover from the seeded RNG.
        var rng = new DeterministicScalarRandom(FixtureRandomSeed);
        ScalarRandomDelegate random = rng.AsDelegate();
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 2, random);
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildOneMultiplyWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();

        using MaskedSpartanProof proof = prover.Prove(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            SensitiveMemoryPool<byte>.Shared);

        return proof.AsReadOnlySpan().ToArray();
    }


    private static MaskedSpartanProof RehydrateProof(byte[] proofBytes)
    {
        //Run the prover once more to obtain a template MaskedSpartanProof
        //carrying the right dimension metadata, then construct a fresh
        //MaskedSpartanProof wrapping the canonical bytes.
        var rng = new DeterministicScalarRandom(FixtureRandomSeed);
        ScalarRandomDelegate random = rng.AsDelegate();
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 2, random);
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildOneMultiplyWitness();
        using FiatShamirTranscript transcript = FreshTranscript();
        using MaskedSpartanProof template = prover.Prove(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            SensitiveMemoryPool<byte>.Shared);

        return MaskedSpartanProof.FromBytes(
            proofBytes,
            template.WitnessCommitmentRowCount,
            template.OuterMaskCommitmentRowCount,
            template.InnerMaskCommitmentRowCount,
            template.OuterRoundCount,
            template.InnerRoundCount,
            template.WitnessIpaRoundCount,
            template.OuterMaskIpaRoundCount,
            template.InnerMaskIpaRoundCount,
            template.ErrorIpaRoundCount,
            template.Curve,
            SensitiveMemoryPool<byte>.Shared);
    }
}