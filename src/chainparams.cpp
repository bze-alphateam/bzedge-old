// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */


/*
Summary of additional consensus parameters
mainnnet
        consensus.fPowNoRetargeting=false;
        consensus.nLWMAHeight=200000;
        consensus.nPowLwmaTargetSpacing = 1 * 60;
        consensus.nZawyLwmaAveragingWindow = 75;  //N=75 recommended by Zawy
        consensus.nZawyLwmaAdjustedWeight = 13772; // hx43 uses k = (N+1)/2 * 0.998 * T 13772
        consensus.nZawyLwmaMinDenominator = 10;
        consensus.fZawyLwmaSolvetimeLimitation = true;


testnet
        consensus.fPowNoRetargeting=false;
        consensus.nLWMAHeight=20000;
        consensus.nPowLwmaTargetSpacing = 1 * 60;
        consensus.nZawyLwmaAveragingWindow = 75;  //N=75 recommended by Zawy
        consensus.nZawyLwmaAdjustedWeight = 13772;
        consensus.nZawyLwmaMinDenominator = 10;
        consensus.fZawyLwmaSolvetimeLimitation = true;

regtest
        consensus.fPowNoRetargeting=true
        consensus.nLWMAHeight=-1
        consensus.nPowLwmaTargetSpacing = 1 * 60;
        consensus.nZawyLwmaAveragingWindow = 75;  //N=75 recommended by Zawy
        consensus.nZawyLwmaAdjustedWeight = 13772;
        consensus.nZawyLwmaMinDenominator = 10;
        consensus.fZawyLwmaSolvetimeLimitation = true;

*/


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    // genesis.nSolution.clear(); // for no solution in genesis block
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}


	/**
	* Build the genesis block. Note that the output of its generation
	* transaction cannot be spent since it did not originally exist in the
	* database (and is in any case of zero value).
	*
	* >>> from pyblake2 import blake2s
	* >>> 'BitcoinZ' + blake2s(b'BitcoinZ - Your Financial Freedom. Dedicated to The Purest Son of Liberty - Thaddeus Kosciuszko. BTC #484410 - 0000000000000000000c6a5f221ebeb77437cbab649d990facd0e42a24ee6231').hexdigest()
	*/
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "BitcoinZ2beeec1ef52fd18475953563ebdb287f056453f452200581f958711118e980b2";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "BZE";
        bip44CoinType = 133; // zcash => As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 2;
        consensus.nSubsidyHalvingInterval = 2102400;  //4yr with 1 min targeting 
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 34;
        consensus.nPowMaxAdjustUp = 34;
        consensus.nPowTargetSpacing = 1 * 60; //no longer for consensus, deprecated in favour of nPowLwmaTargetSpacing and nPowLwmaTargetSpacing. Can be adjusted to 1 min shortly before fork to keep notifications consistent. 
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 175007;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 175007;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 175015;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 484000;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 175017;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 484000;

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000004000");
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000008d730e269b84"); // chainwork of the last checkpoint



		consensus.fPowNoRetargeting=false;
        consensus.nLWMAHeight=199900;
        consensus.nPowLwmaTargetSpacing = 1 * 60;
        consensus.nZawyLwmaAveragingWindow = 75;
        consensus.nZawyLwmaAdjustedWeight = 2280;
        consensus.nZawyLwmaMinDenominator = 10;
        consensus.fZawyLwmaSolvetimeLimitation = true;
        consensus.ZCnPowTargetSpacing = 2.5 * 60; //legacy spacing.

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04696857e466eba4ea69697c7227b1aefa29e7b67c8a1187f3a93c59332b327ec37865f7f620ec139b6f174afbb3ff487c512fb2c37906b92d48caa3ba85a00114");
        nDefaultPort = 1990;
        nPruneAfterHeight = 100000;
       
        // nMaxTipAge = 24 * 60 * 60; // obsolete

        newTimeRule = 200000;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 200000;
        eh_epoch_2_startblock = 200000;
        
        bze_pers_start_blocktime = 1553371200; // Human time (GMT): Saturday, March 23, 2019 8:00:00 PM
        
        const size_t N = 144, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

		// empty solution
		const std::vector<unsigned char> empty_solution;
        genesis = CreateGenesisBlock(
            1478403829,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000021d"),
            empty_solution,
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xf499ee3d498b4298ac6a64205b8addb7c43197e2a660229be65db8a4534d75c1")); //incremented by 1 making 2
        assert(genesis.hashMerkleRoot == uint256S("0xf40283d893eb46b35379a404cf06bd58c22ce05b32a4a641adec56e0792789ad"));
        
		vFixedSeeds.clear();
		vSeeds.clear();
		// use name as: echo -n hostname | sha256sum
		vSeeds.push_back(CDNSSeedData("67ef7caf7a2b08c2f0f11460b121bba1090472761a25da0dc839da81e9255425.BZE", "bzeseed.bzedge.org"));
		vSeeds.push_back(CDNSSeedData("9320e28827e4e0ec1aa7f0876fa21fbe92fe2af311b2aabe2f585e73170a7863.BZE", "bzeseed.btcz.biz"));

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

		checkpointData = (CCheckpointData) {
			boost::assign::map_list_of
			( 0, uint256S("0xf499ee3d498b4298ac6a64205b8addb7c43197e2a660229be65db8a4534d75c1"))
			( 2007, uint256S("0x000000215111f83669484439371ced6e3bc48cd7e7d6be8afa18952206304a1b"))
			( 10000, uint256S("0x00000002ccb858ec2c35fb79ce2079333461efa50f2b59814558b9ae3ce62a40"))
			( 20675, uint256S("0x00000004804df1618f984fef70c1a210988ade5093b6947c691422fc93013a63")) // Thaddeus Kosciuszko - 200th death anniversary (October 15 2017)
			( 40000, uint256S("0x00000005a2d9a94e2e16f9c1e578a2eb46cc267ab7a51539d22ff8aa0096140b"))
			( 56000, uint256S("0x000000026a063927c6746acec6c0957d1f69fa2ab1a59c06ce30d60bbbcea92a"))
			( 84208, uint256S("0x0000000328e5d0346a78aea2d586154ab3145d51ba3936998253593b0ab2980c"))
			( 105841, uint256S("0x000000010305387fd72bc70ce5cc5b512fe513016e7208b9ee61d601fe212991"))  //Dr Hawking, Rest in peace.
			( 140000, uint256S("0x0000000155f89d1ededf519c6445d41c9240ee4daa721c91c19eea0faa2f02c8"))
			( 153955, uint256S("0x00000006913d3122f32e60c9d64e87edd8e9a05444447df49713c15fbae6484d"))
			( 160011, uint256S("0x00000002858c5af3a2e7c511c1b360533bef782361415e8e6515eb5961d88354"))  //BZEdge born
			( 165300, uint256S("0x000001f49a3c070be93770e8d7e84b281c159e367d56c809048d02441db1956c"))
			( 444600, uint256S("0x0000181b00e928fac7c5841f04ab99038cedbd3776ff658df6eb6c841ccc2ea3")),

			1550401324,     // * UNIX timestamp of last checkpoint block
			1105771,         // * total number of transactions between genesis and last checkpoint
							//   (the tx=... number in the SetBestChain debug.log lines)
			3600  // * estimated number of transactions per day after checkpoint
							//   total number of tx / (checkpoint block height / (60 * 24))
		};


        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TBZE";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 2;
        consensus.nSubsidyHalvingInterval = 2102400;  //4yr with 1 min targeting 
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 34; // 34% adjustment down
        consensus.nPowMaxAdjustUp = 34; // 34% adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 175007;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 175007;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 175013;
        // consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 235000; // original testnet
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 200; // private testnet
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 175017;
        // consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 235000; // original testnet
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 200; // private testnet
		
		
		consensus.fPowNoRetargeting=false;
		consensus.nLWMAHeight=76;
		consensus.nPowLwmaTargetSpacing = 1 * 60;
		consensus.nZawyLwmaAveragingWindow = 75;  //N=75 recommended by Zawy
		consensus.nZawyLwmaAdjustedWeight = 2280;
		consensus.nZawyLwmaMinDenominator = 10;
		consensus.fZawyLwmaSolvetimeLimitation = true;
		consensus.ZCnPowTargetSpacing = 2.5 * 60;
		
		

        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
		
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 11990;
        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
		
		eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 80;
        eh_epoch_2_startblock = 76;
		
		bze_pers_start_blocktime = 1550588400; // Human time (GMT): Tuesday, February 19, 2019 3:00:00 PM
		
        genesis = CreateGenesisBlock(
            1550490600,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000005"),
            ParseHex("002472eeef9ec88bf6487438a82728c6f62cf99da923b87122c5d2cfa39e9649a480d2354f12b3d9ba0e03bb912cffe469a9f8bb60f1b31479228d889c1dd310b8b0afc615e24f8244553cedb2b1e58fdb70c72e0638e07706e96fc3d5ea23c3ad7a64a5517b3630441bfcae10039f87f994161425843db28225cdf42ee40d3685d98711e4bf0492e746926afaae48ac9fe066176ef33dc278931fc804e47e82f03c57bcf79ece050f738f9b9d189777be5553d90c7384c59352716c4b5a3a7f3873326b87bffab673f634220ab572db759617b2a424890fd861185a553aeee2e84e96643a94043e98b34c80238bb33a2fe7354b50917f99a51cf39d1382fd49c2aafc316b7ea483e77f53056fc23dfbf925e75bb96213d0a69eff13ee7cf8d1be24fdfe912e1f62ec5502172fbfa19cc46002432979b3daf92d62327bee131e98834f87341aafbe61a7ab1ffffc78920189e60afadb327ff192fab9d0fccc2f88953d95d10eafc9ff0b49b52567cba61aec55f8da9c14b8a6970a411a2f5dc8edf34d7a81864fd23fe52b81399557155d3a6029a69297740aa6b303d781122cc8f6f3d105e6fe084106c06999e3915a3dc9001867fc64bf9950139bdaa7675eb785a0d66f72d8da86df779ea2aa0cf5a38a66c9be9a7a0981f291ce7734cedef300b30fe94c1fce32dcc1b133b7899df43fe5fa909a66b404b68b5c9c4797d2b57eb7271865118227c91e1eed146cd1cf971248393c8764fe47e0f7cd94547570550d389ca18b9fc687d2b041db5e9fa081ce0a70050635e85a583598a47559b5e63dc3b68b9dd83fd27ced0ecfe0bca3d68b62f5d6e53ea238293a61cebb82b126d6efbba214758fc111e41b1b5a7fc14906ee8d4f0f0297803fcc0873fa3da36e4b403ba5138234bff12f47a4575c29ea755560c9e7835eef73380d7bd01b017b1a6b3780dceaec0aa23e2dd0be5ce43c892280521d43c2aae7a6518437483cddc70056816c58ef3406613765dd65b0ffb9f4a3c5085efe46035917825b07027b5fee4200f5a32ca402c039ea49ccbef48d5d0267ce5e25a539a5f937f3e14c683461438a94d09149ed53212b1b29053da475cf1076effe106293b67b120e85a8d2860e23cca9f1afe3a86dd493aa116d8415efab8bd7f2bf119870c3ad62ac9594f876d614b405c7affa71612955d0744661245bb62d9c29d12f912b3ff24d0caa39d9c0872a468a721f9767dd7bfcf40ca79a0815cb11e3ff89b13141c04ffcf2ccafd74b5588e37de8a46513b8033a6f9072f456e395d8094f0b459481ebcc4fc6c6df38238ae864ee52a598486718cc9a16d98b1832b10a11cd3efa4215a9845b35c414ee374a0cd672c954b36628e0cabb55e3159e92152304b19921d542e5f36368ed4256fb12ebccb8a83607efc577295640d5e401d177bd23dca0bc44ac46d834a40620e43b0431f06723bc462aac4758673e61c523b72e6d3d5e96973dadf5a5e170aa65c10a3888783cc15644c49b757d8b22e6c046f3a45e7b8b950d7f0cb76ed0ca041812d8146296665a3a39d80971801821aa9f6cc0f12c8d9b70b8462746a27ecb007e60da22519b710416704d23a5338b8ac551867a9d771f4f51ff83646068a3f597ea4cd3eb72ae736b6abcd2fc0de50381dea58c4d4479384495e79b2a80707bd7671dbeb1050edb2fdbde2a168d4b5b4cf226e0d277b0358ca7d1aae01cd34d08d72e604ad901ced89e84323d85054b9ed19390f1cc94ee09d390796bc3edaead0f7f14d10b1ca4ad6078f62631664c698cf89afd202859243abf4b345d115f14edf1696f91e73436db9426c84c9949a2f8a72806c5260fcf374153cbb832b03990bb3429d725390ca253b0b5349e42045832c6bd"),
            0x2007ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
               
        // genesis - old daemon way
        /*        
        const char* pszTimestamp = "BitcoinZ2beeec1ef52fd18475953563ebdb287f056453f452200581f958711118e980b2";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 4;
        genesis.nTime    = 1550490600;
        genesis.nBits    = 0x2007ffff;
        genesis.nNonce   = uint256S("0x0000000000000000000000000000000000000000000000000000000000000005");
        genesis.nSolution = ParseHex("002472eeef9ec88bf6487438a82728c6f62cf99da923b87122c5d2cfa39e9649a480d2354f12b3d9ba0e03bb912cffe469a9f8bb60f1b31479228d889c1dd310b8b0afc615e24f8244553cedb2b1e58fdb70c72e0638e07706e96fc3d5ea23c3ad7a64a5517b3630441bfcae10039f87f994161425843db28225cdf42ee40d3685d98711e4bf0492e746926afaae48ac9fe066176ef33dc278931fc804e47e82f03c57bcf79ece050f738f9b9d189777be5553d90c7384c59352716c4b5a3a7f3873326b87bffab673f634220ab572db759617b2a424890fd861185a553aeee2e84e96643a94043e98b34c80238bb33a2fe7354b50917f99a51cf39d1382fd49c2aafc316b7ea483e77f53056fc23dfbf925e75bb96213d0a69eff13ee7cf8d1be24fdfe912e1f62ec5502172fbfa19cc46002432979b3daf92d62327bee131e98834f87341aafbe61a7ab1ffffc78920189e60afadb327ff192fab9d0fccc2f88953d95d10eafc9ff0b49b52567cba61aec55f8da9c14b8a6970a411a2f5dc8edf34d7a81864fd23fe52b81399557155d3a6029a69297740aa6b303d781122cc8f6f3d105e6fe084106c06999e3915a3dc9001867fc64bf9950139bdaa7675eb785a0d66f72d8da86df779ea2aa0cf5a38a66c9be9a7a0981f291ce7734cedef300b30fe94c1fce32dcc1b133b7899df43fe5fa909a66b404b68b5c9c4797d2b57eb7271865118227c91e1eed146cd1cf971248393c8764fe47e0f7cd94547570550d389ca18b9fc687d2b041db5e9fa081ce0a70050635e85a583598a47559b5e63dc3b68b9dd83fd27ced0ecfe0bca3d68b62f5d6e53ea238293a61cebb82b126d6efbba214758fc111e41b1b5a7fc14906ee8d4f0f0297803fcc0873fa3da36e4b403ba5138234bff12f47a4575c29ea755560c9e7835eef73380d7bd01b017b1a6b3780dceaec0aa23e2dd0be5ce43c892280521d43c2aae7a6518437483cddc70056816c58ef3406613765dd65b0ffb9f4a3c5085efe46035917825b07027b5fee4200f5a32ca402c039ea49ccbef48d5d0267ce5e25a539a5f937f3e14c683461438a94d09149ed53212b1b29053da475cf1076effe106293b67b120e85a8d2860e23cca9f1afe3a86dd493aa116d8415efab8bd7f2bf119870c3ad62ac9594f876d614b405c7affa71612955d0744661245bb62d9c29d12f912b3ff24d0caa39d9c0872a468a721f9767dd7bfcf40ca79a0815cb11e3ff89b13141c04ffcf2ccafd74b5588e37de8a46513b8033a6f9072f456e395d8094f0b459481ebcc4fc6c6df38238ae864ee52a598486718cc9a16d98b1832b10a11cd3efa4215a9845b35c414ee374a0cd672c954b36628e0cabb55e3159e92152304b19921d542e5f36368ed4256fb12ebccb8a83607efc577295640d5e401d177bd23dca0bc44ac46d834a40620e43b0431f06723bc462aac4758673e61c523b72e6d3d5e96973dadf5a5e170aa65c10a3888783cc15644c49b757d8b22e6c046f3a45e7b8b950d7f0cb76ed0ca041812d8146296665a3a39d80971801821aa9f6cc0f12c8d9b70b8462746a27ecb007e60da22519b710416704d23a5338b8ac551867a9d771f4f51ff83646068a3f597ea4cd3eb72ae736b6abcd2fc0de50381dea58c4d4479384495e79b2a80707bd7671dbeb1050edb2fdbde2a168d4b5b4cf226e0d277b0358ca7d1aae01cd34d08d72e604ad901ced89e84323d85054b9ed19390f1cc94ee09d390796bc3edaead0f7f14d10b1ca4ad6078f62631664c698cf89afd202859243abf4b345d115f14edf1696f91e73436db9426c84c9949a2f8a72806c5260fcf374153cbb832b03990bb3429d725390ca253b0b5349e42045832c6bd");
        consensus.hashGenesisBlock = genesis.GetHash();
		*/
		
        assert(consensus.hashGenesisBlock == uint256S("0x03104faa85339763e81d5489c23325b536161fa2b47437c2f6b1b75b48c0d848"));
        assert(genesis.hashMerkleRoot == uint256S("0xf40283d893eb46b35379a404cf06bd58c22ce05b32a4a641adec56e0792789ad"));
     
        LogPrintf("TESTNET\n");
        LogPrintf("consensus.hashGenesisBlock=%s\n", consensus.hashGenesisBlock.GetHex());
        LogPrintf("genesis.hashMerkleRoot=%s\n", genesis.hashMerkleRoot.GetHex());
        LogPrintf("genesis.nTime=%is\n", genesis.nTime);
        
		vFixedSeeds.clear();
		vSeeds.clear();
		// vSeeds.push_back(CDNSSeedData("44e5b404748cfd46fcfe1d4db145a4d7e742cd6eb343cb50431e0d2895bf5384.TBZE", "testnetseed.bzedge.org")); // original testnet
		//vSeeds.push_back(CDNSSeedData("rotorproject.org", "test-dnsseed.rotorproject.org")); // Zclassic

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


		checkpointData = (CCheckpointData) {
			boost::assign::map_list_of
			( 0, consensus.hashGenesisBlock),
			genesis.nTime,
			0,
			0
		};

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 175007;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 175007;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 175013;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 175016;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

		consensus.fPowNoRetargeting=true;
		consensus.nLWMAHeight=-1;
		consensus.nPowLwmaTargetSpacing = 1 * 60;
		consensus.nZawyLwmaAveragingWindow = 75;  //N=75 recommended by Zawy
		consensus.nZawyLwmaAdjustedWeight = 2280;
		consensus.nZawyLwmaMinDenominator = 10;
		consensus.fZawyLwmaSolvetimeLimitation = true;
		consensus.ZCnPowTargetSpacing = 2.5 * 60;

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 11990;
        nPruneAfterHeight = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

		eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_1_endblock = 1;
        eh_epoch_2_startblock = 1;
        
        bze_pers_start_blocktime = 1550581200; // Tuesday, February 19, 2019 1:00:00 PM

        genesis = CreateGenesisBlock(
            1482971059,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("05ffd6ad016271ade20cfce093959c3addb2079629f9f123c52ef920caa316531af5af3f"),
            0x200f0f0f, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a"));
       
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

		checkpointData = (CCheckpointData){
			boost::assign::map_list_of
			( 0, uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a")),
			0,
			0,
			0
		};
		
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list
    if(blockheight>=params.eh_epoch_2_start() && blockheight>params.eh_epoch_1_end()){
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }
    if(blockheight<params.eh_epoch_2_start()){
        ehparams[0]=params.eh_epoch_1_params();
        return 1;
    }
    ehparams[0]=params.eh_epoch_2_params();
    ehparams[1]=params.eh_epoch_1_params();
    return 2;
}
