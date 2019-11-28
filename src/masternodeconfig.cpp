// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2017-2018 The SnowGem developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// clang-format off
#include "net.h"
#include "masternodeconfig.h"
#include "util.h"
#include "ui_interface.h"
#include "chainparamsbase.h"
#include <base58.h>
// clang-format on

#include <boost/algorithm/string.hpp>

CMasternodeConfig masternodeConfig;

void CMasternodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex)
{
    CMasternodeEntry cme(alias, ip, privKey, txHash, outputIndex);
    entries.push_back(cme);
}

bool CMasternodeConfig::read(std::string& strErr)
{
    int linenumber = 1;
//    boost::filesystem::ifstream streamConfig(GetMasternodeConfigFile());

    std::fstream streamConfig (GetMasternodeConfigFile().string().c_str());

    if (!streamConfig.good()) {
        FILE* configFile = fopen(GetMasternodeConfigFile().string().c_str(), "a");
        if (configFile != NULL) {
            std::string strHeader = "# Masternode config file\n"
                                    "# Format: alias IP:port masternodeprivkey collateral_output_txid collateral_output_index\n"
                                    "# Example: mn1 127.0.0.2:51474 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 0\n";
            fwrite(strHeader.c_str(), std::strlen(strHeader.c_str()), 1, configFile);
            fclose(configFile);
        }
        strErr= "file does not exist";
        return true; // Nothing to read, so just return
    }
    else{
     	if (streamConfig.is_open()){

			while (streamConfig.good()){
								
				std::string line;
				getline (streamConfig,line);

				if (line.empty()) continue;

				std::istringstream iss(line);
				std::string tmp;

				if (iss >> tmp) {
					if (tmp.at(0) == '#') continue;
					iss.str(line);
					iss.clear();
				}

				std::vector<std::string> strs;
				boost::split(strs, line, boost::is_any_of(" "));
				LogPrintf("read Entry %s \n", strs[0]);

				int port = 0;
				std::string hostname = "";
				SplitHostPort(strs[1], port, hostname);

				if (NetworkIdFromCommandLine() == CBaseChainParams::MAIN) {
					if (port != 1990) {
						strErr = _("Invalid port detected in masternode.conf") + "\n" +
								 strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
								 _("(must be 1990 for mainnet)");
						streamConfig.close();
						return false;
					}
				} else if (port == 1990) {
					strErr = _("Invalid port detected in masternode.conf") + "\n" +
							 strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
							 _("(1990 could be used only on mainnet)");
					streamConfig.close();
					return false;
				}
				add(strs[0], strs[1], strs[2], strs[3], strs[4]);
			}
        }
    }

    streamConfig.close();
    return true;
}

bool CMasternodeEntry::castOutputIndex(int &n) const
{
    try {
        n = std::stoi(outputIndex);
    } catch (const std::exception e) {
        LogPrintf("%s: %s on getOutputIndex\n", __func__, e.what());
        return false;
    }

    return true;
}

void CMasternodeConfig::addEntries(std::string& strErr){

    try {
        read(strErr);
    } catch (const std::exception e) {
        LogPrintf("%s: %s on getEntries \n", __func__, e.what());
    }
}

std::vector<CMasternodeEntry> CMasternodeConfig::getEntries(std::string& strErr)
{
	return entries;
}

int CMasternodeConfig::getCount()
{
	int c = -1;
	BOOST_FOREACH (CMasternodeEntry e, entries) {
		if (e.getAlias() != "") c++;
	}
	return c;
}

const std::string& CMasternodeEntry::getAlias() const
{
	return alias;
}

void CMasternodeEntry::setAlias(std::string& alias) const
{
	alias = alias;
}

const std::string& CMasternodeEntry::getOutputIndex() const
{
	return outputIndex;
}

void CMasternodeEntry::setOutputIndex(std::string& outputIndex) const
{
	outputIndex = outputIndex;
}

const std::string& CMasternodeEntry::getPrivKey() const
{
	return privKey;
}

void CMasternodeEntry::setPrivKey(std::string& privKey) const
{
	privKey = privKey;
}

const std::string& CMasternodeEntry::getTxHash() const
{
	return txHash;
}

void CMasternodeEntry::setTxHash(std::string& txHash) const
{
	txHash = txHash;
}

const std::string& CMasternodeEntry::getIp() const
{
	return ip;
}

void CMasternodeEntry::setIp(std::string& ip) const
{
	ip = ip;
}
