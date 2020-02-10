// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2017-2018 The SnowGem developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SRC_MASTERNODECONFIG_H_
#define SRC_MASTERNODECONFIG_H_

#include <string>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

class CMasternodeEntry
{
public:
	std::string alias;
	std::string ip;
	std::string privKey;
	std::string txHash;
	std::string outputIndex;

	CMasternodeEntry(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex);

	const std::string getAlias() const;

	void setAlias(std::string alias) const;

	const std::string getOutputIndex() const;

	bool castOutputIndex(int &n) const;

	void setOutputIndex(std::string outputIndex) const;

	const std::string getPrivKey() const;

	void setPrivKey(std::string privKey) const;

	const std::string getTxHash() const;

	void setTxHash(std::string txHash) const;

	const std::string getIp() const;

	void setIp(std::string ip) const;

    std::string ToString() const;
};

class CMasternodeConfig
{
public:
    std::vector<CMasternodeEntry*> entries;

    CMasternodeConfig()
    {
    }

    void clear();
    bool read(std::string& strErr);
    void add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex);
    
    void addEntries(std::string strErr);

    std::vector<CMasternodeEntry*> getEntries(std::string strErr);

    int getCount();

};

extern CMasternodeConfig masternodeConfig;
#endif /* SRC_MASTERNODECONFIG_H_ */
