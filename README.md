
<img width="120" height="80" src="doc/imgs/logo.png">
BZEdge Transylvanian Oak 2.0.3
Checkout latest releases here: https://github.com/bze-alphateam/bzedge/releases


# BZEdge
**Keep running wallet to strengthen the BZEdge network. Backup your wallet in many locations & keep your coins wallet offline. Copy your BitcoinZ walet into BZEdge folder. BitcoinZ funds before 17 June 2018 will be duplicated on BZEdge. Replay protection: Send entire amount in each transparent address to a new address (including the free 0.1BZE). Those coins will be replay protected. To protect Z funds from replay, send your "protected" coin to the Z address, then the whole balance in one transaction to the next address.**

### Ports:
- RPC port: 1980
- P2P port: 1990

Install
-----------------
### Linux


Get dependencies
```{r, engine='bash'}
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake
```

Install

```{r, engine='bash'}
# Clone BZEdge Repository
git clone https://github.com/bze-alphateam/bzedge
# Build: At the moment building works only without tests. Make sure to disable them.
cd bzedge/
./zcutil/build.sh --disable-tests -j$(nproc)
# fetch key
./zcutil/fetch-params.sh
# Run
./src/bzedged
# Test getting information about the network
cd src/
./bzedge-cli getmininginfo
# Test creating new transparent address
./bzedge-cli getnewaddress
# Test creating new private address
./bzedge-cli z_getnewaddress
# Test checking transparent balance
./bzedge-cli getbalance
# Test checking total balance 
./bzedge-cli z_gettotalbalance
# Check all available wallet commands
./bzedge-cli help
# Get more info about a single wallet command
./bzedge-cli help "The-command-you-want-to-learn-more-about"
./bzedge-cli help "getbalance"
```

Security Warnings
-----------------

**BZEdge is experimental and a work-in-progress.** Use at your own risk.


