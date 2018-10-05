# Stegos Blockchain

Stegos is a completely private, confidential, and scalable cryptocurrency that’s friendly to the environment. Stegos builds and improves upon other privacy coins and can be used to send payments and data with complete confidentiality.

Stegos uses the UTXO (coin) model and PoS (Proof-of-Stake) consensus.

Transactions in Stegos are unlinkable, untraceable, and completely confidential. Stegos makes it impossible to identify recipients of a transaction because transactions are directed to new and unique addresses.

Stegos makes it impossible to trace history of transactions since many individual transactions are joined together to form a super-transaction. This is done in a secure and privacy-preserving way, before submitting the transaction to blockchain validators. Stegos coins are fully fungible!

All amounts in Stegos are hidden using cryptographic commitments and zero-knowledge proofs. Validator stakes and transaction fees are the only exception since these must be visible for blockchain validation.

Many projects claim to be able to process a million transactions per second (TPS) but none of them explain how they are going to maintain all the accumulated data! Bitcoin provides for 7-10 TPS and the Bitcoin blockchain is expected to grow past 170 terabytes by the end of 2018. If we assume that Bitcoin suddenly supports 16,000 TPS, the Bitcoin blockchain will grow by [350 gigabytes every day, or 127 terabytes every year](https://hackernoon.com/if-we-lived-in-a-bitcoin-future-how-big-would-the-blockchain-have-to-be-bd07b282416f). This amount of data is completely unsustainable unless the blockchain will be centralized on a few supercomputers, something that’s contrary to blockchain’s decentralization ethos!

Stegos is a fast and highly scalable blockchain and, unlike other blockchains, it’s kept small. Spent coins and consumed data are safely removed from the blockchain using secure cryptographic pruning. This breakthrough enables Stegos run on billions of mobile devices, for a truly decentralized blockchain. Stegos is the first and only blockchain that can run in your pocket!

Stegos uses transactional sharding to scale. Separate groups of Stegos validators keep the whole blockchain state but verify only a subset of incoming transactions, using cross-shard atomic commits to eliminate double-spending. This scalability approach lets Stegos process hundreds of thousands of transactions per second.

Stegos is friendly to the environment and does not require megawatts of electricity to be spent for mining blocks. Stegos is using PoS (Proof-of-Stake) consensus, building on advancements in distributed systems theory and cryptography. Each new Stegos block must be verified and confirmed by a group of validators, all of which must put tokens in escrow (stake).

The size of the tokens staked has a direct effect on the probability of a validator to win a block and earn transaction fees. Stegos does not have block rewards but replaces them with the *Jackpot*.

This is a feature unique to Stegos and a lottery concept that everyone is familiar with. A portion of the fees from each block are added to the *Jackpot* and any stake forfeited by a validator caught cheating goes into the *Jackpot* as well.

The *Jackpot* is distributed every few thousand blocks when validators run a cryptographic lottery based on verifiable distributed randomness. The amount in the *Jackpot* is then transferred to the winner. The longer a validator keeps its stake and participates in consensus, the higher the probability of winning the *Jackpot* lottery!

## Project Status

Issue tracker is at https://github.com/stegos/stegos/issues.

Project boards are at https://github.com/stegos/stegos/projects.

## Installing from Source

Stegos requires **Rust version 1.29.x** to build.

The recommended way to install Rust it to use [rustup](https://www.rustup.rs/).
If you don't already have `rustup`, you can install it like this:

  ```bash
  $ curl https://sh.rustup.rs -sSf | sh
  ```

Make sure that these binaries are in your `PATH`.
After that, you should be able to build Stegos from the source.

Run `cargo build` to create the main executable:

```bash
# build in release mode
$ cargo build --release
```

This produces `stegos` executable in the `./target/release` subdirectory.

## How To Contribute

We encourage you to contribute in any way you can!

Please see our [CONTRIBUTING GUIDE](https://github.com/stegos/stegos/blob/dev/CONTRIBUTING.md) and [CODE OF CONDUCT](https://github.com/stegos/stegos/blob/readme/CODE_OF_CONDUCT.md) for more information on contributing.


Copyright (c) 2108 Stegos AG
