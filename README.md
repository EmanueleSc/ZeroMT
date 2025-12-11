# *ZeroMT* "Zero-knowledge Multi-Transfer" Research
[`ZeroMT`](https://www.sciencedirect.com/science/article/pii/S2214212624000978) is a research project that investigates the problem of privacy in public blockchains such as Ethereum. Because transaction information is visible to the entire network, public blockchains are unsuitable for use cases where confidentiality is required.

The *ZeroMT* project began by reviewing the state-of-the-art literature on *confidential transactions*, including Zerocash, Monero, Quisquis, Zether, and others, and highlighted that the most promising approaches rely on zero-knowledge proofs of transaction validity.
In this context, *ZeroMT* identifies key privacy challenges, such as transaction costs, the choice of balance model, and the selection of the zero-knowledge proof system, all of which can significantly affect efficiency and security. 

To address these issues, *ZeroMT* develops a research line aimed at reducing transaction costs and improving the security of privacy-preserving blockchains.
Specifically, *ZeroMT* provides a zero-knowledge cryptographic scheme that leverages proof aggregation to enable batch verification of multiple transfers within a single transaction and without delegation. 

This is achieved by generalizing the [`Zether`](https://eprint.iacr.org/2019/191) proof system, namely $\Sigma$-Bullets, extending its statements to support multiple transfers and payees.
To this end, *ZeroMT* adopts a non-blackbox approach to zero-knowledge proofs: it designs interactive proofs, proves their security properties, and provides security reductions for any privacy-preserving protocol built on *ZeroMT*. 

Moreover, *ZeroMT* employs trustless proof systems, avoiding trapdoors or other sources of trust on-chain. 
Finally, the generalized argument system is incorporated into a high-level multi-transfer scheme that uses a non-interactive version of the proof system.

Further details can be found in the [`research paper`](https://www.sciencedirect.com/science/article/pii/S2214212624000978).
