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

# *ZeroMT+*: Towards scalable privacy in account-model blockchain
The [`Ph.D. thesis`](https://tesidottorato.depositolegale.it/bitstream/20.500.14242/210668/1/07_19_24%20-%20Scala%20Emanuele.pdf) provides the in-depth math background behind the zero-knowledge proofs, such as elliptic curve groups, cryptographic assumptions, interactive proofs, homomorphic cryptosystems, computational security notions and so on. 

The thesis outlines that verifying trustless zero-knowledge proofs on-chain is expensive and identifies the component responsible for the high verification cost, that is the *Inner-Product Argument* (IPA). Building on that claim, *ZeroMT+* improves the zero-knowledge proofs time complexity and reduces transaction costs of ZeroMT. 

*ZeroMT+* achieves these gains by reducing, within the IPA, the number of exponentiations by a linear factor and the number of finite-field inversions by a logarithmic factor, both as a function of the witness size. ZeroMT+ also provides security proofs of the zero-knowledge properties for the modified IPA under standard assumptions.

The new version of the IPA is implemented in the [`inner_sigma`](https://github.com/EmanueleSc/ZeroMT/tree/main/Proof%20System%20Implementation/src/inner_sigma) module, and benchmarks can be run using the related [`tests`](https://github.com/EmanueleSc/ZeroMT/blob/main/Proof%20System%20Implementation/tests/inner_sigma_tests.rs). These concrete evaluations confirm the theoretical advantages first outlined in the [conference paper](https://moneroresearch.info/index.php?action=resource_RESOURCEVIEW_CORE&id=221&list=1&highlight=1).

!!! A new paper on *ZeroMT+*, an extension of the above conference work, is COMING SOON and will be published in the *BCRA* journal. !!!
