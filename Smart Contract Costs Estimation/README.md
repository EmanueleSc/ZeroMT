# Smart Contract Costs Estimation
The verifier side of the theoretical ZeroMT protocol runs in a smart contract - i.e. the *MTSC* - within a blockchain platform that supports it such as *Ethereum*. 
In *Ethereum* each smart contract code execution requires an amount of gas to be fulfilled. The exact amount of gas that is required depends on what is carried out from the smart contract in terms of computation. Given a theoretical protocol to be implemented in an *Ethereum* smart contract, knowing in advance its costs in terms of the gas amount required for the execution of its functions is crucial. Following a gas cost estimation for a protocol, it might rise the conclusion that such protocol implementation is unfeasible as too demanding in terms of gas costs.

The *Ethereum* yellow paper provides a value in terms of gas consumption for each mathematical operation that can be carried out natively, such as adding two numbers together. The operations that are supported by the elliptic curve of choice BN-254 are supported in *Ethereum* thanks to the proposal of dedicated precompiled smart contracts in the *Ethereum Improvement Proposal 196*. Included in the *EIP* there are the costs for the arithmetic operations supported by the elliptic curve arithmetic - i.e. addition between points and multiplication between a point and a scalar. Such costs have been successively reduced in many *Ethereum* hard forks, such as Istanbul, with the adoption of the *EIP-1108*. This last EIP proposed a reduction in terms of gas utilization for the elliptic curve operations that are carried out in precompiled contracts.

| Mnemonic | Type                                  | Gas per execution                                        |
| -------- | ------------------------------------- | -------------------------------------------------------- |
| `ADD`    | Scalar addition                       | $3$                                                      |
| `SUB`    | Scalar subtraction                    | $3$                                                      |
| `MUL`    | Scalar multiplication                 | $5$                                                      |
| `DIV`    | Scalar division                       | $5$                                                      |
| `EXP`    | Scalar exponentiation                 | $(exp == 0) ? 10 : (10 + 10 \cdot (1 + log_{256}(exp)))$ |
| `ECADD`  | Curve point addition                  | $500$ (*EIP-196*) - $150$ (*EIP-1108*)                   |
| `ECMUL`  | Curve point and scalar multiplication | $40,000$ (*EIP-196*) - $6,000$ (*EIP-1108*)              |
