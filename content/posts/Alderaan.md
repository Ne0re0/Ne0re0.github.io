
+++
date = '2025-04-13T00:00:00+01:00'
draft = false
description= "This write-up covers the solution of the easy blockchain challenge I created for the Midnight Flag CTF 2025 Quals."
title = '[MidnightFlag CTF 2025 Quals] - Alderaan'
tags = ["Blockchain", "MidnightFlagCTF", "WriteUp"]
+++


| Difficulty | Easy                                                  |
| ---------- | ----------------------------------------------------- |
| Author     | [Me](https://discordapp.com/users/406135822178320390) |
## 📝 Challenge's description

Welcome to the Midnight Flag 2025 Web3 category !
To solve this challenge, destroy it !

## 🔍 Steps

1. 📃 Read the given file
2. ☎️ Call the challenge's contract

## 📃 Step 1 : Read the given file 

`Alderaan.sol`
```js
// Author : Neoreo
// Difficulty : Easy

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract Alderaan {
    event AlderaanDestroyed(address indexed destroyer, uint256 amount);
    bool public isSolved = false;

    constructor() payable{
        require(msg.value > 0,"Contract require some ETH !");
    }

    function DestroyAlderaan(string memory _key) public payable {
        require(msg.value > 0, "Hey, send me some ETH !");
        require(
            keccak256(abi.encodePacked(_key)) == keccak256(abi.encodePacked("ObiWanCantSaveAlderaan")),
            "Incorrect key"
        );

        emit AlderaanDestroyed(msg.sender, address(this).balance);

        isSolved = true;
        selfdestruct(payable(msg.sender));
    }
}
```

Basically, this is the challenge's contract. As we can see, the goal is to set the variable `isSolved` to `true`. The only way to do so is to call `DestroyAlderaan(string)`. 
There are two checks :
- `msg.value > 0` which means that we have to send `at least 1 wei` (Basically, 1ETH is 10^18 wei, the wei is the smallest part of ETH existing)
- The `_key` should be `ObiWanCantSaveAlderaan`

## ☎️ Step 2 : Call the contract 

There are many ways to call a contract. I personally use `Foundry`.

**Install foundry**
```bash
curl -L https://foundry.paradigm.xyz | bash
bash # or zsh depending on your terminal
foundryup
# cast, anvil, forge and chisel commands should be installed now
```

**Call the contract**
```bash
# Let's export those variables so the call is more readable
export TARGET=0x446B01dc71D719804bf25D087A45417214265748
export RPC=http://localhost/rpc
export PK=0xca11ab1ec0ffee000002a575fa5f74540719ba065a610cba6497cdbf22cd5cdb

# Do the call with cast command from foundry
cast send $TARGET "DestroyAlderaan(string)" "ObiWanCantSaveAlderaan"  -r $RPC --private-key $PK --value 1
```

**Here is what the `cast send` command do in details**
1. We call the `DestroyAlderaan()` function from the `$TARGET` contract.  
2. This function takes a string as input, so we actually call `DestroyAlderaan(string)`.  
3. Then, we provide the actual string value.  
4. The `RPC` is mandatory as it serves as the "address" of the blockchain.  
5. Since the call modifies variables on the blockchain, we must provide our private key for identification purpose.  
6. Finally, we send `1 wei` (which is `1/10^18` ETH) to successfully pass the check.  


**Challenge solved**  
Flag : `MCTF{61aa43af25584bb0c06b8be04aa8aa3a}`



