

+++
date = '2025-04-13T00:00:00+01:00'
draft = false
description= "This write-up covers the solution of the medium blockchain challenge I created for the Midnight Flag CTF 2025 Quals."
title = '[MidnightFlag CTF 2025 Quals] - Sublocku'
tags = ["Blockchain", "MidnightFlagCTF", "WriteUp"]
+++


| Difficulty | Medium                                                |
| ---------- | ----------------------------------------------------- |
| Author     | [Me](https://discordapp.com/users/406135822178320390) |

## 📝 Challenge's description

To get the flag, unlock the vault ! But, wait ? Where is the grid ?
## 🔍 Steps

1. 🔢 Retrieve the grid size
2. 🕹️ Retrieve the grid
3. 🏁 Solve the sudoku

## 📃 Given file 

`Sublocku.sol`
```js
// Author : Neoreo
// Difficulty : Medium

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract Sublocku {

    uint private size;
    uint256[][] private game;
    bool public isSolved = false;

    address public owner;
    address public lastSolver;


    constructor(uint256 _size,uint256[][] memory initialGrid) {
        owner = msg.sender;
        size = _size;
        require(initialGrid.length == size, "Grid cannot be empty");
        for (uint i = 0; i < size; i++) {
            require(initialGrid[i].length == size, "Each row must have the same length as the grid");
        }
        game = initialGrid;
    }


    function unlock(uint256[][] memory solve) public {

        require(solve.length == size, "Solution grid size mismatch");
        for (uint i = 0; i < size; i++) {
            require(solve[i].length == size, "Solution grid row size mismatch");
        }

        for (uint i = 0; i < size; i++) {
            for (uint j = 0; j < size; j++) {
                if (game[i][j] != 0) {
                    require(game[i][j] == solve[i][j], "Cannot modify initial non-zero values");
                }
            }
        }

        require(checkRows(solve),    "Row validation failed");
        require(checkColumns(solve), "Column validation failed");
        require(checkSquares(solve), "Square validation failed");
        lastSolver = tx.origin;
    }

    function checkRows(uint256[][] memory solve) private view returns (bool){
        uint256[] memory available;
        uint256 val;
        for (uint i = 0; i < size; i++) {
            available = values();
            for (uint j = 0; j < size; j++) {
                val = solve[i][j];
                if (val <= 0 || val > size){
                    return false;
                }   
                if (available[val-1] == 0){
                    return false;
                }
                available[val-1] = 0;
            }
            if (sum(available) != 0) {
                return false;
            }
        }
        return true;
    }


    function checkColumns(uint256[][] memory solve) private view returns (bool){
        uint256[] memory available;
        uint256 val;
        for (uint i = 0; i < size; i++) {
            available = values();
            for (uint j = 0; j < size; j++) {
                val = solve[j][i];
                if (val <= 0 || val > 9){
                    return false;
                }   
                if (available[val-1] == 0){
                    return false;
                }
                available[val-1] = 0;
            }

            if (sum(available) != 0) {
                return false;
            }
        }
        return true;
    }

    function checkSquares(uint256[][] memory solve) private view returns (bool) {
        uint256[] memory available;
        uint256 val;

        for (uint startRow = 0; startRow < size; startRow += 3) {
            for (uint startCol = 0; startCol < size; startCol += 3) {
                available = values();

                for (uint i = 0; i < 3; i++) {
                    for (uint j = 0; j < 3; j++) {
                        val = solve[startRow + i][startCol + j];
                        if (val <= 0 || val > 9) {
                            return false;
                        }
                        if (available[val-1] == 0) {
                            return false;
                        }
                        available[val-1] = 0;
                    }
                }

                if (sum(available) != 0) {
                    return false;
                }
            }
        }
        return true;
    }


    function values() internal pure returns (uint256[] memory){
        uint256[] memory available_values = new uint256[](9);
        available_values[0] = uint256(1);
        available_values[1] = uint256(2);
        available_values[2] = uint256(3);
        available_values[3] = uint256(4);
        available_values[4] = uint256(5);
        available_values[5] = uint256(6);
        available_values[6] = uint256(7);
        available_values[7] = uint256(8);
        available_values[8] = uint256(9);
        return available_values;
    }

    function sum(uint256[] memory array) internal pure returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < array.length; i++) {
            total += array[i];
        }
        return total;
    }
}
    
```

The challenge's contract is quite long but, in reality, nothing much interesting.   
The only callable functions are `unlock()`.  
Other functions are only used to check that the sudoku grid is valid.  

## 🔢 Step 1 : Retrieve the grid size

As we can see in the different functions (e.g. `values()`) we can admit that the sudoku grid is `9*9`.
To verify that, we can retrieve the storage layout and query the right slot.

```bash
forge inspect Sublocku.sol storage
```

```bash
╭----------------+-------------+------+--------+-------+-----------------------╮
| Name           | Type        | Slot | Offset | Bytes | Contract              |
+==============================================================================+
| size           | uint256     | 0    | 0      | 32    | Sublocku.sol:Sublocku |
|----------------+-------------+------+--------+-------+-----------------------|
| game           | uint256[][] | 1    | 0      | 32    | Sublocku.sol:Sublocku |
|----------------+-------------+------+--------+-------+-----------------------|
| isSolved       | bool        | 2    | 0      | 1     | Sublocku.sol:Sublocku |
|----------------+-------------+------+--------+-------+-----------------------|
| failed_forever | bool        | 2    | 1      | 1     | Sublocku.sol:Sublocku |
╰----------------+-------------+------+--------+-------+-----------------------╯
```

The `size` variable is stored in the `slot 0`. Let's make sure its value is `9`.

```bash
export TARGET=0x684c663485c2F43473c65C2C12A33Cb2CF85B0AB
export RPC=http://localhost/rpc

cast storage $TARGET 0 -r $RPC
```

```python
0x0000000000000000000000000000000000000000000000000000000000000009
```

Yay ! It's `9`.

## 🕹️ Step 2 : Retrieve the grid

The second step is to retrieve the grid.   
The problem ? **The grid is private**.

But, you probably know that everything is public on the blockchain, even `private` variables.
So, we must be able to call the storage to retrieve the grid.

Another problem comes towards us...
The game doesn't use static arrays but dynamic arrays and **THAT CHANGES ALL**.

> In the EVM, static arrays items are stored from slot `n`, to slot `n+i` where `n` is the slot of the array in the storage and `i` is the `i`-th element of the array. 
> This is easy to recover but dynamic arrays can't do that. 
> In fact, if the EVM uses the same method to store dynamic array, it would probably result in overflowing other variables. 
> So the EVM uses another method.

**How are dynamic arrays stored in the EVM**
1. The array length is stored in a 32 bytes slot. In our case, slot `1`.
2. Element at index 0 is stored in the slot `keccak(slot)`
3. Element at index 1 is stored at `keccak(slot)+1`
4. and so on...

In the current challenge, the grid type is `uint256[][]` and that means it's a 2D dynamic array. The challmaker must be a devil. 

How do we retrieve all variables ? Let's resume :

```js
grid[0][0] = keccak(keccak(slot))
grid[0][1] = keccak(keccak(slot)) + 1
grid[0][1] = keccak(keccak(slot)) + 2
...
grid[1][0] = keccak(keccak(slot) + 1)
...
grid[6][5] = keccak(keccak(slot) + 6) + 5
```

Based on that, I wrote the following python script using `web3py` which is much more efficient than `foundry` when it comes to scripting.

```python
########################
# INITIATE THE CONTEXT #
########################
from web3 import Web3, AsyncWeb3
from solcx import compile_source, install_solc

RPC_URL = "http://localhost/rpc"

user_infos = {
    "PrivateKey": "0xca11ab1ec0ffee000002a575fa5f74540719ba065a610cba6497cdbf22cd5cdb",
    "TargetAddress": "0x684c663485c2F43473c65C2C12A33Cb2CF85B0AB"
}

# Make sure the RPC is reachable
w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected(), "Not connected to the blockchain"

# Connect our account to the RPC
account = w3.eth.account.from_key(user_infos['PrivateKey'])
print(f"Account: {account.address}")
print(f"Balance: {Web3.from_wei(w3.eth.get_balance(account.address),'ether')}")
nonce = w3.eth.get_transaction_count(account.address)

# Extract the contract source code
with open('dst/Sublocku.sol','r') as f : 
    source_code = f.read() 

# Install the compiler
install_solc('0.8.26')

# Compile the contract to retrieve its abi
compiled_sol = compile_source(source_code, solc_version='0.8.26')  
print(f"Compiled classes : {compiled_sol.keys()}")

# Load the target contract
sublocku_contract = w3.eth.contract(address=user_infos['TargetAddress'], abi=compiled_sol['<stdin>:Sublocku']['abi'])
print(f"Contract: {sublocku_contract.all_functions()}")

#################################
# EXTRACT THE GRID FROM STORAGE #
#################################

def getGameState() :
    game = []

    # The slot index containing the array length (should be 32bytes long, in hex, with no 0x and as a string)
    slot_row = "0000000000000000000000000000000000000000000000000000000000000001" # Slot 1

	# new_slot_row = keccak(slot) = grid[0]
    new_slot_row = w3.keccak(hexstr=slot_row)

	# Let's iterate through each row = grid[row_id]
    for row_id in range(9) : 
        game.append([])

		# For each row, slot_col = grid[row_id] = keccak(slot) + row_id
        tmp_key_row = int(new_slot_row.hex(), 16)+row_id
        game_col_number = w3.eth.get_storage_at(sublocku_contract.address, tmp_key_row)        
        slot_col = hex(tmp_key_row)[2:]

		# For each row, new_slot_col = grid[row_id][0] = keccak(keccak(slot) + row_id)
        new_slot_col = w3.keccak(hexstr=slot_col)

		# We can then iterate through all 9 values of each row
        for col_id in range(9) :

			# For each value, tmp_key_col = grid[row_id][col_id] = keccak(keccak(slot) + row_id) + col_id
            tmp_key_col = int(new_slot_col.hex(), 16) + col_id

			# Retrieve the value in the storage
            storage_value = w3.eth.get_storage_at(sublocku_contract.address, tmp_key_col)

			# Add the value to the grid
            game[row_id].append(int(storage_value.hex(),16))
    return game

game = getGameState()

# Print the grid
for line in game : 
    print(line)
```

```python
[3, 1, 7, 4, 9, 5, 0, 8, 2]
[9, 2, 6, 3, 1, 8, 7, 5, 4]
[5, 4, 8, 7, 2, 6, 3, 1, 9]
[4, 3, 1, 8, 0, 7, 9, 2, 6]
[6, 9, 2, 1, 3, 4, 8, 7, 5]
[8, 7, 5, 9, 6, 2, 4, 3, 1]
[7, 8, 9, 5, 4, 1, 2, 6, 3]
[1, 0, 4, 2, 8, 0, 5, 9, 7]
[2, 5, 3, 6, 7, 9, 1, 4, 8]
```

At this point, you should notice that the grid is almost complete. Let's check empty slots by appending the following script to our script.

```python
for row_id,row in enumerate(game) : 
    for item_id,item in enumerate(row) :
        if item == 0 : 
            print(f"Missing value at {row_id,item_id}") 
```

```bash
Missing value at (0, 6)
Missing value at (3, 4)
Missing value at (7, 1)
Missing value at (7, 5)
```

# 🏁 Step 3 : Solve the sudoku

We know that 4 values are missing from the grid. We can easily solve this sudoku without any solver and call `setValue()` to solve the grid. 
Be careful, make a mistake once and the sudoku will be locked forever.
We can continue using `foundry` to solve that sudoku and the challenge.

```bash
export TARGET=0x684c663485c2F43473c65C2C12A33Cb2CF85B0AB
export RPC=http://localhost/rpc
export PK=0xca11ab1ec0ffee000002a575fa5f74540719ba065a610cba6497cdbf22cd5cdb

cast send $TARGET "setValue(uint256,uint256,uint256)" 0 6 6 -r $RPC --private-key $PK
cast send $TARGET "setValue(uint256,uint256,uint256)" 3 4 5 -r $RPC --private-key $PK
cast send $TARGET "setValue(uint256,uint256,uint256)" 7 1 6 -r $RPC --private-key $PK
cast send $TARGET "setValue(uint256,uint256,uint256)" 7 5 3 -r $RPC --private-key $PK
cast send $TARGET "unlock()" -r $RPC --private-key $PK
```

**Challenge solved**
Flag : `MCTF{2f5c0a0afcae1a1c5c0eadc25345f2f3}`
