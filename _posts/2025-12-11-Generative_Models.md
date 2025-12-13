---
title: "Generative Models "
date : 2025-12-11 00:00:00 +0900
categories: [DeepLearning, basic,]
tags : [DeepLearning, Generative , Discriminative , GANs , VAEs, ]
---



## Generative Models

Generative Model은 생성모델 즉 확률밀도함수(PDF)를 기반으로 데이터를 학습하여 새로은 유사한 데이터를 생성할수있는 머신러닝 모델이다.
학습 데이터의 분포를 학습하여 새로운 샘플을 최대한 유사하게 만드는게 목표이다.

            Discriminative Model Vs Generative Model
    
학습내용 :  P(Y|X) - 조건부 확률     P(X,Y) - 결합 확률
목적 :      분류(Classification)    생성(Generation)


### Probability Density Function (PDF) 학습

ex) 
사과 데이터 10000개 조사:
- Greenish : 3700
- Reddish : 6000
- Blueish : 300

PDF:
- P(G) = 3700/10000 = 0.37
- P(R) = 6000/10000 = 0.60
- P(B) = 300/10000 = 0.03

확률분포를 따라 빨간색 사과(R)가 주어질 확률이 높으므로 빨간색 사과를 생성할 가능성이 높다.

사과같은 단순한 이미지가 아닌 실제 딥러닝의 문제, 예를 들어 사람의 얼굴 이미지를 생성하는 경우는 문제가 더 복잡해진다.
x,y 64pixel의 흑백 이미지라고 하더라도 0~255사이의 값을 가질 수 있다면 가능한 이미지의 경우의 수는 256^(64*64)라는 너무 큰 숫자가 된다. 이 거대한 차원의 공간에서 사람의 얼굴의 픽셀조합은 극히 일부에 불과하다.

생성모델은 이 고차원의 공간에서 데이터가 밀집해 있는 영역을 찾아내고 그 영역에 높은 확률을 부여하는 함수를 학습한다.
학습이 잘 된다면 노이즈 처럼 보이는 이미지에는 0에 가까운 확률을, 사람 얼굴 같은 이미지에는 높은 확률을 할당한다. 그 높은 확률을 가진 영역에서 값을 sampling하면 우리는 실제와 구별하기 힘든 생성된 이미지를 얻게된다.

### Latent Space

Latent Space?
- 신경망을 통해 학습된 Hidden Layer의 상태
- 데이터의 압축된 표현을 담고있는 저차원의 공간
- 확률밀도함수를 통해 어떤 상태가 발생할지 결정
으로 정리할수있다.

작동원리 : 
1, Hidden Layer -> 확률밀도함수(PDF)를 통해 샘플링
2, 샘플링된 상태 -> Generative Path를 통해 이미지 생성
3, 확률 높은 상태 -> 자주 생성됨

열역학 제 2법칙의 엔트로피 증가법칙이 떠오른다.
현실에서도 변화는 엔트로피가 높은 상태 즉 확률이 높은 상태로의 변화가 더 많이 일어나는것처럼 PDF도 가장 높은 확률의 상태를 생성해냄.

## latent Vector 