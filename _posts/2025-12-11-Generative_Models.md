---
title: "Generative Models "
date : 2025-12-11 00:00:00 +0900
categories: [DeepLearning, basic,]
tags : [DeepLearning, Generative , Discriminative , GANs , VAEs, ]
---



## Generative Models

Generative Model은 생성모델 즉 확률밀도함수(PDF)를 기반으로 데이터를 학습하여 새로은 유사한 데이터를 생성할수있는 머신러닝 모델이다.

학습 데이터의 분포를 학습하여 새로운 샘플을 최대한 유사하게 만드는게 목표이다.


![generative model](/assets/img/posts/deep_learning_generative/11-1-1.png)



            Discriminative Model Vs Generative Model
    
    학습내용 :  P(Y|X) - 조건부 확률     P(X,Y) - 결합 확률
    목적 :      분류(Classification)    생성(Generation)


## Probability Density Function (PDF) 학습

ex :
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

학습이 잘 된다면 노이즈 처럼 보이는 이미지에는 0에 가까운 확률을, 사람 얼굴 같은 이미지에는 높은 확률을 할당한다. 

그 높은 확률을 가진 영역에서 값을 sampling하면 우리는 실제와 구별하기 힘든 생성된 이미지를 얻게된다.


![generative model](/assets/img/posts/deep_learning_generative/11-1-2.png)



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

### Latent Vector

우리가 보는 이미지는 픽셀들의 집합이지만 사실 그 이미지를 결정짓는 핵심 요소는 남자인지 여자인지, 안경을 썻는지, 머리 색은 무엇인지등 추상적인 특징이다.

생성 모델은 고차원 입력 데이터를 훨씬 낮은 차원의 벡터 공간인 Latent Space로 압축(Encoding)한다.

이때 Latent Space의 한 점(Vector) z는 생성될 데이터의 청사진과 같다. 
생성자는 이 벡터 z를 입력받아 다시 고차원의 이미지 x로 확장(Decoding)한다.


얼굴 특징 벡터 연산 Ex:
안경 쓴 남자 - 안경 안 쓴 남자 + 안경 안 쓴 여자 = 안경 쓴 여자

![alt text](/assets/img/posts/deep_learning_generative/11-1-3.png)

- Latent Space에서 벡터 연산 가능
- 각 방향이 특정 특징을 나타냄
- 선형 보간(Linear interpolation)으로 중간 상태 생성 가능

응용 : 
- 특정 속성만 변경(안경 추가/제거 , 나이 변화등)
- 부드러운 전환 생성

### Why generative model required(CV)?

급격한 전환(Sharp transition) -> overfitting 문제

해결법으로 
- Latent Space에서 연속적으로 이동(Walking)
- 부드러운 변화 생성
- 중간 상태들도 의미 있는 이미지로 생성
  
  ![alt text](/assets/img/posts/deep_learning_generative/11-1-4.png)

### Advantages

생성모델은 다양한 Computer Vision문제를 해결한다.

1,Colorization 색상복원 
* 흑백 이미지 -> 컬러이미지 
* 노이즈부분을 Hidden Layer가 처리
* 색상 분포를 학습하여 자연스러운 색상 생성
  
2, Image Deblurring (블러 제거)
* 뭉개지거나 흐릿한 이미지 -> 선명한 이미지
* 여러 단계의 블러 제거

3, Suoer-resolution (초해상도)
* 뭉개진 픽셀로부터 고해상도의 디테일을 상상하여 복원
* 텍스처의 분포를 예측해서 생성

4, 3d모델 예측
* 2D 이미지에서 3D 구조를 추정


### Isues 

#### Results are not real

GAN(Generative Adversarial Network)

Generater -> Fake Images -> Discriminator <- Real Images
                         
                          real or fake?


1, 초기단계
* Generator : 랜덤 노이즈 -> 엉망인 가짜 이미지
* Discriminator : 쉽게 구분 가능

2, 중간단계
* Generator 개선 : 조금 더 현실과 비슷한 이미지
* Discriminator : 더 정교하게 구분

3, 최종단계
* Generator : 진짜와 구분 불가능한 이미지
* Discriminator : 구분불가 (D(x) = 1/2 , 동전 던지기와 같음)

![alt text](/assets/img/posts/deep_learning_generative/11-1-5.png)

파란색 점선 = Discriminative 분포 (p_x)
검은색 점 = Generator 분포 (p_g)
초록색 실선 = Generative 분포
최종적으로: p_g = p_x (진짜와 가짜 구분 불가)


#### DeepFake

![alt text](/assets/img/posts/deep_learning_generative/11-1-6.png)

원리
* 원본 영상의 얼굴인식 
* 타겟 인물의 얼굴 데이터로 학습
* 원본 얼굴을 타겟 얼굴로 자연스럽게 대체

문제점
* 허위 정보 유포
* 개인의 명예훼손
* 정치적 악용


## Restricted Boltzmann Machine(RBM)

RBM은 확률밀도함수(pdf)를 학습하기 위해 만들어진 신경만으로 현대적 딥러닝 , 특히 심층 생성 모델의 부흥을 이끈 기념비적인 모델이다.

* Boltzmann Machine 
![alt text](/assets/img/posts/deep_learning_generative/11-1-7.png)

* Restricted Boltzmann Machine(RBM)
![alt text](/assets/img/posts/deep_learning_generative/11-1-8.png)


### why restricted?

일반적인 Boltzmann Machine은 모든 뉴런이 서로 연결된 완전 연결 그래프 형태이다. 이는 이론적으로 가장 강력한 표현력을 가지지만 , 학습에 필요한 계산량이 너무 방대하여 현실적으로 사용할수 없다.

힌튼교수는 이를 새결하기위해 `같은 층 내의 뉴런끼리는 연결하지 않는다' 라는 제약조건을 도입했다.

즉 같은층의 뉴런끼리 연결하지않는 이분 그래프 구조를 만든다.

* Hidden Layer의 값이 고정되어 있다면 Visible Node의 각 뉴런은 서로 독립적이다.
* 반대로 Visible Node의 값이 고정되어 있다면 , Hidden Layer의 각 뉴런또한 서로 독립적이다.

이 독립성덕분에 우리는 복잡한 확률 계산을 뉴런단위로 쪼개어 병렬 처리할수있게 되었고 효율적인 학습 알고리즘의 적용이 가능해졌다.

P(v,h) vs P(hㅣv) or P(vㅣh)

### RBM && Neural Network

유사점
* 연결구조의 비슷

차이
* RBM - loss(Energy 개념)기반
* Visible - hidden 구조
* Generative Task : Hidden -> (sampling) -> visible

### Energy-based Learning

![alt text](/assets/img/posts/deep_learning_generative/11-1-9.png)

학습 데이터에 존재하는 패턴을 안정적인 상태로 학습하고 학습 데이터와 유사한 패턴에 대해서는 낮은에너지(높은 확률)를 부여하고 노이즈나 데이터에 없는 패턴에 대해서는 높은에너지(낮은 확률)를 부여하도록 가중치와 편향을 조정한다.

![alt text](/assets/img/posts/deep_learning_generative/11-1-10.png)


![alt text](/assets/img/posts/deep_learning_generative/11-1-11.png)

![alt text](/assets/img/posts/deep_learning_generative/11-1-12.png)

![alt text](/assets/img/posts/deep_learning_generative/11-1-13.png)