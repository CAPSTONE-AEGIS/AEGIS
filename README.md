# AEGIS

AI 기반 네트워크 공격 탐지 및 보안 관제 소프트웨어

## Project Overview

본 프로젝트는 가상 네트워크 환경에서 발생하는 Port Scan, ICMP Flood, SSH Brute Force, ARP Spoofing, DNS 이상 트래픽을 수집하고, Python 기반 파서와 AI 모델을 이용하여 공격 유형을 분류하는 보안 관제 소프트웨어를 구현한다.

## Directory Structure

- ai_model/: AI 모델 학습 및 평가 코드
- parser/: pcap, auth.log, dnsmasq.log 파싱 코드
- dashboard/: 탐지 결과 시각화 코드
- data/: 샘플 데이터 및 features.csv
- infra/: 실습 환경 설정 파일
- docs/: 보고서 및 실험 기록

## Attack Types

- Port Scan
- ICMP Flood
- SSH Brute Force
- ARP Spoofing
- DNS Anomaly

## Main Goal

원본 패킷 및 시스템 로그에서 특징값을 추출하고, 학습된 AI 모델을 이용하여 공격 유형과 위험도를 자동으로 판단한다.
