# 🛡️ Network Intrusion Detection System

## Overview

This project is a Machine Learning based Network Intrusion Detection System (NIDS) developed using the NSL KDD cybersecurity dataset.

The system analyzes network connection records and classifies them into one of the following categories:

* Normal
* DoS (Denial of Service)
* Probe
* R2L (Remote to Local)
* U2R (User to Root)

An interactive Streamlit dashboard was built to visualize attack predictions, threat severity levels, attack distributions, and generate security incident reports.

---

## Problem Statement

Modern computer networks face various cyber threats including denial of service attacks, reconnaissance attacks, privilege escalation attacks, and unauthorized access attempts.

The goal of this project is to develop a machine learning model capable of detecting malicious network activity and categorizing different types of cyber attacks.

---

## Dataset

Dataset: NSL KDD

The NSL KDD dataset is an improved version of the KDD Cup 1999 dataset and is widely used for intrusion detection research.

Files Used:

* KDDTrain+.txt
* KDDTest+.txt

Dataset Characteristics:

* 125,973 training records
* 22,544 testing records
* 41 network traffic features
* 1 attack label
* 1 difficulty score

---

## Attack Categories

Original attack labels were grouped into broader categories:

### Normal

* normal

### DoS

* neptune
* smurf
* back
* land
* pod
* teardrop
* apache2
* mailbomb
* processtable
* udpstorm

### Probe

* satan
* ipsweep
* portsweep
* nmap
* saint
* mscan

### R2L

* guess_passwd
* warezclient
* warezmaster
* ftp_write
* imap
* multihop
* phf
* spy
* httptunnel
* named
* sendmail
* snmpguess
* snmpgetattack
* worm
* xlock
* xsnoop

### U2R

* buffer_overflow
* loadmodule
* perl
* rootkit
* ps
* sqlattack
* xterm

---

## Project Workflow

### 1. Data Loading

Loaded:

* KDDTrain+.txt
* KDDTest+.txt

using Pandas.

---

### 2. Data Understanding

Performed:

* Dataset inspection
* Feature analysis
* Attack distribution analysis
* Missing value verification

Result:

* No missing values detected.

---

### 3. Feature Engineering

Identified categorical features:

* protocol_type
* service
* flag

Performed One Hot Encoding using:

```python
pd.get_dummies()
```

Feature count increased from:

* 42 features

to

* 123 features

---

### 4. Label Encoding

Target categories:

* Normal
* DoS
* Probe
* R2L
* U2R

were converted into numerical labels using:

```python
LabelEncoder
```

---

### 5. Feature Scaling

Applied:

```python
StandardScaler
```

to normalize feature values before Logistic Regression training.

---

### 6. Model Training

#### Logistic Regression

```python
LogisticRegression(max_iter=1000)
```

Used as the primary classification model.

#### Random Forest

```python
RandomForestClassifier()
```

Used for performance comparison.

---

### 7. Model Evaluation

Evaluation Metrics:

* Accuracy
* Precision
* Recall
* F1 Score
* Confusion Matrix

Results showed that Logistic Regression outperformed Random Forest on this dataset.

---

### Logistic Regression Results

Accuracy:

78.45%

Key Observations:

* Strong detection of DoS attacks
* Strong detection of Probe attacks
* High Normal traffic classification accuracy
* Difficulty detecting rare R2L attacks

---

### 8. Feature Importance Analysis

Model coefficients were analyzed to identify the most influential network traffic features.

Top indicators included:

* is_guest_login
* num_file_creations
* hot
* dst_host_same_srv_rate
* wrong_fragment

---

### 9. Explainable AI (SHAP)

To improve model interpretability, SHAP (SHapley Additive exPlanations) was integrated into the project.

SHAP was used to:

* Explain individual network traffic predictions
* Identify which features contributed most to attack classifications
* Improve transparency of model decisions
* Provide human interpretable security insights

SHAP visualizations included:

* Summary Plot
* Feature Impact Analysis
* Individual Prediction Explanations

This allows the system to explain why a connection was classified as:

* DoS
* Probe
* R2L
* U2R
* Normal

rather than providing only a prediction result.

Example Insights:

* High serror_rate increased the probability of a DoS attack
* Abnormal guest login activity contributed to malicious classifications
* File creation behavior was a strong indicator of suspicious activity

Explainable AI helps security analysts understand model decisions and improves trust in automated threat detection systems.


### 9. Streamlit Dashboard

Developed an interactive dashboard with:

* Network traffic upload
* Threat classification
* Security metrics
* Attack distribution visualization
* Threat severity scoring
* Incident report generation
* Report download functionality

---

## Threat Severity Levels

| Category | Severity |
| -------- | -------- |
| U2R      | Critical |
| R2L      | High     |
| DoS      | Medium   |
| Probe    | Low      |
| Normal   | Safe     |

---

## Technologies Used

* Python
* Pandas
* NumPy
* Scikit Learn
* Matplotlib
* Seaborn
* Plotly
* Streamlit
* Joblib

---

## Future Improvements

* XGBoost and LightGBM model comparison
* Real Time Packet Monitoring
* Live Network Traffic Capture
* Deep Learning Based Intrusion Detection
* Cloud Deployment and Monitoring
* Security Alert Notification System
* SOC Analyst Dashboard Enhancements
* Real Time Threat Intelligence Integration
* Model Retraining Pipeline
* MLOps Automation

---

## Project Structure

```text
network-intrusion-detection/

├── app.py
├── requirements.txt
├── README.md
│
├── data/
│   ├── KDDTrain+.txt
│   └── KDDTest+.txt
│
├── models/
│   ├── logistic_regression_model.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   └── feature_columns.pkl
│
├── notebooks/
│   └── model_training.ipynb
│
└── screenshots/
```

---

## Author

Built as an end to end Machine Learning and Cybersecurity project demonstrating data preprocessing, feature engineering, model development, evaluation, deployment, and security analytics.
