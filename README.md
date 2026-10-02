# Malicious Website Classification

A machine learning project for detecting malicious websites using **Logistic Regression, Support Vector Machine (SVM), and Random Forest** in R.

This project was completed for **NIT3202 – Statistics and Data Mining** at Victoria University.

## Project Overview

The objective of this project was to compare multiple supervised learning models for classifying websites as either:

- Benign
- Malicious

The dataset contains **1,781 websites** and is highly imbalanced, with malicious websites representing only a small minority of observations.

Because overall accuracy can be misleading for imbalanced classification problems, the project focused on security-relevant metrics including:

- Recall
- Precision
- F1 Score
- Specificity
- Balanced Accuracy
- ROC AUC

## Dataset

The dataset contains website, network and WHOIS-related features used to distinguish malicious and benign websites.

The original target variable is:

`Type`

where:

- `0` = benign
- `1` = malicious

The dataset contains:

- **1,781 websites**
- **1,565 benign websites**
- **216 malicious websites**

## Technologies Used

- R
- caret
- recipes
- ranger
- kernlab
- pROC
- ggplot2

## Data Preparation

Several data-quality issues were handled before modelling.

Key preprocessing steps included:

- Detecting disguised missing values
- Cleaning categorical variables
- Extracting year-based information from WHOIS date fields
- Handling rare and unseen categories
- Median imputation for numeric variables
- Dummy encoding
- Zero-variance feature removal
- Numeric normalisation

A critical issue was discovered in the raw URL field: the identifier prefix perfectly revealed the target class.

To prevent **target leakage**, the URL identifier was removed before model training.

## Train-Test Split

A stratified **70:30 train-test split** was used to preserve the original class distribution.

- Training set: 1,248 websites
- Test set: 533 websites

The test set remained untouched during model tuning.

## Model Validation

All models were evaluated using the same resampling strategy:

- 5-fold cross-validation
- 3 repeats
- Identical resampling folds across models

This ensured a fair comparison between the classifiers.

## Models Compared

### Logistic Regression

Used as an interpretable baseline classifier.

### Support Vector Machine

A radial-kernel SVM was used to capture non-linear relationships.

### Random Forest

A tree-based ensemble model was trained using 500 trees and permutation-based feature importance.

## Evaluation Metrics

Because malicious websites were the minority class, the project prioritised:

- **Recall** — proportion of malicious websites detected
- **Precision** — reliability of malicious predictions
- **F1 Score** — balance between precision and recall
- **Specificity** — proportion of benign websites correctly identified
- **Balanced Accuracy**
- **ROC AUC**

## Results

The **Random Forest** model achieved the strongest overall held-out test performance.

### Random Forest Test Performance

- **Accuracy:** 0.9644
- **F1 Score:** 0.8288
- **Recall:** 0.7188
- **Precision:** 0.9787
- **Specificity:** 0.9979
- **Balanced Accuracy:** 0.8583
- **ROC AUC:** 0.9842

The Random Forest model detected:

- **46 malicious websites correctly**
- **18 malicious websites missed**
- **1 false positive**
- **468 benign websites correctly classified**

It achieved the same recall as Logistic Regression while reducing false positives from 10 to 1.

## Feature Importance

Random Forest permutation importance showed that several network and website-related variables were influential.

Important features included:

- Source application bytes
- Remote application packets
- Destination remote TCP port
- Remote application bytes
- Application bytes
- WHOIS-related features
- TCP conversation exchange
- DNS query times
- URL length

## Repository Contents

### `S8149950_Mini Assignment(1).R`

Complete reproducible R workflow including:

- Data loading
- Data auditing
- Feature engineering
- Leakage removal
- Preprocessing
- Train-test splitting
- Cross-validation
- Model training
- Hyperparameter tuning
- Evaluation
- Visualisation
- Feature importance

### `malicious_and_benign_websites1(1).csv`

Dataset used for the project.

### `NIT3202_Mini_Assignment_Justin_Dang_s8149950.docx`

Full project report containing methodology, results, charts, confusion matrices and discussion.

## Skills Demonstrated

- Supervised machine learning
- Imbalanced classification
- Data cleaning
- Feature engineering
- Target leakage detection
- Train-test splitting
- Repeated cross-validation
- Logistic Regression
- Support Vector Machine
- Random Forest
- Hyperparameter tuning
- ROC analysis
- Confusion-matrix analysis
- Feature importance
- Model comparison
- R programming

## Limitations

- The number of malicious websites in the test set is relatively small.
- The dataset may not represent future malicious website behaviour.
- The classification threshold was not fully cost-optimised.
- Feature importance should not be interpreted as causal evidence.

## Future Improvements

Potential improvements include:

- Threshold optimisation
- Class-weighted modelling
- Probability calibration
- External validation on newer datasets
- Drift monitoring
- SHAP or partial-dependence analysis
- Additional ensemble methods

## Author

**Justin Dang**

Bachelor of Data Science  
Victoria University
