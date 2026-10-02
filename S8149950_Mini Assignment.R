# ============================================================================
# NIT3202 Statistics and Data Mining - Mini Assignment
# Malicious Website Classification
# Student: Justin Dang | Student ID: s8149950
# ============================================================================

# This script is designed to run from top to bottom in a clean R session.
# Place malicious_and_benign_websites1.csv in the same folder as this script,
# or supply the CSV path as the first command-line argument to Rscript.

set.seed(8149950)

# ----------------------------------------------------------------------------
# 1. Packages and file paths
# ----------------------------------------------------------------------------

required.packages <- c(
  "caret",
  "recipes",
  "ranger",
  "pROC",
  "ggplot2",
  "kernlab"
)

missing.packages <- required.packages[
  !vapply(required.packages, requireNamespace, logical(1), quietly = TRUE)
]

if (length(missing.packages) > 0) {
  stop(
    "Install the following packages before running this script: ",
    paste(missing.packages, collapse = ", ")
  )
}

suppressPackageStartupMessages({
  library(caret)
  library(recipes)
  library(ranger)
  library(pROC)
  library(ggplot2)
})

get.script.path <- function() {
  command.args <- commandArgs(trailingOnly = FALSE)
  file.arg <- grep("^--file=", command.args, value = TRUE)

  if (length(file.arg) > 0) {
    return(normalizePath(sub("^--file=", "", file.arg[1])))
  }

  source.file <- tryCatch(sys.frame(1)$ofile, error = function(e) NULL)

  if (is.null(source.file) || length(source.file) != 1 || !nzchar(source.file)) {
    return(NA_character_)
  }

  normalizePath(source.file)
}

script.path <- get.script.path()
project.dir <- if (is.na(script.path)) getwd() else dirname(script.path)
data.filename <- "malicious_and_benign_websites1.csv"
command.args <- commandArgs(trailingOnly = TRUE)

data.path <- if (length(command.args) > 0) {
  command.args[1]
} else {
  file.path(project.dir, data.filename)
}

if (!file.exists(data.path)) {
  fallback.path <- file.path(getwd(), data.filename)

  if (file.exists(fallback.path)) {
    data.path <- fallback.path
  } else {
    stop(
      "Dataset not found. Place ", data.filename,
      " in the script folder or provide its path to Rscript."
    )
  }
}

# ----------------------------------------------------------------------------
# 2. Import and initial data audit
# ----------------------------------------------------------------------------

website.data <- read.csv(
  data.path,
  stringsAsFactors = FALSE,
  na.strings = c("", "NA", "?", "null")
)

required.columns <- c(
  "URL",
  "CHARSET",
  "SERVER",
  "CONTENT_LENGTH",
  "WHOIS_COUNTRY",
  "WHOIS_STATEPRO",
  "WHOIS_REGDATE",
  "WHOIS_UPDATED_DATE",
  "Type"
)

missing.columns <- setdiff(required.columns, names(website.data))

if (length(missing.columns) > 0) {
  stop(
    "The dataset is missing required columns: ",
    paste(missing.columns, collapse = ", ")
  )
}

if (!all(na.omit(unique(website.data$Type)) %in% c(0, 1))) {
  stop("Type must contain only 0 (benign) and 1 (malicious).")
}

# Initial dataset inspection
dim(website.data)
names(website.data)
head(website.data)
str(website.data)

# Check missing values
colSums(is.na(website.data))

# Inspect the target variable
table(website.data$Type, useNA = "ifany")
round(prop.table(table(website.data$Type)) * 100, 2)

# Count disguised missing values such as "None"
none.counts <- sapply(
  website.data,
  function(x) {
    sum(
      trimws(tolower(as.character(x))) %in%
        c("", "none", "na", "n/a", "null", "?"),
      na.rm = TRUE
    )
  }
)

none.counts[none.counts > 0]

# Check whether the URL identifier may reveal the target
table(
  URL_prefix = substr(website.data$URL, 1, 1),
  Type = website.data$Type
)




# ----------------------------------------------------------------------------
# 3. Data cleaning and feature engineering
# ----------------------------------------------------------------------------

website.model <- website.data

# Convert the target into meaningful class labels
website.model$Type <- factor(
  website.model$Type,
  levels = c(0, 1),
  labels = c("benign", "malicious")
)

# Remove the anonymous URL identifier because its B/M prefix
# perfectly reveals the target class and causes target leakage
website.model$URL <- NULL

# Convert disguised missing categorical values to "Unknown"
clean.category <- function(x) {
  x <- trimws(as.character(x))
  
  invalid <- is.na(x) |
    tolower(x) %in% c("", "none", "na", "n/a", "null", "?")
  
  x[invalid] <- "Unknown"
  factor(x)
}

categorical.columns <- c(
  "CHARSET",
  "SERVER",
  "WHOIS_COUNTRY",
  "WHOIS_STATEPRO"
)

website.model[categorical.columns] <- lapply(
  website.model[categorical.columns],
  clean.category
)

# Clean the two WHOIS date columns
clean.date.text <- function(x) {
  x <- trimws(as.character(x))
  
  invalid <- is.na(x) |
    tolower(x) %in% c("", "none", "na", "n/a", "null", "?")
  
  x[invalid] <- NA_character_
  x
}

extract.year <- function(x) {
  match.position <- regexpr(
    "(19|20)[0-9]{2}",
    x,
    perl = TRUE
  )
  
  year <- rep(NA_integer_, length(x))
  valid <- !is.na(x) & match.position > 0
  
  year[valid] <- as.integer(
    substr(
      x[valid],
      match.position[valid],
      match.position[valid] + 3
    )
  )
  
  year
}

registration.date <- clean.date.text(
  website.model$WHOIS_REGDATE
)

updated.date <- clean.date.text(
  website.model$WHOIS_UPDATED_DATE
)

# Extract unambiguous year information from the dates
website.model$WHOIS_REG_YEAR <- extract.year(registration.date)
website.model$WHOIS_UPDATED_YEAR <- extract.year(updated.date)

# Preserve information about whether important values were missing
website.model$WHOIS_REG_MISSING <- factor(
  ifelse(is.na(registration.date), "missing", "observed")
)

website.model$WHOIS_UPDATED_MISSING <- factor(
  ifelse(is.na(updated.date), "missing", "observed")
)

website.model$CONTENT_LENGTH_MISSING <- factor(
  ifelse(
    is.na(website.model$CONTENT_LENGTH),
    "missing",
    "observed"
  )
)

# Remove the original text date columns after extracting their years
website.model$WHOIS_REGDATE <- NULL
website.model$WHOIS_UPDATED_DATE <- NULL

# ----------------------------------------------------------------------------
# 4. Reproducible stratified 70:30 split
# ----------------------------------------------------------------------------

set.seed(8149950)

train.index <- createDataPartition(
  website.model$Type,
  p = 0.70,
  list = FALSE
)

training.data <- website.model[train.index, ]
testing.data  <- website.model[-train.index, ]

# Verify the split and preserved class imbalance
dim(training.data)
dim(testing.data)

table(training.data$Type)
table(testing.data$Type)

round(prop.table(table(training.data$Type)) * 100, 2)
round(prop.table(table(testing.data$Type)) * 100, 2)

# Remaining genuine missing values will be imputed
# using training data only in the modelling pipeline
colSums(is.na(training.data))




# Set malicious as the positive/event class
training.data$Type <- relevel(
  training.data$Type,
  ref = "malicious"
)

testing.data$Type <- relevel(
  testing.data$Type,
  ref = "malicious"
)

levels(training.data$Type)
levels(testing.data$Type)




# ----------------------------------------------------------------------------
# 5. Leakage-safe preprocessing recipe
# ----------------------------------------------------------------------------

website.recipe <- recipe(
  Type ~ .,
  data = training.data
) %>%
  step_novel(all_nominal_predictors()) %>%
  step_other(
    all_nominal_predictors(),
    threshold = 0.01,
    other = "Other"
  ) %>%
  step_impute_median(all_numeric_predictors()) %>%
  step_dummy(all_nominal_predictors()) %>%
  step_zv(all_predictors()) %>%
  step_normalize(all_numeric_predictors())

# Estimate preprocessing values from training data only
prepared.recipe <- prep(
  website.recipe,
  training = training.data,
  retain = TRUE
)

training.processed <- bake(
  prepared.recipe,
  new_data = NULL
)

testing.processed <- bake(
  prepared.recipe,
  new_data = testing.data
)

# Verification
dim(training.processed)
dim(testing.processed)

sum(is.na(training.processed))
sum(is.na(testing.processed))

levels(training.processed$Type)
levels(testing.processed$Type)




# ----------------------------------------------------------------------------
# 6. Security-focused model evaluation
# ----------------------------------------------------------------------------

security.summary <- function(data, lev = NULL, model = NULL) {
  
  positive.class <- "malicious"
  
  cm <- confusionMatrix(
    data = data$pred,
    reference = data$obs,
    positive = positive.class
  )
  
  precision <- unname(cm$byClass["Pos Pred Value"])
  recall <- unname(cm$byClass["Sensitivity"])
  specificity <- unname(cm$byClass["Specificity"])
  balanced.accuracy <- unname(
    cm$byClass["Balanced Accuracy"]
  )
  
  if (is.na(precision)) precision <- 0
  if (is.na(recall)) recall <- 0
  
  f1 <- ifelse(
    precision + recall == 0,
    0,
    2 * precision * recall / (precision + recall)
  )
  
  roc.value <- as.numeric(
    pROC::roc(
      response = data$obs,
      predictor = data[[positive.class]],
      levels = c("benign", "malicious"),
      direction = "<",
      quiet = TRUE
    )$auc
  )
  
  c(
    F1 = f1,
    Recall = recall,
    Precision = precision,
    Specificity = specificity,
    Balanced_Accuracy = balanced.accuracy,
    ROC_AUC = roc.value
  )
}

# Use identical cross-validation folds for fair comparison
set.seed(8149950)

cv.folds <- createMultiFolds(
  training.data$Type,
  k = 5,
  times = 3
)

model.control <- trainControl(
  method = "repeatedcv",
  number = 5,
  repeats = 3,
  index = cv.folds,
  classProbs = TRUE,
  summaryFunction = security.summary,
  savePredictions = "final",
  allowParallel = TRUE
)




# Verify the shared resampling configuration.
control.check <- data.frame(
  CV_Method = model.control$method,
  Folds = model.control$number,
  Repeats = model.control$repeats,
  Class_Probabilities = model.control$classProbs,
  Saved_Predictions = model.control$savePredictions,
  Uses_Security_Summary = identical(
    model.control$summaryFunction,
    security.summary
  )
)

control.check


# ----------------------------------------------------------------------------
# 7. Model training and cross-validation
# ----------------------------------------------------------------------------

# 7.1 Logistic Regression

set.seed(8149950)

logistic.model <- train(
  website.recipe,
  data = training.data,
  method = "glm",
  family = binomial(),
  metric = "F1",
  maximize = TRUE,
  trControl = model.control
)

logistic.model
logistic.model$results




# 7.2 Support Vector Machine with a radial kernel

set.seed(8149950)

svm.model <- train(
  website.recipe,
  data = training.data,
  method = "svmRadial",
  metric = "F1",
  maximize = TRUE,
  tuneLength = 5,
  trControl = model.control
)

svm.model
svm.model$bestTune
svm.model$results

# Display the best cross-validation result
svm.best.result <- svm.model$results[
  which.max(svm.model$results$F1),
  c(
    "sigma",
    "C",
    "F1",
    "Recall",
    "Precision",
    "Specificity",
    "Balanced_Accuracy",
    "ROC_AUC"
  )
]

round(svm.best.result, 4)




# 7.3 Random Forest

set.seed(8149950)

rf.grid <- expand.grid(
  mtry = c(2, 5, 10, 15, 20),
  splitrule = "gini",
  min.node.size = 5
)

rf.model <- train(
  website.recipe,
  data = training.data,
  method = "ranger",
  metric = "F1",
  maximize = TRUE,
  tuneGrid = rf.grid,
  trControl = model.control,
  num.trees = 500,
  importance = "permutation",
  num.threads = 2
)

rf.model
rf.model$bestTune
rf.model$results




# Display the best Random Forest cross-validation result
rf.best.result <- rf.model$results[
  which.max(rf.model$results$F1),
  c(
    "mtry",
    "splitrule",
    "min.node.size",
    "F1",
    "Recall",
    "Precision",
    "Specificity",
    "Balanced_Accuracy",
    "ROC_AUC"
  )
]

metric.columns <- c(
  "F1",
  "Recall",
  "Precision",
  "Specificity",
  "Balanced_Accuracy",
  "ROC_AUC"
)

rf.best.result[metric.columns] <- round(
  rf.best.result[metric.columns],
  4
)

rf.best.result




# ----------------------------------------------------------------------------
# 8. Final evaluation on the held-out testing set
# ----------------------------------------------------------------------------

evaluate.test.model <- function(model, model.name, test.data) {
  
  # Predicted classes and malicious-class probabilities
  predicted.class <- predict(
    model,
    newdata = test.data,
    type = "raw"
  )
  
  predicted.probability <- predict(
    model,
    newdata = test.data,
    type = "prob"
  )[, "malicious"]
  
  predicted.class <- factor(
    predicted.class,
    levels = levels(test.data$Type)
  )
  
  # Confusion matrix with malicious as the positive class
  cm <- caret::confusionMatrix(
    data = predicted.class,
    reference = test.data$Type,
    positive = "malicious"
  )
  
  precision <- unname(cm$byClass["Pos Pred Value"])
  recall <- unname(cm$byClass["Sensitivity"])
  
  f1 <- ifelse(
    precision + recall == 0,
    0,
    2 * precision * recall / (precision + recall)
  )
  
  # ROC AUC for the malicious class
  roc.object <- pROC::roc(
    response = test.data$Type,
    predictor = predicted.probability,
    levels = c("benign", "malicious"),
    direction = "<",
    quiet = TRUE
  )
  
  metrics <- data.frame(
    Model = model.name,
    Accuracy = unname(cm$overall["Accuracy"]),
    F1 = f1,
    Recall = recall,
    Precision = precision,
    Specificity = unname(cm$byClass["Specificity"]),
    Balanced_Accuracy =
      unname(cm$byClass["Balanced Accuracy"]),
    ROC_AUC = as.numeric(pROC::auc(roc.object))
  )
  
  return(
    list(
      metrics = metrics,
      confusion_matrix = cm,
      predicted_class = predicted.class,
      predicted_probability = predicted.probability
    )
  )
}

# Evaluate the three trained models
logistic.test <- evaluate.test.model(
  logistic.model,
  "Logistic Regression",
  testing.data
)

svm.test <- evaluate.test.model(
  svm.model,
  "Support Vector Machine",
  testing.data
)

rf.test <- evaluate.test.model(
  rf.model,
  "Random Forest",
  testing.data
)

# Combine the test results
test.results <- rbind(
  logistic.test$metrics,
  svm.test$metrics,
  rf.test$metrics
)

# Round numeric metrics for display
numeric.columns <- names(test.results)[
  sapply(test.results, is.numeric)
]

test.results[numeric.columns] <- round(
  test.results[numeric.columns],
  4
)

test.results




# 8.1 Confusion-matrix counts

extract.confusion.counts <- function(test.object, model.name) {
  
  cm.table <- test.object$confusion_matrix$table
  
  data.frame(
    Model = model.name,
    True_Positive =
      as.integer(cm.table["malicious", "malicious"]),
    False_Negative =
      as.integer(cm.table["benign", "malicious"]),
    False_Positive =
      as.integer(cm.table["malicious", "benign"]),
    True_Negative =
      as.integer(cm.table["benign", "benign"])
  )
}

confusion.results <- rbind(
  extract.confusion.counts(
    logistic.test,
    "Logistic Regression"
  ),
  extract.confusion.counts(
    svm.test,
    "Support Vector Machine"
  ),
  extract.confusion.counts(
    rf.test,
    "Random Forest"
  )
)

confusion.results




# ----------------------------------------------------------------------------
# 9. Visualisations
# ----------------------------------------------------------------------------

# 9.1 Confusion matrices

prepare.cm.data <- function(test.object, model.name) {
  
  cm.data <- as.data.frame(
    test.object$confusion_matrix$table
  )
  
  names(cm.data) <- c(
    "Prediction",
    "Actual",
    "Count"
  )
  
  cm.data$Model <- model.name
  
  cm.data
}

cm.plot.data <- rbind(
  prepare.cm.data(
    logistic.test,
    "Logistic Regression"
  ),
  prepare.cm.data(
    svm.test,
    "Support Vector Machine"
  ),
  prepare.cm.data(
    rf.test,
    "Random Forest"
  )
)

cm.plot.data$Model <- factor(
  cm.plot.data$Model,
  levels = c(
    "Logistic Regression",
    "Support Vector Machine",
    "Random Forest"
  )
)

cm.plot.data$Actual <- factor(
  cm.plot.data$Actual,
  levels = c("malicious", "benign")
)

cm.plot.data$Prediction <- factor(
  cm.plot.data$Prediction,
  levels = c("benign", "malicious")
)

confusion.plot <- ggplot(
  cm.plot.data,
  aes(
    x = Actual,
    y = Prediction,
    fill = Count
  )
) +
  geom_tile(
    colour = "white",
    linewidth = 1.2
  ) +
  geom_text(
    aes(label = Count),
    size = 5,
    fontface = "bold"
  ) +
  facet_wrap(
    ~Model,
    nrow = 1
  ) +
  scale_fill_gradient(
    low = "#E8F1F8",
    high = "#176B87"
  ) +
  labs(
    title = "Confusion Matrices on the Testing Set",
    subtitle = "Malicious is the positive class",
    x = "Actual class",
    y = "Predicted class",
    fill = "Count"
  ) +
  theme_minimal(base_size = 13) +
  theme(
    panel.grid = element_blank(),
    strip.text = element_text(
      face = "bold",
      size = 11
    ),
    plot.title = element_text(
      face = "bold"
    )
  )

confusion.plot





# 9.2 Test-set performance comparison

selected.metrics <- c(
  "F1",
  "Recall",
  "Precision",
  "Balanced_Accuracy",
  "ROC_AUC"
)

metric.plot.data <- data.frame(
  Model = rep(
    test.results$Model,
    each = length(selected.metrics)
  ),
  Metric = rep(
    selected.metrics,
    times = nrow(test.results)
  ),
  Score = as.numeric(
    t(
      as.matrix(
        test.results[, selected.metrics]
      )
    )
  )
)

metric.plot.data$Model <- factor(
  metric.plot.data$Model,
  levels = c(
    "Logistic Regression",
    "Support Vector Machine",
    "Random Forest"
  )
)

metric.plot.data$Metric <- factor(
  metric.plot.data$Metric,
  levels = selected.metrics,
  labels = c(
    "F1",
    "Recall",
    "Precision",
    "Balanced Accuracy",
    "ROC AUC"
  )
)

performance.plot <- ggplot(
  metric.plot.data,
  aes(
    x = Metric,
    y = Score,
    fill = Model
  )
) +
  geom_col(
    position = position_dodge(width = 0.8),
    width = 0.7
  ) +
  geom_text(
    aes(label = sprintf("%.3f", Score)),
    position = position_dodge(width = 0.8),
    vjust = -0.35,
    size = 3.2
  ) +
  scale_fill_manual(
    values = c(
      "#4C78A8",
      "#F58518",
      "#2A9D8F"
    )
  ) +
  scale_y_continuous(
    limits = c(0, 1.08),
    breaks = seq(0, 1, 0.2)
  ) +
  labs(
    title = "Classifier Performance on the Testing Set",
    subtitle = "Malicious is the positive class",
    x = NULL,
    y = "Score",
    fill = "Model"
  ) +
  theme_minimal(base_size = 13) +
  theme(
    panel.grid.major.x = element_blank(),
    plot.title = element_text(face = "bold"),
    legend.position = "bottom"
  )

performance.plot





# 9.3 Random Forest feature importance

rf.importance <- caret::varImp(
  rf.model,
  scale = TRUE
)$importance

rf.importance$Feature <- rownames(
  rf.importance
)

rf.importance <- rf.importance[
  order(
    rf.importance$Overall,
    decreasing = TRUE
  ),
]

rf.top10 <- head(
  rf.importance,
  10
)

rf.top10




# 9.4 Top 10 Random Forest feature-importance plot

feature.labels <- c(
  "SOURCE_APP_BYTES" =
    "Source application bytes",
  "REMOTE_APP_PACKETS" =
    "Remote application packets",
  "DIST_REMOTE_TCP_PORT" =
    "Destination remote TCP port",
  "REMOTE_APP_BYTES" =
    "Remote application bytes",
  "APP_BYTES" =
    "Application bytes",
  "WHOIS_STATEPRO_Barcelona" =
    "WHOIS state/province: Barcelona",
  "WHOIS_UPDATED_MISSING_observed" =
    "WHOIS updated status: observed",
  "TCP_CONVERSATION_EXCHANGE" =
    "TCP conversation exchange",
  "DNS_QUERY_TIMES" =
    "DNS query times",
  "URL_LENGTH" =
    "URL length"
)

display.labels <- unname(feature.labels[rf.top10$Feature])
rf.top10$Display_Feature <- ifelse(
  is.na(display.labels),
  rf.top10$Feature,
  display.labels
)

importance.plot <- ggplot(
  rf.top10,
  aes(
    x = reorder(Display_Feature, Overall),
    y = Overall
  )
) +
  geom_col(
    fill = "#2A9D8F",
    width = 0.7
  ) +
  geom_text(
    aes(label = sprintf("%.1f", Overall)),
    hjust = -0.15,
    size = 3.7
  ) +
  coord_flip() +
  scale_y_continuous(
    limits = c(0, 112),
    breaks = seq(0, 100, 20)
  ) +
  labs(
    title = "Top 10 Random Forest Feature Importances",
    subtitle = "Permutation importance scaled relative to the most important feature",
    x = NULL,
    y = "Relative importance"
  ) +
  theme_minimal(base_size = 13) +
  theme(
    panel.grid.major.y = element_blank(),
    plot.title = element_text(face = "bold")
  )

importance.plot


# 9.5 Class distribution

class.summary <- as.data.frame(
  table(website.model$Type)
)

names(class.summary) <- c(
  "Class",
  "Count"
)

class.summary$Percentage <- round(
  class.summary$Count /
    sum(class.summary$Count) * 100,
  2
)

class.summary$Class <- factor(
  class.summary$Class,
  levels = c(
    "benign",
    "malicious"
  )
)

class.plot <- ggplot(
  class.summary,
  aes(
    x = Class,
    y = Count,
    fill = Class
  )
) +
  geom_col(
    width = 0.65
  ) +
  geom_text(
    aes(
      label = paste0(
        Count,
        " (",
        Percentage,
        "%)"
      )
    ),
    vjust = -0.5,
    size = 4.5,
    fontface = "bold"
  ) +
  scale_fill_manual(
    values = c(
      "benign" = "#4C78A8",
      "malicious" = "#E45756"
    )
  ) +
  scale_y_continuous(
    limits = c(0, 1750),
    expand = expansion(
      mult = c(0, 0.02)
    )
  ) +
  labs(
    title = "Class Distribution in the Original Dataset",
    subtitle = "Malicious websites form the minority class",
    x = NULL,
    y = "Number of websites"
  ) +
  theme_minimal(
    base_size = 13
  ) +
  theme(
    legend.position = "none",
    plot.title = element_text(
      face = "bold"
    ),
    panel.grid.major.x = element_blank()
  )

class.plot




# 9.6 ROC curves for all three classifiers

roc.models <- list(
  "Logistic Regression" = pROC::roc(
    response = testing.data$Type,
    predictor = logistic.test$predicted_probability,
    levels = c("benign", "malicious"),
    direction = "<",
    quiet = TRUE
  ),
  
  "Support Vector Machine" = pROC::roc(
    response = testing.data$Type,
    predictor = svm.test$predicted_probability,
    levels = c("benign", "malicious"),
    direction = "<",
    quiet = TRUE
  ),
  
  "Random Forest" = pROC::roc(
    response = testing.data$Type,
    predictor = rf.test$predicted_probability,
    levels = c("benign", "malicious"),
    direction = "<",
    quiet = TRUE
  )
)

roc.auc <- vapply(
  roc.models,
  function(x) {
    as.numeric(pROC::auc(x))
  },
  numeric(1)
)

names(roc.models) <- paste0(
  names(roc.models),
  " (AUC = ",
  sprintf("%.3f", roc.auc),
  ")"
)

roc.plot <- pROC::ggroc(
  roc.models,
  legacy.axes = TRUE,
  linewidth = 1.2
) +
  geom_abline(
    intercept = 0,
    slope = 1,
    linetype = "dashed",
    colour = "grey55"
  ) +
  scale_colour_manual(
    values = c(
      "#4C78A8",
      "#F58518",
      "#2A9D8F"
    )
  ) +
  scale_x_continuous(
    limits = c(0, 1),
    breaks = seq(0, 1, 0.2)
  ) +
  scale_y_continuous(
    limits = c(0, 1),
    breaks = seq(0, 1, 0.2)
  ) +
  labs(
    title = "ROC Curves on the Testing Set",
    subtitle = "Malicious is the positive class",
    x = "False positive rate",
    y = "True positive rate",
    colour = "Model"
  ) +
  theme_minimal(
    base_size = 13
  ) +
  theme(
    plot.title = element_text(
      face = "bold"
    ),
    legend.position = "bottom"
  )

roc.plot


# ----------------------------------------------------------------------------
# 10. Export reproducible results
# ----------------------------------------------------------------------------

output.dir <- file.path(project.dir, "outputs")
dir.create(output.dir, showWarnings = FALSE, recursive = TRUE)

cv.results <- rbind(
  data.frame(
    Model = "Logistic Regression",
    logistic.model$results[
      which.max(logistic.model$results$F1),
      metric.columns,
      drop = FALSE
    ],
    row.names = NULL
  ),
  data.frame(
    Model = "Support Vector Machine",
    svm.model$results[
      which.max(svm.model$results$F1),
      metric.columns,
      drop = FALSE
    ],
    row.names = NULL
  ),
  data.frame(
    Model = "Random Forest",
    rf.model$results[
      which.max(rf.model$results$F1),
      metric.columns,
      drop = FALSE
    ],
    row.names = NULL
  )
)

cv.results[metric.columns] <- round(cv.results[metric.columns], 4)

write.csv(
  cv.results,
  file.path(output.dir, "cross_validation_results.csv"),
  row.names = FALSE
)

write.csv(
  test.results,
  file.path(output.dir, "test_results.csv"),
  row.names = FALSE
)

write.csv(
  confusion.results,
  file.path(output.dir, "confusion_matrix_counts.csv"),
  row.names = FALSE
)

write.csv(
  rf.top10[, c("Feature", "Overall")],
  file.path(output.dir, "random_forest_top10_importance.csv"),
  row.names = FALSE
)

ggsave(
  file.path(output.dir, "class_distribution.png"),
  class.plot,
  width = 12,
  height = 6,
  dpi = 200
)

ggsave(
  file.path(output.dir, "classifier_performance.png"),
  performance.plot,
  width = 12,
  height = 7,
  dpi = 200
)

ggsave(
  file.path(output.dir, "confusion_matrices.png"),
  confusion.plot,
  width = 12,
  height = 6,
  dpi = 200
)

ggsave(
  file.path(output.dir, "random_forest_feature_importance.png"),
  importance.plot,
  width = 12,
  height = 6,
  dpi = 200
)

ggsave(
  file.path(output.dir, "roc_curves.png"),
  roc.plot,
  width = 12,
  height = 6,
  dpi = 200
)

capture.output(
  sessionInfo(),
  file = file.path(output.dir, "session_info.txt")
)

cat(
  "\nAnalysis complete. Results were written to:\n",
  normalizePath(output.dir),
  "\n"
)
