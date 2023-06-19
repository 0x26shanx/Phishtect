import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix
from features_extract import extract_features
from joblib import dump
import seaborn as sns
import matplotlib.pyplot as plt

# Assuming the data is in a pandas DataFrame called df
df = pd.read_csv('dataset/url_dataset.csv')

# Drop the 'Url' column
df = df.drop(columns=['Url'])

# Replace -1 with NaN (assuming -1 denotes failure to retrieve feature)
df = df.replace(-1, pd.NA)

# Handle missing values
df = df.dropna()

# Define the feature and target variables
X = df.drop(columns=['label'])
y = df['label']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Standardize the features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Define the classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the classifier
clf.fit(X_train, y_train)

# Use the trained model to make predictions on the test set
y_pred = clf.predict(X_test)

# Calculate the accuracy of the model
accuracy = accuracy_score(y_test, y_pred)

# # Compute confusion matrix
# cf_matrix = confusion_matrix(y_test, y_pred)

# # Plot confusion matrix
# plt.figure(figsize=(10,7))
# sns.heatmap(cf_matrix, annot=True, cmap='Blues')
# plt.title('Confusion Matrix')
# plt.ylabel('True Label')
# plt.xlabel('Predicted Label')

# plt.show()

print(f"Accuracy: {accuracy * 100:.2f}%")

# Save the trained model and scaler into one pickle file
import pickle
with open('trained_model_and_scaler.pkl', 'wb') as f:
    pickle.dump((clf, scaler), f)

