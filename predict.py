from features_extract import extract_features
import pickle
import pandas as pd

# Load the trained model and scaler
with open('trained_model_and_scaler.pkl', 'rb') as f:
    clf, scaler = pickle.load(f)

def make_prediction(url):
    # Extract the features from the URL
    features_dict = extract_features(url)

    # Convert the features dictionary to a DataFrame
    features_df = pd.DataFrame([features_dict])

    # Selecting only the columns that the model was trained on
    # Assuming 'columns' is a list of the column names
    columns = ['UsingIp', 'longUrl', 'shortUrl', 'symbol', 'redirecting', 'prefixSuffix', 'SubDomains', 'Https', 'hasSsl', 'DomainRegLen', 'Favicon', 'NonStdPort', 'Dots', 'Redirection //', 'InfoEmail', 'AbnormalURL', 'WebsiteForwarding', 'DisableRightClick', 'UsingPopupWindow', 'AgeofDomain', 'DNSRecording', 'LinksPointingToPage']
    features = features_df[columns]

    # Scale the features
    features = scaler.transform(features)

    # Use the trained model to make a prediction
    prediction = clf.predict(features)

    # Return the prediction
    if prediction[0] == 0:
        return "The URL is legit."
    else:
        return "The URL is phishing."
# If the script is run directly, ask for URL input
if __name__ == "__main__":
    url = input("Enter a URL: ")
    print(make_prediction(url))