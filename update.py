import os
import time
import schedule
import requests
import subprocess
import pandas as pd
from datetime import datetime

MAX_ROWS_REPO = 8000
MAX_ROWS_DATASET = 5000

def download_phishtank_repo():
    url = "http://data.phishtank.com/data/online-valid.csv"
    response = requests.get(url)
    with open('online-valid.csv', 'wb') as file:
        file.write(response.content)
    print("Phishtank repo downloaded.")
    
    # Load the phishrepo
    df_phishrepo = pd.read_csv('online-valid.csv')
    # Trim the data to the first 8000 rows
    df_phishrepo = df_phishrepo.head(MAX_ROWS_REPO)
    # Save the trimmed data
    df_phishrepo.to_csv('online-valid.csv', index=False)
    print("Phishtank repo trimmed.")

def run_scripts():
    try:
        print("Running scripts...")
        subprocess.run(["python", "features_extract.py"])
        # Load the features dataset
        df_features = pd.read_csv('dataset_output.csv')
        # Trim the data to the first 5000 rows
        df_features = df_features.head(MAX_ROWS_DATASET)
        # Save the trimmed data
        df_features.to_csv('dataset_output.csv', index=False)
        print("Features dataset trimmed.")
        subprocess.run(["python", "rfcmodel.py"])
        print("Scripts run successfully.")
    except Exception as e:
        print("An error occurred while running the scripts:", e)

def job():
    print("Job Started at: ", datetime.now())
    download_phishtank_repo()
    run_scripts()
    print("Job Finished at: ", datetime.now())

schedule.every().day.at("00:00").do(job)

while True:
    schedule.run_pending()
    time.sleep(1)