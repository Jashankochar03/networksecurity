import os
import sys
import numpy as np
import pandas as pd

"""
Defining common contraint variable of training pipeline
"""
TARGET_COLUMN = "Result"
PIPELINE_NAME:str = "NetworkSecurity"
ARTIFACT_DIR:str = "Artifacts"
FILE_NAME:str = "phisingData.csv"
TRAIN_FILE_NAME:str = "train.csv"
TEST_FILE_NAME:str = "test.csv"
SCHEMA_FILE_PATH = os.path.join("data_schema", "schema.yaml")

SAVED_MODEL_DIR =os.path.join("saved_models")
MODEL_FILE_NAME = "model.pkl"


SCHEMA_FILE_PATH = os.path.join("data_schema","schema.yaml")


"""
Data ingestion related constants starts with DATA_INGESTION VAR NAME
"""

DATA_INGESTION_COLLECTION_NAME:str = "NetworkData"
DATA_INGESTION_DATABASE_NAME:str = "JASHANAI"
DATA_INGESTION_DIR_NAME:str = "data_ingestion"
DATA_INGESTION_FEATURE_STORE_DIR:str = "feature_store"
DATA_INGESTION_INGESTED_DIR:str = "ingested"
DATA_INGESTION_TRAIN_TEST_SPLIT_RATION:float = 0.2
PREPROCESSING_OBJECT_FILE_NAME = "preprocessing.pkl"

"""
Data validation constants start with DATA_VALIDATION VAR NAME
"""

DATA_VALIDATION_DIR_NAME:str = "data_validation"
DATA_VALIDATION_VALID_DIR:str = "validated"
DATA_VALIDATION_INVALID_DIR:str = "invalid"
DATA_VALIDATION_DRIFT_REPORT_DIR:str = "drift_report"
DATA_VALIDATION_DRIFT_REPORT_FILE_NAME:str = "report.yaml"

"""
Data transformation related constants starts with DATA_TRANSFORMATION VAR NAME
"""

DATA_TRANSFORMATION_DIR_NAME:str = "data_transformation"
DATA_TRANSFORMATION_TRANSFORMED_DATA_DIR:str = "transformed"
DATA_TRANSFORMATION_TRANSFORMED_OBJECT_DIR:str = "transformed_object"

DATA_TRANSFORMATION_IMPUTER_PARAMS:dict = {
    "missing_values":np.nan,
    "n_neighbors": 3,
    "weights": "uniform"
}

DATA_TRANSFORMATION_TRAIN_FILE_PATH: str = "train.npy"

DATA_TRANSFORMATION_TEST_FILE_PATH: str = "test.npy"


"""
Model Trainer ralated constant start with MODE TRAINER VAR NAME
"""

MODEL_TRAINER_DIR_NAME: str = "model_trainer"
MODEL_TRAINER_TRAINED_MODEL_DIR: str = "trained_model"
MODEL_TRAINER_TRAINED_MODEL_NAME: str = "model.pkl"
MODEL_TRAINER_EXPECTED_SCORE: float = 0.6
MODEL_TRAINER_OVER_FIITING_UNDER_FITTING_THRESHOLD: float = 0.05

TRAINING_BUCKET_NAME = "netwworksecurity"


FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service',
    'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
    'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
    'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
    'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
    'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
    'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
]

# Define the feature names and their choice types (2 or 3 values)
FEATURES_INFO = {
    "having_IP_Address": 2,
    "URL_Length": 3,
    "Shortining_Service": 2,
    "having_At_Symbol": 2,
    "double_slash_redirecting": 2,
    "Prefix_Suffix": 2,
    "having_Sub_Domain": 3,
    "SSLfinal_State": 3,
    "Domain_registeration_length": 2,
    "Favicon": 2,
    "port": 2,
    "HTTPS_token": 2,
    "Request_URL": 3,
    "URL_of_Anchor": 3,
    "Links_in_tags": 3,
    "SFH": 3,
    "Submitting_to_email": 2,
    "Abnormal_URL": 2,
    "Redirect": 3,
    "on_mouseover": 2,
    "RightClick": 2,
    "popUpWidnow": 2,
    "Iframe": 2,
    "age_of_domain": 2,
    "DNSRecord": 2,
    "web_traffic": 3,
    "Page_Rank": 2,
    "Google_Index": 2,
    "Links_pointing_to_page": 3,
    "Statistical_report": 2
}

FEATURE_QUESTIONS = {
    "having_IP_Address": "Does the URL contain an IP address?",
    "URL_Length": "Is length of URL is long (greater than 75)?",
    "Shortining_Service": "Is the URL shortened (like bit.ly)?",
    "having_At_Symbol": "Does the URL contain an '@' symbol?",
    "double_slash_redirecting": "Does the URL have '//' after the protocol?",
    "Prefix_Suffix": "Is there a '-' symbol in the domain?",
    "having_Sub_Domain": "How many subdomains are in the URL?",
    "SSLfinal_State": "Is SSL certificate present and valid?",
    "Domain_registeration_length": "Is domain registered for more than a year?",
    "Favicon": "Is the favicon from the same domain?",
    "port": "Does the URL use a non-standard port?",
    "HTTPS_token": "Does the URL contain 'HTTPS' as part of the domain?",
    "Request_URL": "Are external objects loaded from other domains?",
    "URL_of_Anchor": "Do anchors link to different domains?",
    "Links_in_tags": "Do meta/script tags link externally?",
    "SFH": "Is the Server Form Handler (SFH) suspicious?",
    "Submitting_to_email": "Does the form submit to an email address?",
    "Abnormal_URL": "Is the URL abnormal (mismatch in WHOIS or format)?",
    "Redirect": "How many redirects are used?",
    "on_mouseover": "Does the URL change on mouseover?",
    "RightClick": "Is right-click disabled?",
    "popUpWidnow": "Are popup windows triggered?",
    "Iframe": "Is an iframe used to display content?",
    "age_of_domain": "Is the domain older than 6 months?",
    "DNSRecord": "Does the domain have a DNS record?",
    "web_traffic": "How much web traffic does the site have?",
    "Page_Rank": "Is the page rank low?",
    "Google_Index": "Is the site indexed by Google?",
    "Links_pointing_to_page": "How many backlinks point to the page?",
    "Statistical_report": "Does it match any phishing statistical data?"
}

