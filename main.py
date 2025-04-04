from networksecurity.components.data_ingestion import DataIngestion
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.components.data_validation import DataValidation
from networksecurity.logging.logger import logging
from networksecurity.entity.config_entity import DataIngestionConfig,DataValidationConfig
import sys
from networksecurity.entity.config_entity import TrainingPipelineConfig


if __name__=="__main__":
    try:
        trainingpipelineconfig = TrainingPipelineConfig()
        dataingestionconfig = DataIngestionConfig(trainingpipelineconfig)
        dataingestion = DataIngestion(dataingestionconfig)
        logging.info("Initiate data ingestion")
        dataingestionartifact = dataingestion.initiate_data_ingestion()
        logging.info("Data initiation completed")
        data_validation_config = DataValidationConfig(trainingpipelineconfig)
        data_validation = DataValidation(dataingestionartifact,data_validation_config)
        print(dataingestionartifact)
        data_validation_artifact = data_validation.initiate_data_validation()

    except Exception as e:
        raise NetworkSecurityException(e,sys)