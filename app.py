import sys
import os

import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGODB_URL_KEY")
print(mongo_db_url)
import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile,Request
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
from fastapi.responses import HTMLResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object

from networksecurity.utils.ml_utils.model.estimator import NetworkModel


client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)

from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME
from networksecurity.constant.training_pipeline import DATA_INGESTION_DATABASE_NAME
from networksecurity.constant.training_pipeline import FEATURES_INFO,FEATURE_QUESTIONS

database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/docs")

@app.get("/train")
async def train_route():
    try:
        train_pipeline=TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e,sys)

  
@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        df=pd.read_csv(file.file)
        #print(df)
        preprocesor=load_object("final_model/preprocessor.pkl")
        final_model=load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocesor,model=final_model)
        print(df.iloc[0])
        y_pred = network_model.predict(df)
        print(y_pred)
        df['predicted_column'] = y_pred
        print(df['predicted_column'])
        #df['predicted_column'].replace(-1, 0)
        #return df.to_json()
        df.to_csv('prediction_output/output.csv')
        table_html = df.to_html(classes='table table-striped')
        #print(table_html)
        return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
        
    except Exception as e:
            raise NetworkSecurityException(e,sys)


# Display form@app.get("/form", response_class=HTMLResponse)
@app.get("/form", response_class=HTMLResponse)
async def manual_form(request: Request):
    return templates.TemplateResponse(
        "form.html",
        {
            "request": request,
            "features_info": FEATURES_INFO,
            "feature_questions": FEATURE_QUESTIONS
        }
    )


# Handle form submission
@app.post("/single_predict", response_class=HTMLResponse)
async def manual_predict(request: Request):
    form_data = await request.form()
    input_dict = {key: int(value) for key, value in form_data.items()}
    df = pd.DataFrame([input_dict])

    preprocessor = load_object("final_model/preprocessor.pkl")
    model = load_object("final_model/model.pkl")
    network_model = NetworkModel(preprocessor=preprocessor, model=model)

    prediction = network_model.predict(df)[0]
    prediction_label = "Phishing" if prediction == 0 else "Legitimate"
    return templates.TemplateResponse("result.html", {"request": request, "prediction": prediction_label})



if __name__=="__main__":
    app_run(app,host="0.0.0.0",port=8000)
