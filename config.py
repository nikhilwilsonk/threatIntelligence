import os
from dotenv import load_dotenv

class Config:
    load_dotenv()
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    DATABASE_NAME = 'threat_intelligence_db'

    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
