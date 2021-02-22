from pymongo import MongoClient

DATABASE = MongoClient()['typerace']  # DB_NAME
DEBUG = True
client = MongoClient('localhost', 27017)
