import os

class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
    OUTPUT_DIR = os.path.join(BASE_DIR, 'processed')
    WORKERS = 1
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    STATE_DIR = os.path.join(BASE_DIR, 'luigi_state')
    DASH_PORT = 5001
    LUIGI_PORT = 8082
    CUSTOM_STATIC_PATH = os.path.join(BASE_DIR, 'dashboard/static')


config = Config()