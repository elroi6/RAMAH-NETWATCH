class Config:
    SQLALCHEMY_DATABASE_URI = "sqlite:///netwatch.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    NETWATCH_INTERFACE = "wlan0"
