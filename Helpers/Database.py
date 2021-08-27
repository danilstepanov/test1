from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from Logger import log
import config_helper as ch


class Database(object):

    session = None
    conn = None

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Database, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        if Database.session is None:
            conf_helper = ch.ConfigHelper()
            self.db_user = conf_helper.db_user
            self.database_ip = conf_helper.database_ip
            self.db_port = conf_helper.db_port
            self.db_name = conf_helper.db_name
            self.__connect_to_db()

    def __connect_to_db(self):
        if Database.session is not None:
            return 1
        try:

            engine = create_engine('postgresql://%s:@%s:%s/%s' % (self.db_user, self.database_ip, self.db_port, self.db_name), client_encoding='utf8')
            session = sessionmaker(bind=engine)
            Database.session = session()
            Database.conn = engine.connect()
            log('Connect to DB = %s on host = %s successfully' % (self.db_name, self.database_ip))
            return 1
        except Exception as e:
            log(e)
            log('Connect to DB = %s on host = %s not successfully' % (self.db_name, self.database_ip))
            return 0

    def disconnect(self):
        Database.conn.close()
