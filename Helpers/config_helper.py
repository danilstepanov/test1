import os

class ConfigHelper(object):

    is_init = False

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(ConfigHelper, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        if ConfigHelper.is_init:
            return
        dir = '/'.join(os.path.dirname(__file__).split('/')[:-1])
        config_filename = os.path.join(dir, 'kmi_config.txt')
        dict = {line.split('=')[0].strip(): line.split('=')[1].strip() for line in open(config_filename)}
        self.database_ip=dict.get('db_ip')
        self.db_port=dict.get('db_port')
        self.db_name=dict.get('db_name')
        self.db_user=dict.get('db_user')
        self.testrail_ip=dict.get('testrail_ip')
        self.testrail_user=dict.get('testrail_user')
        self.testrail_password=dict.get('testrail_password')
        ConfigHelper.is_init = True
