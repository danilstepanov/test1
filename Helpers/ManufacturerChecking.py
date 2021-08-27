
from DB_ORM_classes import *
from Database import *
import random


class ManufacturerChecking(object):

    def __init__(self):
        self.db = Database()

    def get_any_manufacturer_name_from_db(self):
        name = random.choice(self.db.session.query(Manufacturer.mfct_name).filter(Manufacturer.del_date == None).all())[0]
        return name

    def get_last_btch_name(self):
        query = self.db.session.query(Batch.btch_id).filter(Batch.del_date == None).all()
        btch_id = max(query)[0]
        btch_name = self.db.session.query(Batch.btch_name).filter(Batch.btch_id == btch_id).one()[0]
        return btch_name
