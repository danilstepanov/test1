from DB_ORM_classes import *
import random
from Logger import log


def get_stbm_id_linked_to_pttp(sqlconnection, pttp_id):
    stbm_ids = sqlconnection.session.query(StbmodelParttype.stbm_stbm_id).filter(StbmodelParttype.pttp_pttp_id == pttp_id, StbmodelParttype.del_date == None).all()
    if len(stbm_ids) != 0:
        stbm_id = random.choice(stbm_ids)[0]
    else:
        stbm_id = get_any_stbm_id(sqlconnection)
        link = StbmodelParttype(stbm_stbm_id=stbm_id, pttp_pttp_id=pttp_id)
        sqlconnection.session.add(link)
        sqlconnection.session.commit()
    log('get_stbm_id_linked_to_pttp for pttp_id = %s return %s' % (pttp_id, stbm_id))
    return stbm_id

def get_any_stbm_id(sqlconnection):
    stbm_ids = sqlconnection.session.query(StbModel.stbm_id).filter(StbModel.del_date == None).all()
    return random.choice(stbm_ids)[0]
