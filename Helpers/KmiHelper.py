import os, sqlalchemy, random
from DB_ORM_classes import Batch, Device,PartType, DeviceClass, DeviceKeymap
from Logger import log
from sqlalchemy.sql.expression import func


def get_homedir_in():
    cur_dir = os.getcwd()
    home_dir = '/' + '/'.join(cur_dir.split('/')[1:3])
    return os.path.join(home_dir, 'in')


def get_homedir_out():
    cur_dir = os.getcwd()
    home_dir = '/' + '/'.join(cur_dir.split('/')[1:3])
    return os.path.join(home_dir, 'out')


def get_nextfree_value_from_list(list, start_value=1):
    list = sorted(list)
    it = list.__iter__()
    cur_val = it.next()
    if cur_val >start_value:
        return start_value
    while 1:
        try:
            next_val = it.next()
            if next_val - cur_val != 1:
                free_val = cur_val + 1
                if free_val >= start_value:
                    break
            cur_val = next_val
        except StopIteration:
            if next_val < start_value:
                free_val = start_value
                break
            else:
                free_val = next_val +1
                break
    return free_val


def get_int_ranges_from_list(list):
    if (list==[]):
        return ''
    list.sort()
    ranges = [[list[0],list[0]]] # ranges contains the start and end values of each range found
    for val in list:
        r = ranges[-1]
        if val==r[1]+1:
            r[1] = val
        elif val>r[1]+1:
            ranges.append([val,val])
    return ", ".join(["-".join([str(y) for y in x]) if x[0]!=x[1] else str(x[0]) for x in ranges])


def check_batch(sqlalchemy_con, batch_id, expected_batch_name, batch_type_id):
    try:
        batch = sqlalchemy_con.session.query(Batch).filter(Batch.btch_id == batch_id, Batch.btch_name == expected_batch_name, Batch.bttp_bttp_id == batch_type_id).one()
    except Exception, e:
        log('ERROR in check_batch: %s' % e)
        return 0
    return 1


def check_devices_status(sqlalchemy_con, pttp_id, start_devc, end_devc, expected_status):
    dvc_statuses = list(set(sqlalchemy_con.session.query(Device.dvst_dvst_id).filter(Device.pttp_pttp_id == pttp_id, Device.devc_num >= start_devc, Device.devc_num <= end_devc).all()))
    assert(len(dvc_statuses) == 1 and dvc_statuses[0][0] == expected_status), 'In range [%s:%s] exists status different from %s' % (start_devc, end_devc, expected_status)


def get_devices_random_range_by_status(sqlalchemy_con, pttp_id,  count, status):
    if status:
        devc_range_db = sqlalchemy_con.session.query(func.min(Device.devc_num), func.max(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id, Device.dvst_dvst_id == status).one()
        current_devc = devc_range_db[0]
        while current_devc < devc_range_db[1]:
            i = 0
            for device in range(current_devc, current_devc+count):
                i += 1
                devc_st = sqlalchemy_con.session.query(Device.dvst_dvst_id).filter(Device.devc_num == device, Device.pttp_pttp_id == pttp_id).one()[0]
                if devc_st != status:
                    current_devc = device + 1
                    break
                if i == count:
                    log('get_devices_random_range_by_status %s return [%s-%s]' % (status, current_devc, current_devc+count-1))
                    return [current_devc, current_devc+count-1]
        log('get_devices_random_range_by_status %s return 0' % status)
        return 0
    else:
        devc_range_db = sqlalchemy_con.session.query(func.min(Device.devc_num), func.max(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id).one()
        start_devc = random.randint(devc_range_db[0], devc_range_db[1]-count)
        return [start_devc, start_devc+count-1]


def get_unique_key_index(sqlalchemy_con, pttp_id):
    return sqlalchemy_con.session.query(DeviceKeymap.key_index).order_by(func.random()).filter(DeviceKeymap.dvcl_dvcl_id == DeviceClass.dvcl_id, DeviceClass.dvcl_id == PartType.dvcl_dvcl_id, PartType.pttp_id == pttp_id, DeviceKeymap.key_length >= 128, DeviceKeymap.key_type == 'U').limit(1).all()[0][0]

