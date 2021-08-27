
import StringIO
from DB_ORM_classes import *
from Database import *
import sqlalchemy, json
import random, time, re
from keywords.KMIDalKeywords import *
import Helpers.KmiHelper as kmihelper
from Logger import log
from sqlalchemy.sql.expression import func
from keywords.TestRailKW import get_data_from_file


device_type_dict = {'DevTypeGeneric': 1, 'DevTypeSC6': 2}


class AuxKeys:
    le_keys = 1
    ck_ip_keys = 2
    pairing_keys = 3


def key_map_item_to_key_info(key_map_item):
    if key_map_item.keyLength % 8:
        raise ValueError('Length of key {0} (\'{1}\') is not byte-aligned'.format(
            key_map_item.keyIndex, key_map_item.keyName))
    return keygen.KeyInfo(
        key_map_item.keyIndex,
        key_map_item.keyLength / 8,
        keygen.KeyType_Common if key_map_item.keyType == kmi.KeyTypeCommon else keygen.KeyType_Unique)


def convert_key_map_to_key_infos(key_map):
    return keygen.KeyInfoVector(
        sorted((key_map_item_to_key_info(i) for i in key_map),
               key=lambda x: x.keyIndex))


def create_keymap_for_akms(case_id, dvcl_id):
    keymap_data = get_data_from_file(case_id)
    keys = StringIO.StringIO(keymap_data).readlines()[3:]
    for line in keys:
        idx, type,code,len,is_obf, need_obf, is_root,is_scemu, is_block = line.split(';')[:-1];
        kmi_addKeyMapItem(int(idx), code, 1 if type=='C' else 2, int(len), dvcl_id, int(is_obf), int(need_obf), int(is_root), int(is_scemu), int(is_block))
    print 1


def clear_pttp_for_akms(db, pttp_id):
    db.session.query(DeviceHistory).filter(DeviceHistory.pttp_pttp_id == pttp_id).delete()
    db.session.query(PartTypeKey).filter(PartTypeKey.pttp_pttp_id==pttp_id).delete()
    db.session.query(DeviceKey).filter(DeviceKey.pttp_pttp_id==pttp_id).delete()
    db.session.query(Device).filter(Device.pttp_pttp_id==pttp_id).delete()
    db.session.commit()


def link_pttp_to_dvcl(db, pttp_id, dvcl_id):
    db.session.query(PartType).filter(PartType.pttp_id==pttp_id).update({PartType.dvcl_dvcl_id:dvcl_id},synchronize_session=False)
    db.session.commit()


def create_keymap_for_amlogic(dvcl_id):
    kmi_addKeyMapItem(1, 'Seed_%s' % dvcl_id, 2, 128, dvcl_id, 1, 0, 1)
    kmi_addKeyMapItem(2, 'OTP Key B_%s' % dvcl_id, 2, 128, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(3, 'OTP Key C_%s' % dvcl_id, 1, 128, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(4, 'OTP Key D_%s' % dvcl_id, 1, 128, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(5, 'OTP Key A_%s' % dvcl_id, 2, 128, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(6, 'JTAG_%s' % dvcl_id, 2, 64, dvcl_id, 0, 1, 1)


def create_keymap_for_dvcl(dvcl_id):
    kmi_addKeyMapItem(1, 'common1_%s' % dvcl_id, 1, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(2, 'common2_%s' % dvcl_id, 1, 128, dvcl_id, 1, 0, 1)
    kmi_addKeyMapItem(3, 'common3_%s' % dvcl_id, 1, 256, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(4, 'unique1_%s' % dvcl_id, 2, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(5, 'unique2_%s' % dvcl_id, 2, 128, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(6, 'unique3_%s' % dvcl_id, 2, 256, dvcl_id, 0, 1, 1)

def create_keymap_for_dvcl_only_fw_keys(dvcl_id):
    kmi_addKeyMapItem(1, 'common1_%s' % dvcl_id, 1, 2048, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(2, 'common2_%s' % dvcl_id, 1, 128, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(3, 'common3_%s' % dvcl_id, 1, 192, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(4, 'common4_%s' % dvcl_id, 1, 256, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(5, 'common5_%s' % dvcl_id, 1, 128, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(6, 'common6_%s' % dvcl_id, 1, 1280, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(7, 'common7_%s' % dvcl_id, 1, 4096, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(8, 'common8_%s' % dvcl_id, 1, 256, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(9, 'common9_%s' % dvcl_id, 1, 2048, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(10, 'common10_%s' % dvcl_id, 1, 128, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(11, 'common11_%s' % dvcl_id, 1, 256, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(12, 'common12_%s' % dvcl_id, 1, 192, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(13, 'common13_%s' % dvcl_id, 1, 192, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(14, 'common14_%s' % dvcl_id, 1, 160, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(15, 'common15_%s' % dvcl_id, 1, 1296, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(16, 'common16_%s' % dvcl_id, 1, 1296, dvcl_id, 0, 0, 0)

def create_keymap_for_dvcl_without_obf(dvcl_id):
    kmi_addKeyMapItem(1, 'common1_%s' % dvcl_id, 1, 64, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(2, 'common2_%s' % dvcl_id, 1, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(3, 'common3_%s' % dvcl_id, 1, 256, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(4, 'unique1_%s' % dvcl_id, 2, 64, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(5, 'unique2_%s' % dvcl_id, 2, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(6, 'unique3_%s' % dvcl_id, 2, 256, dvcl_id, 0, 0, 1)


def create_keymap_with_one_seed(dvcl_id):
    kmi_addKeyMapItem(1, 'common1_%s' % dvcl_id, 1, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(2, 'common2_%s' % dvcl_id, 1, 128, dvcl_id, 1, 0, 1)
    kmi_addKeyMapItem(3, 'common3_%s' % dvcl_id, 1, 256, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(4, 'unique1_%s' % dvcl_id, 2, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(5, 'unique2_%s' % dvcl_id, 2, 128, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(6, 'unique3_%s' % dvcl_id, 2, 256, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(66, 'unique4_%s' % dvcl_id, 2, 192, dvcl_id, 0, 1, 1)


def create_keymap_with_two_seed(dvcl_id):
    kmi_addKeyMapItem(1, 'common1_%s' % dvcl_id, 1, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(2, 'common2_%s' % dvcl_id, 1, 128, dvcl_id, 1, 0, 1)
    kmi_addKeyMapItem(3, 'common3_%s' % dvcl_id, 1, 256, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(4, 'unique1_%s' % dvcl_id, 2, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(5, 'unique2_%s' % dvcl_id, 2, 128, dvcl_id, 1, 0, 1)
    kmi_addKeyMapItem(6, 'unique3_%s' % dvcl_id, 2, 256, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(66, 'unique4_%s' % dvcl_id, 2, 192, dvcl_id, 0, 1, 1)


def create_keymap_with_one_seed_and_FW_keys(dvcl_id):
    kmi_addKeyMapItem(1, 'common1_%s' % dvcl_id, 1, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(2, 'common2_%s' % dvcl_id, 1, 128, dvcl_id, 1, 0, 1)
    kmi_addKeyMapItem(3, 'common3_%s' % dvcl_id, 1, 256, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(4, 'unique1_%s' % dvcl_id, 2, 64, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(5, 'unique2_%s' % dvcl_id, 2, 128, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(6, 'unique3_%s' % dvcl_id, 2, 256, dvcl_id, 0, 1, 1)
    kmi_addKeyMapItem(7, 'aes128_%s' % dvcl_id, 1, 128, dvcl_id, 0, 1, 0)
    kmi_addKeyMapItem(8, 'aes256_%s' % dvcl_id, 1, 256, dvcl_id, 0, 1, 0)
    kmi_addKeyMapItem(9, 'rsa_pub_exp_%s' % dvcl_id, 1, 32, dvcl_id, 0, 1, 0)
    kmi_addKeyMapItem(10, 'rsa_pub_mod_%s' % dvcl_id, 1, 2048, dvcl_id, 0, 1, 0)


def create_keymap_for_aps(dvcl_id):
    kmi_addKeyMapItem(1, 'CAS5_COMMON_ENC_KEY16B_0', 1, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(5, 'CAS5_COMMON_ENC_KEY16B_1', 1, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(9, 'CAS5_COMMON_ENC_KEY16B_2', 1, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(13, 'CAS5_COMMON_ENC_KEY32B_0', 1, 256, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(17, 'CAS5_COMMON_HASH_KEY32B_0', 1, 256, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(21, 'CAS5_COMMON_HASH_KEY32B_1', 1, 256, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(29, 'CAS5_INDIVIDUAL_ENC_KEY16B_0', 1, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(33, 'CAS5_INDIVIDUAL_ENC_KEY16B_1', 2, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(37, 'CAS5_INDIVIDUAL_ENC_KEY16B_2', 2, 128, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(45, 'CAS5_INDIVIDUAL_HASH_KEY32B_0', 2, 256, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(49, 'CAS5_INDIVIDUAL_HASH_KEY32B_1', 2, 256, dvcl_id, 0, 0, 1)
    kmi_addKeyMapItem(60, 'FIRMWARE_RSA_PUBLIC_MODULUS_KEY256B', 1, 2048, dvcl_id, 0, 0, 0)
    kmi_addKeyMapItem(61, 'FIRMWARE_RSA_PUBLIC_EXPONENT_KEY16B', 1, 128, dvcl_id, 0, 0, 0)


def get_keymap_by_dvcl(dvcl_id):
        return convert_key_map_to_key_infos(kmi_get_key_map(dvcl_id))


def get_keymaps_length(sqlalchemy_connection, dev_cl_id):
        keys_length = sqlalchemy_connection.session.query(DeviceKeymap.key_length).filter(DeviceKeymap.dvcl_dvcl_id == dev_cl_id).all()
        key_length = 0
        for item in keys_length:
            key_length += item[0]
        return key_length


def get_number_vendors(sqlalchemy_con):
    return sqlalchemy_con.session.query(Vendor).count()

def get_rows_kmi_part_number(sqlalchemy_con):
    return sqlalchemy_con.session.query(PartNumber).count()

def get_rows_kmi_operators(sqlalchemy_con):
    return sqlalchemy_con.session.query(Operator).count()

def get_rows_kmi_manufactures(sqlalchemy_con):
    return sqlalchemy_con.session.query(Manufacturer).count()

def get_operator_id_by_name(sqlalchemy_con, operator_name, deleting):
    if deleting is None:
        query = sqlalchemy_con.session.query(Operator.oper_id).filter(Operator.oper_name == operator_name, Operator.del_date == None)
    else:
        query = sqlalchemy_con.session.query(Operator.oper_id).filter(Operator.oper_name == operator_name, Operator.del_date != None)
    try:
        id = query.one()
        return id[0]
    except Exception, x:
        log(x)
        return 0

def get_any_operator_name(sqlalchemy_con, deleting):
    if deleting is None:
        query = sqlalchemy_con.session.query(Operator.oper_name).filter(Operator.del_date == None)
    else:
        query = sqlalchemy_con.session.query(Operator.oper_name).filter(Operator.del_date != None)
    try:
        names = query.all()
        return random.choice(names)[0]
    except Exception, x:
        log(x)
        return 0

def get_operator_name_by_id(sqlalchemy_con, operator_id, deleting):
    if deleting is None:
        query = sqlalchemy_con.session.query(Operator.oper_name).filter(Operator.oper_id == operator_id, Operator.del_date == None)
    else:
        query = sqlalchemy_con.session.query(Operator.oper_name).filter(Operator.oper_id == operator_id, Operator.del_date != None)
    try:
        name = query.one()
        return name[0]
    except Exception, x:
        log(x)
        return 0

def get_vendor_id_by_name(sqlalchemy_con, vnd_name, deleting):
    if deleting is None:
        query = sqlalchemy_con.session.query(Vendor.vndr_id).filter(Vendor.vndr_name == vnd_name, Vendor.del_date == None)
    else:
        query = sqlalchemy_con.session.query(Vendor.vndr_id).filter(Vendor.vndr_name == vnd_name, Vendor.del_date != None)
    try:
        id = query.one()
        return id[0]
    except Exception, x:
        log(x)
        return 0

def get_vendor_name_by_id(sqlalchemy_con, vendor_id, deleting):
    if deleting is None:
        query = sqlalchemy_con.session.query(Vendor.vndr_name).filter(Vendor.vndr_id == vendor_id, Vendor.del_date == None)
    else:
        query = sqlalchemy_con.session.query(Vendor.vndr_name).filter(Vendor.vndr_id == vendor_id, Vendor.del_date != None)
    try:
        name = query.one()
        return name[0]
    except Exception, x:
        log(x)
        return 0


def get_any_vendor_name_from_db(sqlalchemy_con):
    names = sqlalchemy_con.session.query(Vendor.vndr_name).filter(Vendor.del_date == None).all()
    return random.choice(names)[0]

def get_any_pttp_id_with_ptnmb(sqlalchemy_con):
    ids = sqlalchemy_con.session.query(PartNumber.pttp_pttp_id).filter(PartNumber.pttp_pttp_id != None , PartNumber.del_date == None).all()
    pttp_id = random.choice(ids)[0]
    return pttp_id


def get_part_number_name_by_id(sqlalchemy_con, partnumber_id):
    ptnb_name = sqlalchemy_con.session.query(PartNumber.part_number).filter(PartNumber.ptnm_id == partnumber_id).all()
    return ptnb_name[0][0]

def check_part_number_info(sqlalchemy_con, partnumber_info, partnumber_id, is_linked_with_pttp):
    ptnb_value = sqlalchemy_con.session.query(PartNumber.part_number).filter(PartNumber.ptnm_id == partnumber_id, PartNumber.del_date == None).one()[0]
    dev_class_id = sqlalchemy_con.session.query(PartNumber.dvcl_dvcl_id).filter(PartNumber.ptnm_id == partnumber_id, PartNumber.del_date == None).one()[0]
    dev_class_name = sqlalchemy_con.session.query(DeviceClass.dvcl_name).filter(DeviceClass.dvcl_id == dev_class_id).one()[0]
    vendor_id = sqlalchemy_con.session.query(DeviceClass.vndr_vndr_id).filter(DeviceClass.dvcl_name == dev_class_name).one()[0]
    vendor_name = sqlalchemy_con.session.query(Vendor.vndr_name).filter(Vendor.vndr_id == vendor_id).one()[0]
    dvtp_dvtp_id = sqlalchemy_con.session.query(DeviceClass.dvtp_dvtp_id).filter(DeviceClass.dvcl_name == dev_class_name).one()[0]
    dvtp_name = sqlalchemy_con.session.query(DeviceType.dvtp_name).filter(DeviceType.dvtp_id == dvtp_dvtp_id).one()[0]
    if is_linked_with_pttp is not None:
        pttp_id = sqlalchemy_con.session.query(PartNumber.pttp_pttp_id).filter(PartNumber.ptnm_id == partnumber_id).one()[0]
        pttp_name = sqlalchemy_con.session.query(PartType.pttp_name).filter(PartType.pttp_id == pttp_id).one()[0]
        pttp_is_test = sqlalchemy_con.session.query(PartType.is_test_pttp).filter(PartType.pttp_name == pttp_name).one()[0]
        assert (pttp_id == partnumber_info.partTypeInfo.partTypeId), 'Wrong Part Type ID in db'
        assert (pttp_name == partnumber_info.partTypeInfo.partTypeName), 'Wrong Part Type Name in db'
        assert (pttp_is_test == partnumber_info.partTypeInfo.isTest), 'Wrong Part Type =is_test= in db'
    else:
        log('Check Whithout PartType')
    assert(partnumber_id == partnumber_info.partNumberId), 'Wrong PartNumber id in db'
    assert(ptnb_value == partnumber_info.partNumberValue), 'Wrong PartNumber Name in db'
    assert(dev_class_id == partnumber_info.deviceClassInfo.deviceClassId), 'Wrong Device Class id in db'
    assert(dev_class_name == partnumber_info.deviceClassInfo.deviceClassName), 'Wrong Device Class name in db'
    assert(vendor_id == partnumber_info.deviceClassInfo.vendorInfo.vendorId), 'Wrong Vendor Id in db'
    assert(vendor_name == partnumber_info.deviceClassInfo.vendorInfo.vendorName), 'Wrong Vendor Name in db'
    assert(dvtp_dvtp_id == partnumber_info.deviceClassInfo.deviceType), 'Wrong Device Type ID in db'
    assert(dvtp_name == partnumber_info.deviceClassInfo.deviceTypeName), 'Wrong Device Type Name in db'

def get_manufacturer_id_by_name(sqlalchemy_con, manufacturerName):
    manufacturerId = sqlalchemy_con.session.query(Manufacturer.mfct_id).filter(Manufacturer.mfct_name == manufacturerName, Manufacturer.del_date == None).one()[0]
    return manufacturerId

def get_any_manufacturer_id_with_stbm(sqlalchemy_con):
    mfct_name = sqlalchemy_con.session.query(StbModel.mfct_mfct_id).filter(StbModel.del_date == None).all()
    return random.choice(mfct_name)[0]

def check_manufacturer_info(sqlalchemy_con, manufacturer_info, manufacturer_id, stb_model):
    manufacturer_name = sqlalchemy_con.session.query(Manufacturer.mfct_name).filter(Manufacturer.mfct_id == manufacturer_id, Manufacturer.del_date == None).one()[0]
    assert (manufacturer_info.manufacturerName == manufacturer_name), 'Wrong manufacturer_name in db'
    assert (manufacturer_info.manufacturerId == manufacturer_id), 'Wrong manufacturer_id in db'
    if stb_model is not None:
        stbm_info = tuple(manufacturer_info.stbModelList)
        stbm_info_db = sqlalchemy_con.session.query(StbModel.stbm_id, StbModel.stbm_name).filter(StbModel.mfct_mfct_id == manufacturer_id, StbModel.del_date == None).all()
        stbm_list_from_kmi = convert_to_list('stbm', stbm_info)
        stbm_list_from_db = convert_to_list('stbm' ,stbm_info_db)
        if len(stbm_list_from_kmi) != len(stbm_list_from_db):
            log('length of kmi_list = %s , length of stbm from DB = %s' % (len(stbm_list_from_kmi), len(stbm_list_from_db)))
            return 0
        diff = [item for item in stbm_list_from_db if not item in stbm_list_from_kmi]
        if len(diff) == 0:
            log('==========Checking StbModel SUCCESS==========')
            return 1
        else:
            log('There are StbModel : %s in DB but not in from KMI ' % diff)
            return 0
    return 1

def check_manufacturer_list(sqlalchemy_con, manufacturer_list):
    manufacturer_list_from_db = sqlalchemy_con.session.query(Manufacturer.mfct_id, Manufacturer.mfct_name).filter(Manufacturer.del_date == None)
    manufacturer_list_kmi = convert_to_list('manufacturer', manufacturer_list)
    manufacturer_list_db = convert_to_list('manufacturer', manufacturer_list_from_db)
    if len(manufacturer_list_kmi) != len(manufacturer_list_db):
        log('length of kmi_list = %s , length of manufacturer from DB = %s' % (len(manufacturer_list_kmi), len(manufacturer_list_db)))
        return 0
    diff = [item for item in manufacturer_list_db if not item in manufacturer_list_kmi]
    if len(diff) == 0:
        log('==========Checking Manufacturer SUCCESS==========')
        return 1
    else:
        log('There are Manufacturer : %s in DB but not in from KMI ' % diff)
        return 0

def check_manufacture_deleted(sqlalchemy_con, manufacture_id):
    is_deleted = sqlalchemy_con.session.query(Manufacturer.del_date).filter(Manufacturer.mfct_id == manufacture_id).one()[0]
    if is_deleted == None:
        log('ERROR Del_date empty')
        return 0
    else:
        return 1

def get_any_linked_stb_model_to_pttp(sqlalchemy_con):
        stbModel_id = random.choice(sqlalchemy_con.session.query(StbmodelParttype.stbm_stbm_id).filter(StbModel.del_date == None).all())[0]
        return stbModel_id


def get_any_vendor_id_from_db(sqlalchemy_con):
    ids = sqlalchemy_con.session.query(Vendor.vndr_id).filter(Vendor.del_date == None).all()
    return random.choice(ids)[0]


def get_any_vendor_id_from_db_without_dev_classes(sqlalchemy_con):
    vendor_ids = sqlalchemy_con.session.query(Vendor.vndr_id).filter(~Vendor.vndr_id.in_(sqlalchemy_con.session.query(DeviceClass.vndr_vndr_id).all()), Vendor.del_date == None).all()
    try:
        return random.choice(vendor_ids)[0]
    except Exception,e:
        return kmi_addVendor('Vendor_%s'% time.ctime())


def get_any_vendor_id_from_db_with_dev_classes(sqlalchemy_con):
    vendor_ids = sqlalchemy_con.session.query(Vendor.vndr_id).filter(Vendor.vndr_id.in_(sqlalchemy_con.session.query(DeviceClass.vndr_vndr_id).all())).all()
    return random.choice(vendor_ids)[0]


def delete_vendor(sqlalchemy_con, vendor_name):
    sqlalchemy_con.session.query(Vendor).filter(Vendor.vndr_name == vendor_name).delete()
    sqlalchemy_con.session.commit()


kmi_fields = {'vendor':('vendorId', 'vendorName'),
              'operator': ('operatorId', 'operatorName'),
              'stbm':('stbModelId', 'stbModelName'),
              'manufacturer':('manufacturerId', 'manufacturerName'),
              'dvcl':('deviceClassId', 'deviceClassName')}

db_fields = {'vendor':('vndr_id', 'vndr_name'),
             'operator': ('oper_id', 'oper_name'),
             'stbm': ('stbm_id', 'stbm_name'),
             'manufacturer':('mfct_id', 'mfct_name'),
             'dvcl': ('dvcl_id', 'dvcl_name')}

def convert_to_list(item_name, object):
    convert_list=[]
    if type(object) == tuple:
        fields = kmi_fields[item_name]
    else:
        fields = db_fields[item_name]
    for item in object:
        id = fields[0]
        name = fields[1]
        elements = dict([('Id', getattr(item,id)), ('Name', getattr(item,name))])
        convert_list.append(elements)
    return convert_list


def convert_device_classes_to_list(device_classes):
    log('Convert device_classes to list: type - %s, list - %s' % (type(device_classes), device_classes))
    converted_list = []
    print str(type(device_classes))
    if 'list' in str(type(device_classes)):
        for dvcl in device_classes:
            dvcl_dict = dict([('deviceClassName', dvcl[0]), ('deviceClassId', dvcl[1]), ('deviceTypeName', dvcl[2])])
            converted_list.append(dvcl_dict)
    else:
        for dvcl in device_classes:
            dvcl_dict = dict([('deviceClassName', dvcl.deviceClassName), ('deviceClassId', dvcl.deviceClassId), ('deviceTypeName', dvcl.deviceTypeName)])
            converted_list.append(dvcl_dict)
    return converted_list


def check_vendor_list(sqlalchemy_con, kmi_vendor_list):
    vendors_from_db = sqlalchemy_con.session.query(Vendor.vndr_name, Vendor.vndr_id).filter(Vendor.del_date == None).all()
    vendor_list_from_kmi = convert_to_list('vendor', kmi_vendor_list)
    vendor_list_from_db = convert_to_list('vendor', vendors_from_db)
    if len(vendor_list_from_kmi) != len(vendor_list_from_db):
        log('length of kmi_list = %s , length of vendors from DB = %s' % (len(vendor_list_from_kmi), len(vendor_list_from_db)))
        return 0
    diff = [item for item in vendor_list_from_db if not item in vendor_list_from_kmi]
    if len(diff) == 0:
        log('==========Checking vendors SUCCESS==========')
        return 1
    else:
        log('There are vendors : %s in DB but not in from KMI ' % diff)
        return 0

def check_operator_list(sqlalchemy_con, operator_list):
    operator_from_db = sqlalchemy_con.session.query(Operator).filter(Operator.del_date == None).all()
    operator_list_from_db = convert_to_list('operator', operator_from_db)
    operator_list_from_kmi = convert_to_list('operator', operator_list)
    if len(operator_list_from_db) != len(operator_list_from_kmi):
        log('length of kmi_list = %s , length of operators from DB = %s' % (len(operator_list_from_db), len(operator_list_from_kmi)))
        return 0
    diff = [item for item in operator_list_from_db if not item in operator_list_from_kmi]
    if len(diff) == 0:
        log('==========Checking Operators SUCCESS==========')
        return 1
    else:
        log('There are vendors : %s in DB but not in from KMI ' % diff)
        return 0



def check_vendor_in_db(sqlalchemy_con, vendor_name):
    try:
        sqlalchemy_con.session.query(Vendor).filter(Vendor.vndr_name == vendor_name, Vendor.del_date == None).one()
        return 1
    except Exception, e:
        log(e)
        return 0


def check_vendor_info(sqlalchemy_con, vendor_info, device_class_id):
    try:
        device_class = sqlalchemy_con.session.query(DeviceClass).filter(DeviceClass.dvcl_id == device_class_id).one()
    except Exception, x:
        log(x)
        return 0
    if device_class.vendor.vndr_name == vendor_info.vendorName and device_class.vendor.vndr_id == vendor_info.vendorId:
        log('Checking vendor_info for device_class %s SUCCESS' % device_class_id)
        return 1
    log('Checking vendor_info for device_class %s NOT SUCCESS' % device_class_id)
    return 0


def check_dev_class_list(sqlalchemy_con, vendor_id, dev_class_list):
    if len(dev_class_list) == 0:
        log('In DB NO device classes fro vendor %s ' % vendor_id)
    dev_cl_db = sqlalchemy_con.session.query(DeviceClass.dvcl_name, DeviceClass.dvcl_id, DeviceType.dvtp_name).filter(DeviceClass.dvtp_dvtp_id == DeviceType.dvtp_id, DeviceClass.vndr_vndr_id == vendor_id, DeviceClass.del_date == None).all()
    device_classes_from_db = convert_device_classes_to_list(dev_cl_db)
    device_classes_from_kmi = convert_device_classes_to_list(dev_class_list)
    log('Device class list from db : %s' % device_classes_from_db)
    log('Device class list from KMI : %s' % device_classes_from_kmi)
    if len(device_classes_from_kmi) != len(device_classes_from_db):
        log('length of device_classes_from_kmi = %s , length device_classes_from_db = %s' % (
            len(device_classes_from_kmi), len(device_classes_from_db)))
        return 0
    diff = [item for item in device_classes_from_db if not item in device_classes_from_kmi]
    if len(diff) == 0:
        log('==========Checking device_class_list success==========')
        return 1
    else:
        log('There are device_classes : %s in DB but not in from KMI ' % diff)
        return 0


def get_device_class_id_for_vendor_by_name(sqlalchemy_con, vndr_id, dev_cl_name, device_type=1):
    if device_type == 'SC6':
        device_type = 2
    try:
        dev_cl_id = sqlalchemy_con.session.query(DeviceClass.dvcl_id).filter(DeviceClass.vndr_vndr_id == vndr_id, DeviceClass.dvcl_name == dev_cl_name, DeviceClass.dvtp_dvtp_id == device_type).one()
        return dev_cl_id[0]
    except Exception, x:
        log(x)
        return 0


def get_devcl_name_by_id(sqlalchemy_con, dvcl_id, del_date):
    if del_date is None:
        query = sqlalchemy_con.session.query(DeviceClass.dvcl_name).filter(DeviceClass.dvcl_id == dvcl_id, DeviceClass.del_date == None)
    else:
        query = sqlalchemy_con.session.query(DeviceClass.dvcl_name).filter(DeviceClass.dvcl_id == dvcl_id, DeviceClass.del_date != None)
    try:
        device_cl_name = query.one()
        log('get_devcl_name_by_id return %s' % device_cl_name[0])
        return device_cl_name[0]
    except Exception, x:
        log('query: %s' % query)
        return 0

def get_any_device_class_whith_partnumbers(sqlalchemy_con):
    dvcl_ids = sqlalchemy_con.session.query(PartNumber.dvcl_dvcl_id).filter(PartNumber.del_date == None).all()
    try:
        dvcl_id = random.choice(dvcl_ids)[0]
    except Exception as E:
        log('In db Table Part_numbers EMPTY')
        return 0
    return dvcl_id

def get_any_device_class_id_from_db(sqlalchemy_con, device_type=1):
    if device_type == 'SC6':
        device_type = 2
    dvcl_ids = sqlalchemy_con.session.query(DeviceClass.dvcl_id).filter(DeviceClass.del_date == None, DeviceClass.dvtp_dvtp_id == device_type).all()
    try:
        dvcl_id = random.choice(dvcl_ids)[0]
    except Exception as E:
        log('In DB no device_class with type %s, trying to add it' % device_type)
        vndr_id = get_any_vendor_id_from_db(sqlalchemy_con)
        dvcl_id = kmi_addDeviceClass('DeviceClass_%s' % time.time(),vndr_id, device_type)
    return dvcl_id


def get_any_device_class_id_from_db_with_keymap(sqlalchemy_con):
    dvcl_ids = sqlalchemy_con.session.query(DeviceKeymap.dvcl_dvcl_id).filter(DeviceKeymap.is_otp_key == 1, DeviceKeymap.dvcl_dvcl_id == DeviceClass.dvcl_id, DeviceClass.del_date == None).all()
    unique_dvcl_ids = list(set(dvcl_ids))
    count = len(unique_dvcl_ids)
    if count == 0:
        vndr_id = get_any_vendor_id_from_db(sqlalchemy_con)
        devcl_id = kmi_addDeviceClass('DeviceClass_with_keymap', vndr_id)
        create_keymap_for_dvcl(devcl_id)
    else:
        devcl_id = random.choice(unique_dvcl_ids)[0]
    return devcl_id


def get_any_device_class_id_from_db_without_pttp(sqlalchemy_con):
    dvcl_ids = sqlalchemy_con.session.query(DeviceClass.dvcl_id).filter(~DeviceClass.dvcl_id.in_(sqlalchemy_con.session.query(PartType.dvcl_dvcl_id).all()), DeviceClass.del_date == None).all()
    if len(dvcl_ids) == 0:
        vndr_id = get_any_vendor_id_from_db(sqlalchemy_con)
        devcl_id = kmi_addDeviceClass('DeviceClass_without_pttp', vndr_id)
    else:
        devcl_id = random.choice(dvcl_ids)[0]
    return devcl_id


def restore_device_class(sqlalchemy_con, devcl_id):
    sqlalchemy_con.session.query(DeviceClass).filter_by(dvcl_id=devcl_id).update({DeviceClass.del_date: None})
    sqlalchemy_con.session.commit()


def check_key_map_list(sqlalchemy_con, key_maps, devcl_id):
    key_map_from_db = sqlalchemy_con.session.query(DeviceKeymap).filter(DeviceKeymap.dvcl_dvcl_id == devcl_id).all()
    if len(key_maps) != len(key_map_from_db):
        log('Length of keymap not equal: from DB %s , from KMI %s' % (len(key_map_from_db), len(key_maps)))
        return 0
    dict_key_type = {1: 'C', 2: 'U'}
    for item1 in key_maps:
        j = 0
        for item2 in key_map_from_db:
            j += 1
            if item1.itemId == item2.dvkm_id and item1.keyIndex == item2.key_index and item1.keyCode == item2.key_code and dict_key_type[item1.keyType] == item2.key_type and item1.keyLength == item2.key_length and int(item1.isObfuscationData) == item2.is_obfuscation_value and int(item1.needObfuscation) == item2.need_obfuscation:
                break
            if j == len(key_maps):
                log('There are no key in DB with dvkm_id %s and key_code %s , but this key in key_map from KMI' % (item1.itemId, item1.keyCode))
                return 0
    log('Checking key_maps for device_class %s SUCCESS' % devcl_id)
    return 1


def check_part_number_list(sqlalchemy_con, part_nmb_list, devcl_id):
    if len(part_nmb_list) == 0:
        return 0
    part_numbers_from_db = sqlalchemy_con.session.query(PartNumber).filter(PartNumber.dvcl_dvcl_id == devcl_id, PartNumber.del_date == None).all()
    if len(part_nmb_list) != len(part_numbers_from_db):
        log('Length of part_nmb_list not equal: from DB %s , from KMI %s' % (len(part_numbers_from_db), len(part_nmb_list)))
        return 0
    for item1 in part_nmb_list:
        i = 0
        for item2 in part_numbers_from_db:
            i += 1
            if item1.partNumberId == item2.ptnm_id and item1.partNumberValue == item2.part_number:
                break
            if i == len(part_nmb_list):
                log('There are no part_number in DB with ptnm_id %s and name %s , but this part_number in part_number_list from KMI' % (item1.partNumberId, item1.partNumberValue))
                return 0
    log('Checking part_numbers for device_class %s SUCCESS' % devcl_id)
    return 1


def check_part_type_list(sqlalchemy_con, part_type_list, devcl_id):
    log('part_type_list from KMI: %s, with length %s' % (part_type_list, len(part_type_list)))
    part_types_from_db = sqlalchemy_con.session.query(PartType.pttp_id, PartType.pttp_name).filter(PartType.dvcl_dvcl_id == devcl_id, PartType.del_date == None).all()
    log('part_types_fromDB: %s' % part_types_from_db)
    if len(part_type_list) != len(part_types_from_db):
        log('Length of part_type_list not equal: from DB %s , from KMI %s' % (len(part_types_from_db), len(part_type_list)))
        return 0
    if len(part_type_list) == 0:
        log('There are No part types for device class %s' % devcl_id)
        return 1
    for item1 in part_type_list:
        i = 0
        log('part_type_from Kmi: %s - %s' % (item1.partTypeId, item1.partTypeName))
        for item2 in part_types_from_db:
            i += 1
            if (item1.partTypeId == item2.pttp_id and item1.partTypeName == item2.pttp_name):
                break
            if i == len(part_type_list):
                log('There are no part_type in DB with partTypeId %s and name %s , but this part_type in part_type_list from KMI' % (item1.partTypeId, item1.partTypeName))
                return 0
    log('Checking part_types for device_class %s SUCCESS' % devcl_id)
    return 1

def get_all_pttp_ids(sqlalchemy_con, is_test=0):
    return sqlalchemy_con.session.query(PartType.pttp_id).filter(PartType.del_date == None, PartType.is_test_pttp == is_test).all()

def get_any_part_type_id_from_db(sqlalchemy_con, is_test=0):
    pttp_ids = sqlalchemy_con.session.query(PartType.pttp_id).filter(PartType.del_date == None, PartType.is_test_pttp == is_test).all()
    if len(pttp_ids) == 0:
        dev_cl = get_any_device_class_id_from_db(sqlalchemy_con)
        pttp_name = 'FirstPartType' if is_test == 0 else 'FirstPartType_Test'
        pttp_id = add_pttp_with_keys(sqlalchemy_con, pttp_name, dev_cl, 1, 100, is_test)
    else:
        pttp_id = random.choice(pttp_ids)[0]
    return pttp_id


def get_pttp_name_by_id(sqlalchemy_con, pttp_id):
    return sqlalchemy_con.session.query(PartType.pttp_name).filter(PartType.pttp_id == pttp_id).one()[0]


def get_any_partnumber_id_by_pttp(sqlalchemy_con, pttp_id):
    if pttp_id == 0:
        ptnmb_ids = sqlalchemy_con.session.query(PartNumber.ptnm_id).filter(PartNumber.del_date == None).all()
    else:
        ptnmb_ids = sqlalchemy_con.session.query(PartNumber.ptnm_id).filter(PartNumber.del_date == None, PartNumber.pttp_pttp_id == pttp_id).all()
    return random.choice(ptnmb_ids)[0]


def is_part_number_deleted(sqlalchemy_con, partnumber_id):
    ptnb_del_date = sqlalchemy_con.session.query(PartNumber.del_date).filter(PartNumber.ptnm_id == partnumber_id).all()
    if ptnb_del_date[0][0] == None:
        log("ERROR Del date empty")
        return 0
    else:
        return 1


def check_part_number(sqlalchemy_con, partnumber_name, partnumber_id):
    ptnb_name = sqlalchemy_con.session.query(PartNumber.part_number).filter(PartNumber.ptnm_id == partnumber_id).all()
    assert(len(ptnb_name) != 0), "IN database no Partnumber whith name: %s" % partnumber_name
    assert(ptnb_name[0][0] == partnumber_name), 'Wrong part_number in db'


def get_devcl_id_by_pttp_id(sqlalchemy_con, pttp_id):
    return sqlalchemy_con.session.query(PartType.dvcl_dvcl_id).filter(PartType.pttp_id == pttp_id, PartType.del_date == None).one()[0]


def get_nextfree_operator_id(sqlalchemy_con, start_operator_id=1):
    operator_tupels = sqlalchemy_con.session.query(Operator.oper_id).order_by(Operator.oper_id).all()
    operator_list = [item[0] for item in operator_tupels]
    free_operator_id = kmihelper.get_nextfree_value_from_list(operator_list, start_operator_id)
    return free_operator_id

def check_operator_info(sqlalchemy_con, operator_info, operator_id):
    operator_info_from_db = sqlalchemy_con.session.query(Operator.oper_id, Operator.oper_name).filter(Operator.oper_id == operator_id).one()
    assert(operator_info.operatorId == operator_info_from_db[0]), 'Wrong operator id in db'
    assert(operator_info.operatorName == operator_info_from_db[1]), 'Wrong operator name in db'


def get_nextfree_pttp_id(sqlalchemy_con, start_pttp=1):
    pttps_tuples = sqlalchemy_con.session.query(PartType.pttp_id).order_by(PartType.pttp_id).all()
    pttp_list = [item[0] for item in pttps_tuples]
    free_pttp_id = kmihelper.get_nextfree_value_from_list(pttp_list, start_pttp)
    log('Next free pttp_id = %s' % free_pttp_id)
    return free_pttp_id

def get_nextfree_partnumber_id(sqlalchemy_con, start_ptnb=1):
    ptnb_tupels = sqlalchemy_con.session.query(PartNumber.ptnm_id).order_by(PartNumber.ptnm_id).all()
    ptnb_list = [item[0] for item in ptnb_tupels]
    free_ptnb_id = kmihelper.get_nextfree_value_from_list(ptnb_list, start_ptnb)
    log('Next free ptnb_id = %s' % free_ptnb_id)
    return free_ptnb_id


def get_next_free_device_class(sqlalchemy_con):
    dvcl_tuples = sqlalchemy_con.session.query(DeviceClass.dvcl_id).order_by(DeviceClass.dvcl_id).all()
    dvcl_list = [item[0] for item in dvcl_tuples]
    free_dvcl = kmihelper.get_nextfree_value_from_list(dvcl_list)
    log('Next free dvcl_id = %s' % free_dvcl)
    return free_dvcl

def add_devices_to_blacklist(sqlalchemy_con, pttp_id, count):
    devices = sqlalchemy_con.session.query(Device.devc_num).filter(Device.pttp_pttp_id == pttp_id).order_by(func.random()).limit(count).all()
    status = 0
    for device in devices:
        if status == 7:
            status = 0
        status += 1
        sqlalchemy_con.session.query(Device).filter(Device.pttp_pttp_id == pttp_id, Device.devc_num == device).update(
            {Device.dvst_dvst_id: status, Device.is_committed: 1, Device.is_backed_up: 1, Device.is_blacklisted: 1},
            synchronize_session=False)
        sqlalchemy_con.session.commit()


def add_pttp_with_keys(sqlalchemy_con, pttp_name, dvcl_id, start_device, end_device, uniq_keys_filename='', is_test=0):
    if uniq_keys_filename == '':
        uniq_keys_filename = 'uniq_keys_pttp_%s' % pttp_name
    free_pttp_id = get_nextfree_pttp_id(sqlalchemy_con)
    pttp_id = kmi_addPartType(pttp_name, dvcl_id, free_pttp_id, bool(is_test))
    path_to_common_keys = os.path.join(kmihelper.get_homedir_out(), 'common_keys_pttp_%s' % pttp_name)
    path_to_uniq_keys = os.path.join(kmihelper.get_homedir_out(), uniq_keys_filename)
    key_map = convert_key_map_to_key_infos(kmi_get_key_map(dvcl_id))
    kmi_generate_common_keys(path_to_common_keys, pttp_id, dvcl_id, key_map)
    kmi_save_common_keys(pttp_id, path_to_common_keys, '')
    kmi_generate_unique_keys(path_to_uniq_keys, pttp_id, dvcl_id, start_device, end_device, path_to_common_keys, key_map)
    ans = kmi_save_unique_keys(pttp_id, start_device, end_device, 'generated_unique_keys_%s' % time.ctime(), path_to_uniq_keys)
    print 1
    if type(ans) != int:
        print 2
        sqlalchemy_con.session.query(PartTypeKey).filter(PartTypeKey.pttp_pttp_id == pttp_id).delete(synchronize_session=False)
        print 3
        sqlalchemy_con.session.commit()
        print 4
        return ans
    print 5
    sqlalchemy_con.session.query(Device).filter(Device.pttp_pttp_id == pttp_id).update({Device.is_committed:1, Device.is_backed_up:1})
    print 6
    sqlalchemy_con.session.commit()
    log('add_pttp_with_keys return %s' % pttp_id)
    return pttp_id

def add_pttp_with_keys_forced(sqlalchemy_con, pttp_name, dvcl_id, start_device, end_device, uniq_keys_filename='', is_test=0):
    if uniq_keys_filename == '':
        uniq_keys_filename = 'uniq_keys_pttp_%s' % pttp_name
    for i in range(1,10):
        free_pttp_id = get_nextfree_pttp_id(sqlalchemy_con)
        pttp_id = kmi_addPartType(pttp_name, dvcl_id, free_pttp_id, bool(is_test))
        log(('>>>>>>>>>>>>>>', pttp_id))
        if pttp_id != 'Error in kmi_addPartType':
            break
    path_to_common_keys = os.path.join(kmihelper.get_homedir_out(), 'common_keys_pttp_%s' % pttp_name)
    path_to_uniq_keys = os.path.join(kmihelper.get_homedir_out(), uniq_keys_filename)
    key_map = convert_key_map_to_key_infos(kmi_get_key_map(dvcl_id))
    kmi_generate_common_keys(path_to_common_keys, pttp_id, dvcl_id, key_map)
    kmi_save_common_keys(pttp_id, path_to_common_keys, '')
    kmi_generate_unique_keys(path_to_uniq_keys, pttp_id, dvcl_id, start_device, end_device, path_to_common_keys, key_map)
    #for i in range(1,100):
    ans = kmi_save_unique_keys(pttp_id, start_device, end_device, 'generated_unique_keys_%s' % time.time(), path_to_uniq_keys)
    #     if ans != 'ERROR in kmi_save_unique_keys':
    #        break
    if type(ans) != int:
        sqlalchemy_con.session.query(PartTypeKey).filter(PartTypeKey.pttp_pttp_id == pttp_id).delete(synchronize_session=False)
        sqlalchemy_con.session.commit()
        log(('perviy if', ans))
        return ans
    sqlalchemy_con.session.query(Device).filter(Device.pttp_pttp_id == pttp_id).update({Device.is_committed:1, Device.is_backed_up:1})
    sqlalchemy_con.session.commit()
    log(('vtoroy if', ans))
    return pttp_id


def generate_keys_for_pttp(sqlalchemy_con, pttp_id, start_devc, end_devc):
    dvcl_id  = sqlalchemy_con.session.query(PartType.dvcl_dvcl_id).filter(PartType.pttp_id == pttp_id).one()[0]
    uniq_keys_filename = 'uniq_keys_pttp_%s' % pttp_id
    path_to_common_keys = os.path.join(kmihelper.get_homedir_out(), 'common_keys_pttp_%s' % pttp_id)
    path_to_uniq_keys = os.path.join(kmihelper.get_homedir_out(), uniq_keys_filename)
    key_map = kmi_get_key_map(dvcl_id)
    keys_info = convert_key_map_to_key_infos(key_map)
    fw_ids = [item.itemId for item in key_map if item.isOtp == 0]
    for id in fw_ids:
        kmi_generate_firmware_key(id)
    kmi_generate_common_keys(path_to_common_keys, pttp_id, dvcl_id, keys_info)
    kmi_save_common_keys(pttp_id, path_to_common_keys, '')
    kmi_generate_unique_keys(path_to_uniq_keys, pttp_id, dvcl_id, start_devc, end_devc, path_to_common_keys, keys_info)
    ans = kmi_save_unique_keys(pttp_id, start_devc, end_devc, 'generated_unique_keys_%s' % time.ctime(), path_to_uniq_keys)
    if type(ans) != int:
        sqlalchemy_con.session.query(PartTypeKey).filter(PartTypeKey.pttp_pttp_id == pttp_id).delete(synchronize_session=False)
        sqlalchemy_con.session.commit()
        return ans
    sqlalchemy_con.session.query(Device).filter(Device.pttp_pttp_id == pttp_id).update({Device.is_committed: 1, Device.is_backed_up: 1})
    sqlalchemy_con.session.commit()
    os.remove(path_to_common_keys)
    os.remove(path_to_uniq_keys)
    return 1


def is_pttp_exist(sqlalchemy_con, pttp_name):
    try:
        sqlalchemy_con.session.query(PartType).filter(PartType.pttp_name == pttp_name).one()
        return 1
    except Exception,e:
        log('is_pttp_exist SAYS: %s' % e)
        return 0


def add_pttp_with_blacklisted_devices(sqlalchemy_con, pttp_name, dvcl_id, start_device, end_device, count_blacklisted_devices):
    if is_pttp_exist(sqlalchemy_con, pttp_name) == 0:
        pttp_id = add_pttp_with_keys(sqlalchemy_con, pttp_name, dvcl_id, start_device, end_device)
    else:
        pttp_id = sqlalchemy_con.session.query(PartType.pttp_id).filter(PartType.pttp_name == pttp_name).one()[0]
    list_devices = [item for item in range(start_device, end_device+1)]
    random.shuffle(list_devices)
    list_blacklisted_devices = list_devices[:count_blacklisted_devices]
    status =0
    for device in list_blacklisted_devices:
        if status == 7:
            status = 0
        status += 1
        sqlalchemy_con.session.query(Device).filter(Device.pttp_pttp_id == pttp_id,Device.devc_num==device).update({Device.dvst_dvst_id:status, Device.is_committed:1, Device.is_backed_up:1, Device.is_blacklisted:1}, synchronize_session=False)
        sqlalchemy_con.session.commit()
    return pttp_id


def add_prtnmb_to_pttp(sqlalchemy_con, prtnmb_name, pttp_id):
    dvcl_id = get_devcl_id_by_pttp_id(sqlalchemy_con, pttp_id)
    prtnmb_id = kmi_addPartNumber(prtnmb_name, dvcl_id)
    kmi_setPartTypeForPartNumber(prtnmb_id, pttp_id)
    return prtnmb_id


def check_parttype(sqlalchemy_con, pttp_name, dvcl_id, pttp_id, is_test, ext_info):
    pttp_info_from_db = sqlalchemy_con.session.query(PartType.pttp_name, PartType.dvcl_dvcl_id, PartType.is_test_pttp, PartType.extended_info).filter(PartType.pttp_id == pttp_id, PartType.del_date == None).one()
    assert(pttp_name == pttp_info_from_db[0]), 'Wrong parttype name'
    assert(dvcl_id == pttp_info_from_db[1]), 'Wrong device_class_id'
    assert(is_test == pttp_info_from_db[2]), 'Wrong type of parttype: from test = %s, from db = %s' % (is_test, pttp_info_from_db[2])
    if ext_info is None:
        assert(pttp_info_from_db[3] is None), 'Wrong ext_info in DB must be None'
    else:
        assert(json.loads(ext_info) == pttp_info_from_db[3]), 'Wrong extended_info for parttype'
    return 1


def get_pttp_by_status(sqlalchemy_con, status, dvcl_id=0, device_type=1):
    if status and dvcl_id == 0:
        pttp_id = sqlalchemy_con.session.query(Device.pttp_pttp_id).order_by(func.random()).filter(Device.dvst_dvst_id == status, Device.pttp_pttp_id == PartType.pttp_id, PartType.dvcl_dvcl_id == DeviceClass.dvcl_id, DeviceClass.dvtp_dvtp_id == device_type).limit(1).all()[0][0]
    elif status and dvcl_id:
        pttp_id = sqlalchemy_con.session.query(Device.pttp_pttp_id).order_by(func.random()).filter(Device.dvst_dvst_id == status, Device.pttp_pttp_id == PartType.pttp_id, PartType.dvcl_dvcl_id == dvcl_id).limit(1).all()[0][0]
    elif status == 0 and dvcl_id != 0:
        pttp_id = sqlalchemy_con.session.query(Device.pttp_pttp_id).order_by(func.random()).filter(Device.pttp_pttp_id == PartType.pttp_id, PartType.dvcl_dvcl_id == dvcl_id).limit(1).all()[0][0]
    else:
        pttp_id = sqlalchemy_con.session.query(Device.pttp_pttp_id).order_by(func.random()).filter(Device.pttp_pttp_id == PartType.pttp_id, PartType.dvcl_dvcl_id == DeviceClass.dvcl_id, DeviceClass.dvtp_dvtp_id == device_type).limit(1).all()[0][0]
    log('get_pttp_by_status return %s' % pttp_id)
    return pttp_id


def get_exported_devices_for_pairing(sqlalchemy_con, pttp_id, count, start_devc, end_devc, only_range):
    if start_devc == 0 and end_devc == 0:
        devc_range_db = sqlalchemy_con.session.query(func.min(Device.devc_num), func.max(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id, Device.dvst_dvst_id == 2).one()
        start_devc = random.randint(devc_range_db[0], devc_range_db[1]-count)
        end_devc = start_devc + count -1
        iteration = 0
        while kmi_check_device_range_has_status(pttp_id, start_devc, end_devc, 'DeviceStatusGenerated') == 1:
            iteration += 1
            start_devc = random.randint(devc_range_db[0], devc_range_db[1]-count)
            end_devc = start_devc + count -1
            if(iteration == 10):
                log('get_exported_devices_random_range return empty range')
                return None
        log('range for pairing:  [%s, %s]' % (start_devc, end_devc))
    devices = []
    devices.append([start_devc, end_devc])
    if only_range:
        return devices
    dict_devices = {}
    for device in range(start_devc, end_devc+1):
        dict_version_value = {}
        devc_versions = sqlalchemy_con.session.query(AuxKey.version, AuxKey.value).filter(AuxKey.aktp_aktp_id == 3, AuxKey.devc_num == device, AuxKey.pttp_pttp_id == pttp_id).all()
        for ver in devc_versions:
            dict_version_value[ver[0]] = ver[1]
        dict_devices[device] = dict_version_value
    devices.append(dict_devices)
    return devices


def check_device_range_has_exported_status(sqlalchemy_con, pttp, devc_range):
    for item in range(devc_range[0], devc_range[1] + 1):
        try:
            sqlalchemy_con.session.query(Device).filter(Device.dvst_dvst_id == 2, Device.pttp_pttp_id == pttp, Device.devc_num == item).one()
        except Exception, x:
            log(x)
            return 0
    log('All devices in range (%s - %s) has exported staus' % (devc_range[0], devc_range[1]))
    return 1


def get_sc6_parttype(sqlalchemy_con):
    sc6_dvcl = sqlalchemy_con.session.query(func.min(DeviceClass.dvcl_id)).filter(DeviceClass.dvtp_dvtp_id == 2).one()[0]
    log('SC6 Device class with min id = %s' % sc6_dvcl)
    pttp_ids = sqlalchemy_con.session.query(PartType.pttp_id).filter(PartType.dvcl_dvcl_id == sc6_dvcl).all()
    list_pttp_ids = [item[0] for item in pttp_ids]
    log('List part_types for device class %s : %s' % (sc6_dvcl, list_pttp_ids))
    for pttp in list_pttp_ids:
        if len(sqlalchemy_con.session.query(DeviceKey.devc_num).filter(DeviceKey.pttp_pttp_id == pttp, DeviceKey.key_value != None).limit(1).all()) == 1:
            log('get_sc6_parttype return %s' % pttp)
            return pttp
    log('All part_types for device_class %s has no generated unique_keys' % sc6_dvcl)
    return 0


def get_pttp_for_export_in_cas(sqlalchemy_con):
    dvcl_ids = sqlalchemy_con.session.query(DeviceClass.dvcl_id).all()
    dvcl_id_for_cas = 0
    for item in dvcl_ids:
        lengths = sqlalchemy_con.session.query(DeviceKeymap.key_length).filter(DeviceKeymap.dvcl_dvcl_id == item[0]).all()
        i = 0
        for length in lengths:
            i += 1
            if length[0] % 128 != 0:
                break
            if i == len(lengths):
                dvcl_id_for_cas = item[0]
        if dvcl_id_for_cas != 0:
            break
    if dvcl_id_for_cas == 0:
        log('In DB no device_class and parttype for export in CAS')
        return 0
    pttp = get_pttp_by_status(sqlalchemy_con, 2, dvcl_id_for_cas)
    log('get_pttp_for_export_in_cas return %s' % pttp)
    return pttp


def prepare_pttp_for_cur_devices_statuses(sqlalchemy_con, pttp_id, start_devc, end_devc, count=1):
    rnd_stbm_id = sqlalchemy_con.session.query(StbModel.stbm_id).filter(StbModel.del_date==None).order_by(func.random()).limit(1).one()[0]
    blbx_id = sqlalchemy_con.session.query(BlackBox.blbx_id).filter(BlackBox.del_date==None).order_by(func.random()).limit(1).one()[0]
    oper_id = sqlalchemy_con.session.query(Operator.oper_id).filter(Operator.del_date==None).order_by(func.random()).limit(1).one()[0]
    status = 1
    count_same_status = 0
    sn_db = [str(item[0]) for item in sqlalchemy_con.session.query(StbDevice.serial_number).all()]
    export_keys_batch_id=0
    import_programming_batch_id=0
    import_manufacturing_batch_id=0
    export_for_ind_device_batch_id = 0
    query = None
    for device in range(start_devc, end_devc+1):
        if status == 1:
            pass

        if status > 1:
            if  export_keys_batch_id == 0:
                batch_query = 'insert into kmi_batches (btch_id, bttp_bttp_id, btch_name) values(nextval(\'btch_seq\'), %d, \'%s\')' % (
                2, 'EXPORT OTP KEYS %s' % time.ctime())
                sqlalchemy_con.conn.execute(batch_query)
                export_keys_batch_id = sqlalchemy_con.session.query(func.max(Batch.btch_id)).one()[0]
            history_query = 'insert into kmi_device_histories (devh_id, pttp_pttp_id, devc_num, is_committed, is_backed_up,' \
                            ' is_blacklisted, dvst_dvst_id,  btch_btch_id, blbx_blbx_id) values(nextval(\'devh_seq\'), %d, %d, %d, %d, %d, %d, \
                            %d, %d)' % (pttp_id, device, 1, 1, 0, 2, export_keys_batch_id, blbx_id)
            sqlalchemy_con.conn.execute(history_query)
            query = 'update kmi_devices set dvst_dvst_id=%d,blbx_blbx_id=%d where pttp_pttp_id=%d and devc_num=%d' % (status, blbx_id, pttp_id, device)

        if status > 2:
            if import_programming_batch_id == 0:
               batch_query = 'insert into kmi_batches (btch_id, bttp_bttp_id, btch_name) values(nextval(\'btch_seq\'), %d, \'%s\')' % (
                   4, 'Import programming status report %s' % time.ctime())
               sqlalchemy_con.conn.execute(batch_query)
               import_programming_batch_id = sqlalchemy_con.session.query(func.max(Batch.btch_id)).one()[0]
            if status == 4:
                history_query = 'insert into kmi_device_histories (devh_id, pttp_pttp_id, devc_num, is_committed, is_backed_up,' \
                           ' is_blacklisted, dvst_dvst_id, btch_btch_id, blbx_blbx_id) values(nextval(\'devh_seq\'), %d, %d, %d, %d, %d, %d,\
                           %d, %d)' % (pttp_id, device, 1, 1, 0, 4, import_programming_batch_id, blbx_id)
            else:
                history_query = 'insert into kmi_device_histories (devh_id, pttp_pttp_id, devc_num, is_committed, is_backed_up,' \
                                ' is_blacklisted, dvst_dvst_id, btch_btch_id, blbx_blbx_id) values(nextval(\'devh_seq\'), %d, %d, %d, %d, %d, %d,\
                                %d, %d)' % (pttp_id, device, 1, 1, 0, 3, import_programming_batch_id, blbx_id)
            sqlalchemy_con.conn.execute(history_query)
            query = 'update kmi_devices set dvst_dvst_id=%d,blbx_blbx_id=%d where pttp_pttp_id=%d and devc_num=%d' % (status, blbx_id, pttp_id, device)
        if status >4:
            new_sn = random.randint(0, 100000)
            str_new_sn = '%010X' % new_sn
            while str_new_sn in sn_db:
                new_sn = random.randint(0, 100000)
                str_new_sn = '%010X' % new_sn
            sn_db.append(str_new_sn)
            query = 'insert into kmi_stb_devices values(nextval(\'stbd_seq\'),%d,\'%010X\',\'%s\')' % (rnd_stbm_id, new_sn, time.ctime())
            #query = 'select * from stbd_ensure(%d, %s::text)' % (rnd_stbm_id, new_sn)
            sqlalchemy_con.conn.execute(query)
            if import_manufacturing_batch_id == 0:
                batch_query = 'insert into kmi_batches (btch_id, bttp_bttp_id, btch_name) values(nextval(\'btch_seq\'), %d, \'%s\')' % (
                    5, 'Import STB manufacture report %s' % time.ctime())
                sqlalchemy_con.conn.execute(batch_query)
                import_manufacturing_batch_id = sqlalchemy_con.session.query(func.max(Batch.btch_id)).one()[0]
            if status == 6:
                history_query = 'insert into kmi_device_histories (devh_id, pttp_pttp_id, devc_num, is_committed, is_backed_up,' \
                                ' is_blacklisted, dvst_dvst_id, btch_btch_id, blbx_blbx_id, stbd_stbd_id, oper_oper_id) values(nextval(\'devh_seq\'), %d, %d, %d, %d, %d, %d, \
                                %d, %d, currval(\'stbd_seq\'), %d)' % (pttp_id, device, 1, 1, 0, 6, import_manufacturing_batch_id, blbx_id, oper_id)
            else:
                history_query = 'insert into kmi_device_histories (devh_id, pttp_pttp_id, devc_num, is_committed, is_backed_up,' \
                                ' is_blacklisted, dvst_dvst_id, btch_btch_id, blbx_blbx_id, stbd_stbd_id, oper_oper_id) values(nextval(\'devh_seq\'), %d, %d, %d, %d, %d, %d, \
                                %d, %d, currval(\'stbd_seq\'), %d)' % (
                                pttp_id, device, 1, 1, 0, 5, import_manufacturing_batch_id, blbx_id, oper_id)
            sqlalchemy_con.conn.execute(history_query)
            query = 'update kmi_devices set dvst_dvst_id=%d,blbx_blbx_id=%d,oper_oper_id=%d,stbd_stbd_id=currval(\'stbd_seq\') where pttp_pttp_id=%d and devc_num=%d' % (status, blbx_id,oper_id,pttp_id, device)
        if status > 6:
            if export_for_ind_device_batch_id == 0:
                batch_query = 'insert into kmi_batches (btch_id, bttp_bttp_id, btch_name) values(nextval(\'btch_seq\'), %d, \'%s\')' % (
                    7, 'Export OTP keys for ind device_%s' % time.ctime())
                sqlalchemy_con.conn.execute(batch_query)
                export_for_ind_device_batch_id = sqlalchemy_con.session.query(func.max(Batch.btch_id)).one()[0]
            history_query = 'insert into kmi_device_histories (devh_id, pttp_pttp_id, devc_num, is_committed, is_backed_up,' \
                            ' is_blacklisted, dvst_dvst_id, btch_btch_id, blbx_blbx_id, stbd_stbd_id, oper_oper_id) values(nextval(\'devh_seq\'), %d, %d, %d, %d, %d, %d, \
                            %d, %d, currval(\'stbd_seq\'), %d)' % (
                            pttp_id, device, 1, 1, 0, status, export_for_ind_device_batch_id, blbx_id, oper_id)
            sqlalchemy_con.conn.execute(history_query)
        if query is not None:
            sqlalchemy_con.conn.execute(query)
            log(query)
            query = None
        count_same_status += 1
        if status == 7 and count == count_same_status:
                status = 0
        if count == count_same_status:
            status += 1
            count_same_status = 0
    log('prepare_pttp_for_cur_devices_statuses SUCCESS')


def get_pttp_without_devices(sqlalchemy_con, pttp_name, dvcl_id):
    pttp_with_devices = list(set([item[0] for item in sqlalchemy_con.session.query(PartTypeKey.pttp_pttp_id).all()]))
    pttp_without_devices = [item[0] for item in sqlalchemy_con.session.query(PartType.pttp_id).filter(~PartType.pttp_id.in_(pttp_with_devices)).all()]
    if len(pttp_without_devices) == 0:
        pttp_id = get_nextfree_pttp_id(sqlalchemy_con)
        kmi_addPartType(pttp_name,dvcl_id, pttp_id)
    else:
        pttp_id = random.choice(pttp_without_devices)
    log('get_pttp_without_devices return %s' % pttp_id)
    return pttp_id


def get_pttp_for_device_history(sqlalchemy_con, min_devices):
    pttp_id = sqlalchemy_con.session.query(DeviceHistory.pttp_pttp_id).order_by(func.random()).limit(1).one()[0]
    batch_pttp = sqlalchemy_con.session.query(func.max(DeviceHistory.btch_btch_id), func.max(DeviceHistory.devc_num),func.min(DeviceHistory.btch_btch_id), func.min(DeviceHistory.devc_num)).filter(DeviceHistory.pttp_pttp_id == pttp_id).one()
    i = 0
    while (batch_pttp[0]-batch_pttp[2])<1 and (batch_pttp[1]-batch_pttp[3] < min_devices -1):
        i += 1
        pttp_id = sqlalchemy_con.session.query(DeviceHistory.pttp_pttp_id).order_by(func.random()).limit(1).one()[0]
        batch_pttp = sqlalchemy_con.session.query(func.max(DeviceHistory.btch_btch_id),
                                                 func.min(DeviceHistory.btch_btch_id)).filter(
                                                 DeviceHistory.pttp_pttp_id == pttp_id).one()
        if (i == 20):
            log('In DB no pttp fwith two different batches')
            return 0
    log('get_pttp_for_device_history return pttp = %d with min devc_num = %d' % (pttp_id, batch_pttp[3]))
    return [pttp_id, batch_pttp[3]]


def get_param(sqlalchemy_con, param_name, *args):
    query = "select %s from kmi_resource_params where rprm_code='%s'" % (param_name, args[0])
    value = sqlalchemy_con.conn.execute(query).fetchone()[0]
    return value


def get_context_by_prtnmb(sqlalchemy_con, ptnmb_id):
    ctx_tuple = sqlalchemy_con.session.query(FusemapIni.ovdf_ctx).filter(FusemapIni.ptnm_ptnm_id == ptnmb_id).order_by(FusemapIni.fsmptp_fsmptp_id).all()
    return (item[0] for item in ctx_tuple)


def set_need_obfuscation_for_gs2(sqlalchemy, pttp_id, flag, all_keys):
    dvkm_ids = sqlalchemy.session.query(DeviceKeymap.dvkm_id).filter(DeviceKeymap.dvcl_dvcl_id==PartType.dvcl_dvcl_id, PartType.pttp_id == pttp_id).order_by(DeviceKeymap.key_index).all()
    if all_keys == 0:
        dvkm_ids = [item[0] for i, item in enumerate(dvkm_ids) if i %2 ==0 ]
    if flag == 1:
        for dvkm in dvkm_ids:
            sqlalchemy.session.query(DeviceKeymap).filter(DeviceKeymap.dvkm_id == dvkm).update({DeviceKeymap.need_obfuscation: 1}, synchronize_session=False)
    else:
        for dvkm in dvkm_ids:
            sqlalchemy.session.query(DeviceKeymap).filter(DeviceKeymap.dvkm_id == dvkm).update({DeviceKeymap.need_obfuscation: 0}, synchronize_session=False)
    sqlalchemy.session.commit()


def get_max_released_device(sqlalchemy, pttp_id):
    try:
        return sqlalchemy.session.query(func.max(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id, Device.dvst_dvst_id==7).one()[0]+1
    except:
        return sqlalchemy.session.query(func.min(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id).one()[0]


def get_max_device_not_generated(sqlcon, pttp_id):
    try:
        return sqlcon.session.query(func.max(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id, Device.dvst_dvst_id>1).one()[0]+1
    except:
        return sqlcon.session.query(func.min(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id).one()[0]


def get_any_index(sqlcon, dvcl_id):
    index = sqlcon.session.query(func.max(DeviceKeymap.key_index)).filter(DeviceKeymap.dvcl_dvcl_id==dvcl_id, DeviceKeymap.is_otp_key==1).one()[0]
    log('get_any_index return %s for device_class %s' % (index, dvcl_id))
    return index

def check_fwkeys_was_added_successfully(sqlcon, key_code, key_algo, key_privacy, key_fragment, need_fwky_id):
    altp_status_dict = {'rsa': 1, 'aes': 2, 'binary data': 3}
    kftp_status_dict = {'full': 0, 'exponent': 1, 'modulus': 2}
    pvtp_status_dict = {'symmetric': 0, 'public': 1, 'private': 2}
    try:
        fwky_id, altp_id = sqlcon.session.query(FirmwareKey.fwky_id, FirmwareKey.altp_altp_id).filter(FirmwareKey.key_code == key_code).one()
        pvtp_id, kftp_id = sqlcon.session.query(FirmwareKeymaps.pvtp_pvtp_id, FirmwareKeymaps.kftp_kftp_id).filter(FirmwareKeymaps.fwky_fwky_id == fwky_id).one()
    except:
        return 0
    assert (altp_id == altp_status_dict[key_algo]), 'Error key algo is not correct'
    assert (pvtp_id == pvtp_status_dict[key_privacy]), 'Error key privacy is not correct'
    assert (kftp_id == kftp_status_dict[key_fragment]), 'Error key fragment is not correct'
    if need_fwky_id is not False:
        return (1, fwky_id)
    else:
        return 1

def get_lock_ids(sqlcon):
    rsrc_ids = []
    names = sqlcon.session.query(LockList.wf_name).filter(LockList.del_date == None).all()
    for item in names:
        rsrc_ids.append(sqlcon.session.query(Resourses.rsrc_id).filter(Resourses.rsrc_name == item[0]).one()[0])
    return rsrc_ids

def get_any_lest_name_with_lest_id_pttp_id(sqlcon):
    lest_name, lest_id, pttp_id = random.choice(sqlcon.session.query(LEKeySet.lest_name, LEKeySet.lest_id, LEKeySet.pttp_pttp_id).filter(LEKeySet.del_date == None).all())
    return (lest_name, lest_id, pttp_id)

def check_that_lest_name_was_changed(sqlcon, new_lest_name, lest_id, pttp_id):
    new_db_lest_name = sqlcon.session.query(LEKeySet.lest_name).filter(LEKeySet.lest_id == lest_id, LEKeySet.pttp_pttp_id == pttp_id).one()[0]
    try:
        assert(new_db_lest_name == new_lest_name), 'Error lest name was not changed'
    except:
        return 'Error lest name was not changed'
    return 1