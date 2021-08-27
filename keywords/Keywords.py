
from Helpers.Management import *
import Helpers.Management
import Helpers.StbModel
import Helpers.Database as DB
from Helpers.Logger import Logger, log
import Helpers.AuxHelper
import Helpers.PartnerDRM
import Helpers.OTPValidation
import Helpers.SSLEncryption as ssl
import Helpers.GenerateKeys as genkeys
import Helpers.ExportKeys
import Helpers.KmiHelper
import Helpers.TestParttype
import Helpers.FirmwareKeys
import Helpers.ManufacturerChecking
import Helpers.Report as report
import Helpers.UserKeys as ukey
import Helpers.PyFTP
import Helpers.ExternalServers
import KMIDalKeywords as dal
import Helpers.FirmwareKeys
from TestRailKW import get_test_data

class Keywords(object):

    def __init__(self):
        self.db = DB.Database()
        self.aux_helper = Helpers.AuxHelper.AuxHelper(self.db)
        self.drm_helper = Helpers.PartnerDRM.PartnerDRM(self.db)
        print '__init__ Success'

    def get_random_int(self, a, b):
        return random.randint(int(a), int(b))

    def sum(self, arg1, arg2):
        return int(arg1) + int(arg2)

    def create_my_list(self, start, end, full_range=1):
        if full_range==1:
            li = list(range(int(start), int(end)+1))
        else:
            li = list(range(int(start), int(end), 2))
        log('create_my_list return %s' % li)
        return li

    def init_logger(self, filename):
        print 'Log file %s' % filename
        log_dir = '%s/Logs' % os.path.dirname(os.path.abspath(__file__))
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        logfile = '%s/%s.txt' % (log_dir, filename)
        self.logger = Logger(logfile)

    def check_vendor_in_DB(self, vendor_name):
        log('=====check_vendor_in_DB for vendor_name: %s START=====' % vendor_name)
        return check_vendor_in_db(vendor_name)

    def get_number_rows_from_table(self, table_name):
        log('=====get_number_rows_from_table from table %s START=====' % table_name)
        if table_name == 'kmi_vendors':
            return get_number_vendors(self.db)
        if table_name == 'kmi_le_keysets':
            return self.aux_helper.get_number_rows()
        if table_name == 'kmi_le_keys':
            return self.aux_helper.get_number_rows(table_name)
        if table_name == 'kmi_le_export_history':
            return self.aux_helper.get_number_rows(table_name)
        if table_name == 'kmi_partners':
            return self.drm_helper.get_number_all_partners()
        if table_name == 'kmi_prtnr_pttp':
            return self.drm_helper.get_number_ivs()
        if table_name == 'kmi_part_numbers':
            return get_rows_kmi_part_number(self.db)
        if table_name == 'kmi_operators':
            return get_rows_kmi_operators(self.db)
        if table_name == 'kmi_manufactures':
            return get_rows_kmi_manufactures(self.db)

    def clear_table(self, table_name):
        log('=====clear_table %s START=====' % table_name)
        if table_name == 'kmi_partners':
            return self.drm_helper.clear_partners()
        if table_name == 'kmi_le_export_history':
            return self.aux_helper.clear_export_history()

    def get_operator_id_by_name(self, operator_name, deleting=None):
        log('====get_operator_id_by_name : %s START====' % operator_name)
        return get_operator_id_by_name(self.db, operator_name, deleting)

    def get_operator_name_by_id(self, operator_id, deleting = None):
        log('====get_operator_id_by_name : %s START====' % operator_id)
        return get_operator_name_by_id(self.db, operator_id, deleting)

    def get_any_operator_name(self, deleting = None):
        log('====get_any_operator_name====')
        return get_any_operator_name(self.db, deleting)

    def get_vendor_id_by_name(self, vnd_name, deleting = None):
        log('=====get_vendor_id_by_name : %s START=====' % vnd_name)
        return get_vendor_id_by_name(self.db, vnd_name, deleting)

    def get_vendor_name_by_id(self, vnd_id, deleting=None):
        log('=====get_vendor_name_by_id: %s START=====' % vnd_id)
        return get_vendor_name_by_id(self.db, vnd_id, deleting)

    def get_any_vendor_name_from_db(self):
        log('=====get_any_vendor_name_from_DB START=====')
        return get_any_vendor_name_from_db(self.db)

    def get_any_vendor_id_from_db(self):
        log('=====get_any_vendor_id_from_DB START=====')
        return get_any_vendor_id_from_db(self.db)

    def get_any_vendor_id_from_db_without_dev_classes(self):
        log('=====get_any_vendor_id_from_DB_without_dev_classes START=====')
        return get_any_vendor_id_from_db_without_dev_classes(self.db)

    def get_any_vendor_id_from_db_with_dev_classes(self):
        log('=====get_any_vendor_id_from_DB_with_dev_classes START=====')
        return get_any_vendor_id_from_db_with_dev_classes(self.db)

    def delete_vendor(self, vnd_name):
        log('=====delete_vendor %s START=====' %vnd_name)
        delete_vendor(self.db, vnd_name)

    def check_kmi_vendor_list(self, kmi_vendor_list):
        log('=====check_kmi_vendor_list START=====')
        return check_vendor_list(self.db, kmi_vendor_list)

    def check_vendor_info(self,vendor_info, devcl_id):
        log('=====check_vendor_info for device_class_id = %s START' % devcl_id)
        return check_vendor_info(self.db, vendor_info, devcl_id)

    def check_operator_list(self, kmi_operator_list):
        log('====check_operator_list START====')
        return check_operator_list(self.db, kmi_operator_list)


    def get_part_number_name_by_id(self, partnumber_id):
        log('====get_part_number_from_db = %s START====' % partnumber_id)
        return get_part_number_name_by_id(self.db, partnumber_id)

    def check_device_class_list(self, vendor_id, dev_class_list):
        log('=====check_device_class_list for vendorId = %s START=====' %vendor_id)
        return check_dev_class_list(self.db, vendor_id, dev_class_list)

    def get_device_class_id_for_vendor_by_name(self, vndr_id, dev_cl_name, device_type=1):
        log('=====get_device_class_id_for_vendor_by_name START=====')
        log('get device class id for vendor with ID = %s  and device class name %s' % (vndr_id, dev_cl_name))
        return get_device_class_id_for_vendor_by_name(self.db, vndr_id, dev_cl_name, device_type)

    def get_devcl_name_by_id(self, dvcl_id, del_date= None):
        log('=====get_devcl_name_by_id: %s START=====' % dvcl_id)
        return get_devcl_name_by_id(self.db, dvcl_id, del_date)

    def get_generic_device_class_id(self):
        log('=====get_generic_device_class_id START=====')
        dvcl_id = get_any_device_class_id_from_db(self.db)
        log('get_generic_device_class_id return %s' % dvcl_id)
        return dvcl_id

    def get_sc6_device_class_id(self):
        log('=====get_sc6_device_class_id START=====')
        return get_any_device_class_id_from_db(self.db, 'SC6')

    def get_any_device_class_id_from_DB(self):
        log('=====get_any_device_class_id_from_DB START=====')
        return get_any_device_class_id_from_db(self.db)

    def get_any_device_class_with_partnumber(self):
        log('====get_any_dvcl_id_from_table_kmi_part_numbers====')
        return get_any_device_class_whith_partnumbers(self.db)

    def get_any_device_class_id_from_DB_with_keymap(self):
        log('=====get_any_device_class_id_from_DB_with_keymap START=====')
        dvcl = get_any_device_class_id_from_db_with_keymap(self.db)
        log('=====get_any_device_class_id_from_DB_with_keymap return %s' % dvcl)
        return dvcl

    def get_devcl_id_by_pttp_id(self, pttp_id):
        log('=====get_devcl_id_by_pttp_id START=====')
        return get_devcl_id_by_pttp_id(self.db, pttp_id)

    def get_any_device_class_id_from_db_without_pttp(self):
        log('=====get_any_device_class_id_from_DB_without_pttp START=====')
        return get_any_device_class_id_from_db_without_pttp(self.db)

    def get_next_free_device_class(self):
        log('=====get_next_free_device_class START=====')
        return get_next_free_device_class(self.db)

    def restore_device_class(self, dvcl_id):
        log('=====restore_device_class with id %s START, set del_date is NULL=====' % dvcl_id)
        restore_device_class(self.db, dvcl_id)

    def check_key_map_list(self, key_map, devcl_id):
        log('=====check_key_map_list for device class id = %s START=====' % devcl_id)
        return check_key_map_list(self.db, key_map, devcl_id)

    def check_part_number_list(self, part_nmb_list, devcl_id):
        log('=====check_part_number_list for device class id = %s START=====' % devcl_id)
        return check_part_number_list(self.db, part_nmb_list, devcl_id)

    def check_part_number_info(self, partnumber_info, partnumber_id, is_linked_with_pttp=None):
        log('====check_function_kmi_get_partnumber START====')
        try:
            check_part_number_info(self.db, partnumber_info, int(partnumber_id), is_linked_with_pttp)
            return 1
        except Exception,e:
            log('ERROR in kmi get partnumber > %s' % e)
            return 0

    def check_part_type_list(self, part_type_list, devcl_id):
        log('=====check_part_type_list for device class id = %s START=====' % devcl_id)
        return check_part_type_list(self.db, part_type_list, devcl_id)

    def get_any_part_type_id_from_db(self):
        log('=====get_any_part_type_id_from_DB START=====')
        return get_any_part_type_id_from_db(self.db)

    def get_all_pttp_ids(self):
        log('====get_all_pttp_ids START====')
        return get_all_pttp_ids(self.db)

    def get_any_pttp_id_with_ptnmb(self):
        log('====get_any_part_type_id_from_part_number START====')
        try:
            return get_any_pttp_id_with_ptnmb(self.db)
        except Exception, e:
            log('ALL PartNumber was Deleted db is empty')
            return 0
    def get_test_pttp_id_from_db(self):
        log('=====get_test_pttp_id_from_db START=====')
        return get_any_part_type_id_from_db(self.db, is_test=1)

    def get_pttp_name_by_id(self, pttp_id):
        log('=====get_pttp_name_by_id START=====')
        return get_pttp_name_by_id(self.db, int(pttp_id))

    def get_any_partnumber_id_by_pttp(self, pttp_id=0):
        log('=====get_any_partnumber_id_by_pttp START=====')
        return get_any_partnumber_id_by_pttp(self.db, int(pttp_id))

    def is_part_number_deleted(self, partnumber_id):
        log('====check_that_partnumber_deleted====')
        return is_part_number_deleted(self.db, int(partnumber_id))

    def check_part_number(self, partnumber_name, partnumber_id):
        log('====check_that_name_PartNumber_was_changed====')
        try:
            check_part_number(self.db, str(partnumber_name), int(partnumber_id))
            return 1
        except Exception as e:
            log('Error in check_edit_partnumber: %s' % e)
            return 0

    def get_keymap_by_dvcl(self, dvcl_id):
        log('=====get_keymap_by_dvcl START=====')
        return Helpers.Management.get_keymap_by_dvcl(int(dvcl_id))

    def set_need_obfuscation_flag_for_gs2(self, pttp_id, flag, all_keys=1):
        log('=====set_need_obfuscation_flag_for_gs2 START=====')
        return Helpers.Management.set_need_obfuscation_for_gs2(self.db, pttp_id, int(flag), int(all_keys))

    def get_keymap_length(self, dvcl_id):
        log('=====get_keymap_length START=====')
        return Helpers.Management.get_keymaps_length(self.db, int(dvcl_id))

    def get_nextfree_pttp_id(self, start_value=1):
        log('=====get_nextfree_pttp_id START=====')
        return get_nextfree_pttp_id(self.db, start_value)

    def get_nextfree_partnumber_id(self, start_value=1):
        log('====get_next_free_PartNumber====')
        return get_nextfree_partnumber_id(self.db, start_value)

    def get_nextfree_operator_id(self, start_value=1):
        log('====get_next_free_Operator_id')
        return get_nextfree_operator_id(self.db, start_value)

    def check_operator_info(self, operator_info, operator_id):
        log('====check_operator_info START====')
        try:
            check_operator_info(self.db, operator_info, operator_id)
            return 1
        except Exception as e:
            log('ERROR In check operator_info: %s' % e)
            return 0

    def add_pttp_forced(self, pttp_name, dvcl):
        for i in range(0,1000):
            free_pttp_id = get_nextfree_pttp_id(self.db)
            pttp_id = dal.kmi_addPartType(pttp_name, dvcl, free_pttp_id)
            if pttp_id == 'Error in kmi_addPartType':
                continue
            return pttp_id


    def add_pttp_with_keys(self, pttp_name, dvcl_id, start_device, end_device, file_uniq_keys=''):
        log('=====add_parttype_with_keys START=====')
        return add_pttp_with_keys(self.db, pttp_name, dvcl_id, int(start_device), int(end_device), file_uniq_keys)

    def get_any_index(self, dvcl_id):
        log('=====get_any_index START=====')
        return get_any_index(self.db, dvcl_id)

    def add_pttp_with_keys_forced(self, pttp_name, dvcl_id, start_device, end_device, file_uniq_keys=''):
        log('=====add_parttype_with_keys START=====')
        return add_pttp_with_keys_forced(self.db, pttp_name, dvcl_id, int(start_device), int(end_device), file_uniq_keys)

    def add_test_pttp_with_keys(self,pttp_name, dvcl_id, start_device, end_device, file_uniq_keys):
        log('=====add_test_pttp_with_keys START=====')
        return add_pttp_with_keys(self.db, pttp_name, dvcl_id, start_device, end_device, file_uniq_keys, is_test=1)

    def add_devices_to_blacklist(self, pttp_id, count):
        log('=====add_devices_to_blacklist START=====')
        return add_devices_to_blacklist(self.db, pttp_id, count)

    def add_pttp_with_blacklisted_devices(self, pttp_name, dvcl_id, start_device, end_device, count_blacklisted_devices):
        log('=====add_pttp_with_blacklisted_devices START=====')
        return add_pttp_with_blacklisted_devices(self.db, pttp_name, dvcl_id, int(start_device), int(end_device), int(count_blacklisted_devices))

    def add_prtnmb_to_pttp(self, part_number_name, pttp_id):
        log('=====add_prtnmb_to_pttp START=====')
        return add_prtnmb_to_pttp(self.db, part_number_name, pttp_id)

    def check_parttype(self, pttp_name, dvcl_id, pttp_id, is_test=0, ext_info=None):
        log('=====check_parttype START=====')
        try:
            return check_parttype(self.db, pttp_name, dvcl_id, pttp_id, int(is_test), ext_info)
        except Exception as E:
            log('ERROR in check_parttype: %s' % E)
            return 0


    def get_pttp_with_exported_keys(self):
        log('=====get_pttp_with_exported_keys START=====')
        return get_pttp_by_status(self.db, 2)

    def get_pttp_with_exported_keys_for_pairing(self):
        log('=====get_pttp_with_exported_keys_for_pairing START=====')
        return get_pttp_by_status(self.db, 2,device_type=1)

    def get_pttp_without_devices(self, pttp_name, dvcl_id):
        log('=====get_pttp_without_devices START=====')
        return get_pttp_without_devices(self.db, pttp_name, dvcl_id)

    def get_pttp_for_device_history(self, min_devices):
        log('=====get_pttp_for_device_history START=====')
        return get_pttp_for_device_history(self.db, min_devices)

    def get_devices_random_range_by_status(self, pttp_id, count, status=0):
        log('=====get_devices_random_range START=====')
        return Helpers.KmiHelper.get_devices_random_range_by_status(self.db, pttp_id, int(count), int(status))

    def get_sc6_parttype(self):
        log('=====get_sc6_parttype START=====')
        return get_sc6_parttype(self.db)

    def get_pttp_for_export_in_cas(self):
        log('=====get_pttp_for_export_in_cas START=====')
        return get_pttp_for_export_in_cas(self.db)

    def check_devices_in_blacklist(self, pttp_id, path_to_exported_file):
        log('=====check_devices_in_blacklist START=====')
        try:
            report.check_devices_in_blacklist(self.db, pttp_id, path_to_exported_file)
            return 1
        except Exception,e:
            log('ERROR in check_devices_in_blacklist: %s' % e)
            return 0

    def check_current_device_statuses(self, pttp_id, start_devc, end_devc, path_to_exported_file):
        log('=====check_current_device_statuses START=====')
        try:
            report.check_current_device_statuses(self.db, int(pttp_id), int(start_devc), int(end_devc), path_to_exported_file)
            return 1
        except Exception,e:
            log('ERROR in check_current_device_statuses: %s' % e)
            return 0

    def prepare_pttp_for_cur_devices_statuses_report(self, pttp_id, start_devc, end_devc):
        log('=====prepare_pttp_for_cur_devices_statuses_report START=====')
        prepare_pttp_for_cur_devices_statuses(self.db, int(pttp_id), int(start_devc), int(end_devc))

    def prepare_pttp_for_device_status_report_v2(self, pttp_id, start_devc, end_devc, length_range):
        log('=====prepare_pttp_for_device_status_report_v2 START=====\nARGS: %s,%s,%s,%s' % (pttp_id, start_devc, end_devc, length_range))
        prepare_pttp_for_cur_devices_statuses(self.db, int(pttp_id), int(start_devc), int(end_devc), int(length_range))

    def check_device_status_report_v2(self, pttp_id, list_report_items, start_dev, end_dev):
        log('=====check_device_status_report_v2 START=====')
        try:
            report.check_device_status_report_v2(self.db, int(pttp_id), list_report_items, int(start_dev), int(end_dev))
            return 1
        except Exception, e:
            log('ERROR in check_device_status_report_v2: %s' % e)
            return 0

    def check_device_status_report_v2_too_long(self, pttp_id, list_report_items, start_dev, end_dev):
        log('=====check_device_status_report_v2 too long START=====')
        try:
            report.check_device_status_report_v2(self.db, int(pttp_id), list_report_items, int(start_dev), int(end_dev), too_long=True)
            return 1
        except Exception, e:
            log('ERROR in check_device_status_report_v2 too long: %s' % e)

    def check_devices_history(self, pttp_id, list_devices, out_path):
        log('=====check_devices_history START=====')
        try:
            report.check_devices_history(self.db, int(pttp_id), list_devices, out_path)
            return 1
        except Exception, e:
            log('ERROR in check_devices_history: %s' % e)
            return 0

#=======================LE keywords================

    def get_any_ck_ip_keys_id(self, secure=None):
        log('====get_any_ck_ip_keys_id START====')
        return self.aux_helper.get_any_ck_ip_keys_id(secure)

    def check_le_keyset(self, pttp_id, le_keyset_id, le_keyset_name):
        log('=====check_le_keyset for le_keyset = %s START=====' % le_keyset_id)
        return self.aux_helper.check_aux_keyset(int(pttp_id), le_keyset_id, le_keyset_name)

    def check_ck_ip_keyset(self, pttp_id, keyset_id, keyset_name):
        log('=====check_cp_ip_keyset for keyset = %s START=====' % keyset_id)
        return self.aux_helper.check_aux_keyset(int(pttp_id), keyset_id, keyset_name, Helpers.AuxHelper.AuxKeys.ck_ip_keys)

    def get_number_keys_in_leset(self, le_keyset_id):
        log('=====get_number_keys_in_leset for le_keyset = %s START=====' % le_keyset_id)
        return self.aux_helper.get_number_keys_in_aux_keyset(le_keyset_id)

    def get_number_keys_in_ck_keyset(self, keyset_id):
        log('=====get_number_keys_in_ck_keyset for keyset = %s START=====' % keyset_id)
        return self.aux_helper.get_number_keys_in_aux_keyset(keyset_id)

    def check_format_of_lekeys(self, le_keyset_id):
        log('=====check_format_of_lekeys for le_keyset = %s START=====' % le_keyset_id)
        return self.aux_helper.check_format_of_auxkeys(le_keyset_id)

    def check_format_of_ckkeys(self, keyset_id):
        log('=====check_format_of_ckkeys for keyset = %s START=====' % keyset_id)
        return self.aux_helper.check_format_of_auxkeys(keyset_id)

    def check_aux_keyset_list(self, pttp_id, kmi_leset_list):
        log('=====check_le_keyset_list for pttp = %s START=====' % pttp_id)
        return self.aux_helper.check_aux_keyset_list(int(pttp_id), kmi_leset_list)

    def check_file_with_exported_LE(self, path_to_file, le_set_id, pttp_id1, otp_key_id1, pttp_id2, otp_key_id2):
        log('=====check_file_with_exported_LE for le_set_id = %s START=====' % le_set_id)
        return self.aux_helper.check_file_with_exported_LE( path_to_file, le_set_id, int(pttp_id1), int(otp_key_id1), int(pttp_id2), int(otp_key_id2))

    def get_version_exported_file_from_db(self, le_set_id, pttp_id1, pttp_id2):
        log('=====get_version_exported_file_from_db for le_set_id = %s START=====' % le_set_id)
        return self.aux_helper.get_version_from_db(le_set_id, pttp_id1, pttp_id2)

    def is_auxset_deleted(self, leset_id):
        log('=====is_auxset_deleted for le_set_id = %s START=====' % leset_id)
        return self.aux_helper.is_auxset_deleted(leset_id)

    def get_any_ckkeyset_id(self, pttp_id = None):
        log('=====get_any_ckkeyset_id START=====')
        return self.aux_helper.get_any_auxkeyset_id(Helpers.AuxHelper.AuxKeys.ck_ip_keys, pttp_id)

    def get_any_lekeyset_id(self):
        log('=====get_any_lekeyset_id START=====')
        return self.aux_helper.get_any_auxkeyset_id(Helpers.AuxHelper.AuxKeys.le_keys, None)

    def get_sec_constants_keyset(self, pttp_id):
        log('=====get_sec_constants_keyset START=====')
        return self.aux_helper.get_any_auxkeyset_id(Helpers.AuxHelper.AuxKeys.sp_security_contants, pttp_id)

    def get_sec_constant_keyset_not_linked_pttp(self, pttp_id):
        log('=====get_sec_constant_keyset_not_linked_pttp START=====')
        return self.aux_helper.get_any_auxkeyset_id(Helpers.AuxHelper.AuxKeys.sp_security_contants, pttp_id, 0)

    def check_exported_ck_keyset(self, ckset_id, path):
        log('=====check_exported_ck_keyset START=====')
        try:
            self.aux_helper.check_exported_ck_keyset(ckset_id, path)
            return 1
        except Exception as E:
            log('ERROR in check_exported_ck_keyset: %s' % E)
            return 0

    def check_exported_sps_constants(self, sps_constans_set_id, pttp_id, out_path):
        log('=====check_exported_sps_constants START=====')
        try:
            self.aux_helper.check_exported_sps_constants(sps_constans_set_id, int(pttp_id), str(out_path))
            return 1
        except Exception as E:
            log('ERROR in check_exported_sps_constants: %s' % E)
            return 0

    def check_generated_pairing_keys(self, pttp_id, list_devices_with_version, versions):
        log('=====check_generated_pairing_keys START=====')
        try:
            self.aux_helper.check_generated_pairing_keys(pttp_id, list_devices_with_version, versions)
            return 1
        except Exception as E:
            log('ERROR in check_generated_pairing_keys: %s' % E)
            return 0

    def get_exported_devices_for_pairing(self, pttp_id, count_devices, start_devc=0, end_devc=0, only_range=0):
        log('=====get_exported_devices_for_pairing START=====')
        return get_exported_devices_for_pairing(self.db, pttp_id, int(count_devices), start_devc, end_devc, only_range)

    def get_exported_devices_for_pairing_range(self, pttp_id, count_devices):
        log('=====get_exported_devices_for_pairing START=====')
        return get_exported_devices_for_pairing(self.db, pttp_id, int(count_devices), 0, 0,1)

    def check_exported_ck_ip_keys_secure(self, le_set_id, pttp, key_index, dvcl_id, fw_keys_id, filename):
        log('====check_exported_ck_ip_keys_secure START====')
        return self.aux_helper.check_exported_ck_ip_keys_secure(int(le_set_id), int(pttp), int(key_index), int(dvcl_id), int(fw_keys_id), str(filename))

    def check_clone(self, le_set_id, le_set_id_cloned):
        return self.aux_helper.check_cloned(le_set_id, le_set_id_cloned)

    def get_max_lest_id(self):
        return self.aux_helper.get_max_lest_id()

    def get_aux_key_types_by_id(self, id):
        return self.aux_helper.get_aux_key_types_by_id(id)



#====================Partners keywords===================


    def get_partner_name_by_id(self, prtnr_id):
        log('=====get_partner_name_by_id for prtnr_id = %s START=====' % prtnr_id)
        return self.drm_helper.get_partner_name_by_id(prtnr_id)

    def get_partner_id_by_name(self, prtnr_name):
        log('=====get_partner_id_by_name for prtnr_name = %s START=====' % prtnr_name)
        return self.drm_helper.get_partner_id_by_name(prtnr_name)

    def get_any_partner_id_from_db(self):
        log('=====get_any_partner_id_from_db START=====' )
        return self.drm_helper.get_any_partner_id_from_db()

    def is_partner_in_db(self, partner):
        log('=====is_partner_in_db for prtnr_id = %s START=====' % partner.partnerId)
        return self.drm_helper.is_partner_in_db(partner)

    def is_partner_active(self, prtnr_id):
        log('=====is_partner_active for prtnr_id = %s START=====' % prtnr_id)
        return self.drm_helper.is_partner_active(prtnr_id)

    def is_iv_active(self, prtnr_id, pttp_id):
        log('=====is_iv_active for prtnr_id = %s, pttp_id %s START=====' % (prtnr_id, pttp_id))
        return self.drm_helper.is_iv_active(prtnr_id, pttp_id)

    def check_partner_list(self, kmi_partner_list):
        log('=====check_partner_list START=====')
        return self.drm_helper.check_partner_list(kmi_partner_list)

    def get_iv_length(self, partnr_id, pttp_id):
        log('=====get_iv_length START=====')
        return self.drm_helper.get_iv_length(partnr_id, pttp_id)

    def get_iv(self, partnr_id, pttp_id):
        log('=====get_iv START=====')
        return self.drm_helper.get_iv(partnr_id, pttp_id)

    def check_partner_iv_info(self, prtnr_id, pttp_id, kmi_partner_iv):
        log('=====check_partner_iv_info START=====')
        return self.drm_helper.check_partner_iv_info(prtnr_id, pttp_id, kmi_partner_iv)

    def check_list_partner_iv_info(self, kmi_partner_iv_info_list, prtnr_id=0, pttp_id=0):
        log('=====check_list_partner_iv_info START=====')
        return self.drm_helper.check_list_partner_iv_info(kmi_partner_iv_info_list, prtnr_id, pttp_id)

    def check_drm_config(self, partner_id, prtnmbr_id, otp_index, config_name, extfile=None):
        log('=====check_drm_config START=====')
        return self.drm_helper.check_drm_config(int(partner_id), int(prtnmbr_id), int(otp_index), str(config_name), extfile)

    def check_drm_data(self, partner_id, prtnmbr_id, otp_index, start_dev, end_dev, config_name, data_name,
                       operation='encrypt', ext_srv_id=0):
        log('=====check_drm_data START=====')
        log('BLBX: %s' % ext_srv_id)
        try:
            self.drm_helper.check_drm_data(int(partner_id), int(prtnmbr_id), int(otp_index), int(start_dev),
                                           int(end_dev), str(config_name), str(data_name), operation, int(ext_srv_id))
            return 1
        except Exception, e:
            log('ERROR in check_drm_data: %s' % e)
            return 0

    def check_drm_data_from_ext_file(self, partner_id, pttp_id, otp_index, start_dev, end_dev, config_name, data_name,
                       operation='encrypt', ext_srv_id=0):
        log('=====check_drm_data START=====')
        log('BLBX: %s' % ext_srv_id)
        try:
            self.drm_helper.check_drm_data_from_ext_file(int(partner_id), int(pttp_id), int(otp_index), int(start_dev),
                                           int(end_dev), str(config_name), str(data_name), operation, int(ext_srv_id))
            return 1
        except Exception, e:
            log('ERROR in check_drm_data: %s' % e)
            return 0

    def check_drm_data_stbm(self, partner_id, prtnmbr_id, otp_index, stbm_id, config_name, data_name, operation='encrypt', ext_srv_id=0, drmw = None):
        log('=====check_drm_data START=====')
        log('BLBX: %s' % ext_srv_id)
        try:
            self.drm_helper.check_drm_data_stbm(int(partner_id), int(prtnmbr_id), int(otp_index), int(stbm_id), str(config_name), str(data_name), operation, int(ext_srv_id), str(drmw))
            return 1
        except Exception, e:
            log('ERROR in check_drm_data: %s' %e)
            return 0

    def get_nextfree_partner_id(self):
        log('=====get_nextfree_partner_id START=====')
        return self.drm_helper.get_nextfree_partner_id()

#========================OTPValidation keywords=================

    def check_processed_otp_file(self, input_file, output_file):
        log('=====check_processed_otp_file START=====')
        return Helpers.OTPValidation.OTPValidation(self.db).check_processed_otp_file(input_file, output_file)

    def check_processed_otp_file_v3_v4(self, input_file, output_file, version=3):
        log('=====check_processed_otp_file START=====')
        try:
            return Helpers.OTPValidation.OTPValidation(self.db).check_processed_otp_file_v3_v4(input_file, output_file, version)
        except Exception as E:
            log('Error in check_processed_otp_file_v3_v4: %s' % E)
            return 0
#===============================================================

    def check_encrypt_ssl_certificates_gameconsole(self, pttp_id, dvkm_common_key_id, manuf_name, input_file,  cert_per_file, output_file_with_certs):
        try:
            return ssl.SSLEncryption(self.db).check_encrypt_ssl_certificates_gameconsole(int(pttp_id), int(dvkm_common_key_id), str(manuf_name), str(input_file),  int(cert_per_file), str(output_file_with_certs))
        except Exception as E:
            log('Error in check_encrypt_ssl_certificates_gameconsole: %s' % E)
            return 0

    def check_encrypt_ssl_certificates_stingray(self, input_file, full_path_output_file):
        try:
            return ssl.SSLEncryption(self.db).check_encrypt_ssl_certificates_stingray(str(input_file), str(full_path_output_file))
        except Exception as E:
            log('Error in check_encrypt_ssl_certificates_stingray: %s' % E)
            return 0

    def check_encrypt_ssl_certificates_universal(self, pttp_id, dvkm_common_key_id, aux_set_id, iv_type, ladder_lvl, ssl_type, input_file):
        path_to_output_file = os.path.join(km_help.get_homedir_out(), 'encrypted_%s' % input_file)
        path_to_input_file = os.path.join(km_help.get_homedir_in(), input_file)
        try:
            return ssl.SSLEncryption(self.db).check_encrypt_ssl_certificates_universal(int(pttp_id), int(dvkm_common_key_id), int(aux_set_id), iv_type, ladder_lvl, int(ssl_type), str(path_to_input_file), str(path_to_output_file))
        except Exception as E:
            log('Error in check_encrypt_ssl_certificates_universal: %s' % E)
            return 0

#=====================Manufacturer==============================

    def get_any_manufacturer_name_from_db(self):
        log('=====get_any_manufacturer_name_from_db START=====')
        return Helpers.ManufacturerChecking.ManufacturerChecking().get_any_manufacturer_name_from_db()

    def get_any_manufacturer_id_with_stbm(self):
        log('====get_any_manufacturer_name_with_stb START====')
        return get_any_manufacturer_id_with_stbm(self.db)

    def get_manufacturer_id_by_name(self, manufacturerName):
        log('====get_manufacturerID_by_name %s START====' % manufacturerName)
        try:
            return get_manufacturer_id_by_name(self.db, manufacturerName)
        except Exception as E:
            return 'Manufacturer Name does not exist in db'

    def check_manufacturer_info(self, manufacturer_info, manufacturer_id, stb_model = None):
        log('====check_manufacturer_info START====')
        return check_manufacturer_info(self.db, manufacturer_info ,manufacturer_id, stb_model)

    def check_manufacturer_list(self, manufacturer_list):
        log('====check_manufacturer_list START====')
        return check_manufacturer_list(self.db, manufacturer_list)

    def check_deleted_manufacture(self, manufacture_id):
        log('====check_deleted_manufacture START====')
        try:
            return check_manufacture_deleted(self.db, manufacture_id)
        except Exception as E:
            log('ERROR manufacturer not deleted: %s' % E)
            return 'ERROR manufacturer not deleted'

    def get_last_btch_name(self):
        log('====get_last_batch_name START====')
        return Helpers.ManufacturerChecking.ManufacturerChecking().get_last_btch_name()

    def get_any_linked_stb_model_to_pttp(self):
        log('====get_any_stb_model START====')
        try:
            return get_any_linked_stb_model_to_pttp(self.db)
        except Exception as E:
            log('ERROR stb model is emty: %s' % E)
            return 'ERROR stb model is emty'
#=======================Generation Keys=========================

    def check_common_keys(self, file_common_keys, pttp_id, key_map):
        log('=====check_common_keys START=====')
        return Helpers.GenerateKeys.check_common_keys(file_common_keys, pttp_id, key_map)

    def check_common_keys_in_db(self, file_common_keys, pttp_id):
        log('=====check_common_keys_in_db START=====')
        return Helpers.GenerateKeys.check_common_keys_in_db(self.db, file_common_keys, pttp_id)

    def get_next_free_devc_num(self, pttp_id):
        log('=====get_next_free_devc_num START=====')
        query = 'select max(devc_num) from kmi_devices where pttp_pttp_id=%s' %pttp_id
        max_devc_num = self.db.conn.execute(query).fetchone()[0]
        return max_devc_num+1 if max_devc_num else 1

    def check_unique_keys(self, file_unique_keys, pttp_id, start_device, end_device, key_map, file_common_keys):
        log('=====check_unique_keys START=====')
        return Helpers.GenerateKeys.check_unique_keys(file_unique_keys, pttp_id, start_device, end_device, key_map, file_common_keys)

    def check_unique_keys_in_db(self, pttp_id, start_devc_num, end_devc_num, file_unique_keys, key_map):
        log('=====check_unique_keys_in_db START=====')
        return Helpers.GenerateKeys.check_unique_keys_in_db(self.db, pttp_id, start_devc_num, end_devc_num, file_unique_keys, key_map)


#=======================ExportKeys===============================

    def add_pttp_without_obf_and_linked_with_blbx(self, blackbox_id, dvcl_id, end_devc_num=100):
        log('=====add_pttp_without_obf_and_linked_with_blbx START=====')
        return Helpers.ExportKeys.add_pttp_without_obf_and_linked_with_blbx(self.db, blackbox_id, dvcl_id, end_devc_num)

    def add_pttp_without_obf_and_linked_with_blbx_forced(self, blackbox_id, dvcl_id, end_devc_num=100):
        log('=====add_pttp_without_obf_and_linked_with_blbx START=====')
        return Helpers.ExportKeys.add_pttp_without_obf_and_linked_with_blbx_forced(self.db, blackbox_id, dvcl_id, end_devc_num)

    def add_pttp_linked_with_blbx(self, blackbox_id, dvcl_id):
        log('=====add_pttp_linked_with_blbx START=====')
        return Helpers.ExportKeys.add_pttp_linked_with_blbx(self.db, blackbox_id, dvcl_id)

    def add_blbx_with_keyladder(self, blbx_name='BlackBox'):
        log('=====add_blbx_with_keyladder START=====')
        return Helpers.ExportKeys.add_blbx_with_keyladder(blbx_name)

    def generate_keys_for_parttype(self, pttp_id, start_device, end_device):
        log('=====generate_keys_for_parttype START=====')
        return generate_keys_for_pttp(self.db, pttp_id, start_device, end_device)

    def get_any_blackbox_with_keyladder(self):
        log('=====get_any_blackbox_with_key_ladder START=====')
        return Helpers.ExportKeys.get_any_blackbox_with_keyladder(self.db)

    def check_exported_keys_universal_gs1_lcs1(self, pttp_id, start_devc_num, end_devc_num, blackbox_id, exported_keys_filename):
        log('=====check_exported_keys_universal_gs1_lcs1 START=====')
        return Helpers.ExportKeys.check_exported_keys_universal_gs1_lcs1(self.db, int(pttp_id), int(start_devc_num), int(end_devc_num), int(blackbox_id), exported_keys_filename)

    def check_exported_keys_universal(self, pttp_id, start_devc_num, end_devc_num, blackbox_id, exported_keys_filename, ptnmb_id=0):
        log('=====check_exported_keys_universal START=====')
        return Helpers.ExportKeys.check_exported_keys_universal(self.db, int(pttp_id), start_devc_num, end_devc_num, int(blackbox_id), exported_keys_filename, int(ptnmb_id))

    def check_exported_individual_key(self, pttp_id, start_device, end_device, key_index, filename, kdf_key_id=0, is_root=True, rom_id=0, jtg_ctrl=''):
        log('=====check_exported_individual_key START=====')
        return Helpers.ExportKeys.check_exported_individual_key(self.db, int(pttp_id), int(start_device), int(end_device), int(key_index), filename, int(kdf_key_id), is_root, int(rom_id), jtg_ctrl)

    def check_exported_keys_in_aps(self, pttp_id, start_device, end_device, ext_srv_id, fwkey_id, keys_file, conf_file):
        log('=====check_exported_keys_in_aps START=====')
        try:
            return Helpers.ExportKeys.check_exported_keys_in_aps(self.db, pttp_id, start_device, end_device, ext_srv_id, fwkey_id, keys_file, conf_file)
        except Exception as E:
            log('Error in check_exported_keys_in_aps: %s' % E)
            return 0

    def check_exported_keys_in_cas(self, pttp_id, start_devc, end_devc, aux_set_id, algo, keys_file, gs=None):
        log('=====check_exported_keys_in_cas START=====')
        try:
            return Helpers.ExportKeys.check_exported_keys_in_cas(self.db, int(pttp_id), int(start_devc), int(end_devc), int(aux_set_id), algo, keys_file, gs)
        except Exception as E:
            log('Error in check_exported_keys_in_aps: %s' % E)
            return 0

    def check_exported_keys_in_casdb_kdf(self,  pttp_id, start_devc, end_devc, aux_set_id, algo_mode, filename, algo, oper_id, kdf_num):
        log('=====check_export_keys_in_casdb_kdf START====')
        return Helpers.ExportKeys.check_exported_keys_in_cas_kdf(self.db, int(pttp_id), int(start_devc), int(end_devc), int(aux_set_id), algo_mode, filename, algo, int(oper_id), int(kdf_num))

    def check_exported_pairing_keys(self, pttp_id, start_devc, end_devc, list_versions, otp_key_index, auxset_id, algo,  keys_file):
        log('=====check_exported_pairing_keys START=====')
        try:
            return self.aux_helper.check_exported_pairing_keys( pttp_id, start_devc, end_devc, list_versions, otp_key_index, auxset_id, 2, algo,  keys_file)
        except Exception as E:
            log('Error in check_exported_keys_in_aps: %s' % E)
            return 0

    def check_batch(self, batch_id, expected_batch_name, batch_type_id):
        log('=====check_batch START=====')
        return Helpers.KmiHelper.check_batch(self.db, batch_id, expected_batch_name, int(batch_type_id))

    def create_keymap_without_obf_only_fw_keys(self, dvcl_id):
        log('=====create_keymap_without_obf only fw keys START=====')
        return Helpers.Management.create_keymap_for_dvcl_only_fw_keys(dvcl_id)

    def check_fwkeys_was_added_successfully(self, key_code, key_algo, key_privacy, key_fragment, need_fwky_id=False):
        return Helpers.Management.check_fwkeys_was_added_successfully(self.db, key_code, key_algo, key_privacy, key_fragment, need_fwky_id)

    def create_keymap_without_obf(self, dvcl_id):
        log('=====create_keymap_without_obf START=====')
        return Helpers.Management.create_keymap_for_dvcl_without_obf(dvcl_id)

    def create_keymap_with_one_seed(self, dvcl_id):
        log('=====create_keymap_with_one_seed START=====')
        return Helpers.Management.create_keymap_with_one_seed(dvcl_id)

    def create_keymap_with_two_seed(self, dvcl_id):
        log('=====create_keymap_with_two_seed START=====')
        return Helpers.Management.create_keymap_with_two_seed(dvcl_id)

    def create_keymap_for_amlogic(self, dvcl_id):
        log('=====create_keymap_for_amlogic START=====')
        return Helpers.Management.create_keymap_for_amlogic(dvcl_id)

    def create_keymap_for_aps(self, dvcl_id):
        log('=====create_keymap_for_aps START=====')
        return Helpers.Management.create_keymap_for_aps(dvcl_id)


    def get_max_device_not_generated(self, pttp_id):
        log('=====get_max_device_not_generated START=====')
        return Helpers.Management.get_max_device_not_generated(self.db,pttp_id)

    def get_any_lest_name_with_lest_id_pttp_id(self):
        log('====get_any_lest_name_with_lest_id_pttp_id START====')
        return Helpers.Management.get_any_lest_name_with_lest_id_pttp_id(self.db)

    def check_that_lest_name_was_changed(self, lest_name, lest_id, pttp_id):
        log('====check_that_lest_name_was_changed START====')
        return Helpers.Management.check_that_lest_name_was_changed(self.db, lest_name, lest_id, pttp_id)


#=======================TestParttype===============================

    def get_any_test_pttp(self):
        log('=====get_any_test_pttp START=====')
        return Helpers.TestParttype.get_test_pttp(self.db)

    def get_test_pttp_without_obf(self):
        log('=====get_test_pttp_without_obf START=====')
        return Helpers.TestParttype.get_test_pttp(self.db, 0)

    def get_test_pttp_with_KOF1(self):
        log('=====get_test_pttp_with_KOF1 START=====')
        return Helpers.TestParttype.get_test_pttp(self.db, 1)

    def get_test_pttp_with_KOF2(self):
        log('=====get_test_pttp_with_KOF2 START=====')
        return Helpers.TestParttype.get_test_pttp(self.db, 2)

    def get_test_pttp_with_fwkeys(self):
        log('=====get_test_pttp_with_fwkeys START=====')
        return Helpers.TestParttype.get_test_pttp_with_fwkeys(self.db)

    def get_test_pttp_with_fw_keys_and_stbmodel(self):
        log('=====get_test_pttp_with_fw_keys_and_stbmodel START=====')
        return Helpers.TestParttype.get_test_pttp_with_fw_keys_and_stbmodel(self.db)

    def check_test_pttp_keys(self, pttp_id, testpttp_plain_keys, testpttp_obf_keys):
        log('=====check_test_plain_keys START=====')
        return Helpers.TestParttype.check_test_pttp_keys(self.db, int(pttp_id), testpttp_plain_keys, testpttp_obf_keys)

    def get_devices_status_from_test_pttp(self, pttp_id):
        log('=====get_devices_status_from_test_pttp START=====')
        return Helpers.TestParttype.get_devices_status_from_test_pttp(self.db, pttp_id)

    def get_linked_aes_fwkey_by_pttp(self, dvcl_id, pttp_id):
        log('=====get_linked_aes_fwkey_by_pttp START=====')
        return Helpers.FirmwareKeys.get_fwkey_id(self.db, 'aes', dvcl_id, pttp_id, linked=1)

    def get_not_linked_aes_fwkey_by_pttp(self, dvcl_id, pttp_id):
        log('=====get_not_linked_aes_fwkey_by_pttp START=====')
        return Helpers.FirmwareKeys.get_fwkey_id(self.db, 'aes', dvcl_id, pttp_id)

    def get_linked_rsa_fwkey_by_pttp(self, dvcl_id, pttp_id):
        log('=====get_linked_rsa_fwkey_by_pttp START=====')
        return Helpers.FirmwareKeys.get_fwkey_id(self.db, 'rsa', dvcl_id, pttp_id, linked=1)

    def get_aes_fwkey_by_pttp_and_stbmodel(self, dvcl_id, pttp_id, stbm_id):
        log('=====get_aes_fwkey_by_pttp_and_stbmodel START=====')
        return Helpers.FirmwareKeys.get_fwkey_id(self.db, 'aes', dvcl_id, pttp_id, stbm_id)

    def get_rsa_fwkey_by_pttp_and_stbmodel(self, dvcl_id, pttp_id, stbm_id):
        log('=====get_rsa_fwkey_by_pttp_and_stbmodel START=====')
        return Helpers.FirmwareKeys.get_fwkey_id(self.db, 'rsa', dvcl_id, pttp_id, stbm_id)

    def get_rsa_fwkey_by_dvcl(self, dvcl_id):
        log('=====get_rsa_fwkey_by_dvcl START=====')
        return Helpers.FirmwareKeys.get_fwkey_id(self.db, 'rsa', dvcl_id)

    def get_aes_fwkey_by_dvcl(self, dvcl_id):
        log('=====get_rsa_fwkey_by_dvcl START=====')
        return Helpers.FirmwareKeys.get_fwkey_id(self.db, 'aes', dvcl_id)

    def get_stbm_id_linked_to_pttp(self, pttp_id):
        log('=====get_stbm_id_linked_to_pttp START=====')
        return Helpers.StbModel.get_stbm_id_linked_to_pttp(self.db, pttp_id)

    def check_exported_fw_key_for_test_pttp(self, file_with_fwkey, fwkey_id):
        log('=====check_exported_fw_key_for_test_pttp START=====')
        return Helpers.TestParttype.check_exported_fw_key_for_test_pttp(self.db, file_with_fwkey, fwkey_id)

    def check_devices_status(self, pttp_id, start_devc, end_devc, expected_status):
        log('=====check_devices_status START=====')
        try:
            Helpers.KmiHelper.check_devices_status(self.db, pttp_id, start_devc, end_devc, int(expected_status))
            return 1
        except Exception as E:
            log('Error in check_devices_status: %s' % E)
            return 0

    def get_unique_key_index(self, pttp_id):
        log('=====get_unique_key_index START=====')
        return Helpers.KmiHelper.get_unique_key_index(self.db, pttp_id)



#==================UsersAndUserKeys====================================

    def generate_pgp_key(self, email, length, key_name, type):
        log('=====generate_public_key START=====')
        return ukey.generate_pgp_key(str(email),int(length), str(key_name), str(type))

    def generate_pgp_key_without_first_line(self,  email, length, key_name, type):
        log('=====generate_pgp_key_without_first_line START=====')
        return ukey.generate_pgp_key_without_first_line(str(email), int(length), str(key_name), str(type))

    def get_any_user(self):
        log('=====get_any_user START=====')
        return ukey.get_any_user(self.db)

    def check_public_key(self, user_id, key_id, key_value):
        log('=====check_public_key START=====')
        return ukey.check_public_key(self.db, user_id, key_id, key_value)

    def get_number_keys_for_user(self, user_id):
        log('=====get_number_keys_for_user START=====')
        return ukey.get_number_keys_for_user(self.db, user_id)

    def check_pgp_key_pair(self, user_id, pttp_id, key_name, key_email, comment, expires_time):
        log('=====check_pgp_key_pair START=====')
        return ukey.check_pgp_key_pair(self.db, int(user_id), int(pttp_id), key_name, key_email, comment, int(expires_time))

    def get_number_keys_for_pttp(self, pttp_id):
        log('=====get_number_keys_for_pttp START=====')
        return ukey.get_number_keys_for_pttp(self.db, pttp_id)

    def get_pttp_with_pgp(self):
        log('=====get_pttp_with_pgp START=====')
        return ukey.get_pttp_with_pgp(self.db)

    def check_exported_public_key(self, key_id, pttp_id, output_filename):
        log('=====check_exported_public_key START=====')
        return ukey.check_exported_public_key(self.db, int(key_id), int(pttp_id), str(output_filename))

    def get_public_user_key_id(self):
        log('=====get_public_user_key_id START=====')
        return ukey.get_public_user_key_id(self.db)

    def get_private_pgp_key(self):
        log('=====get_private_pgp_key START=====')
        return ukey.get_private_pgp_key(self.db)

    def check_user_keys(self, key_list, user_id):
        log('=====check_user_keys START=====')
        return ukey.check_user_keys(self.db, key_list, user_id)

    def get_any_user_id_with_keys(self):
        log('=====get_any_user_id_with_keys START=====')
        return ukey.get_any_user_id_with_keys(self.db)

    def get_generated_user_keyid(self, user_id):
        log('=====get_generated_user_keyid START=====')
        return ukey.get_generated_user_keyid(self.db, user_id)

    def is_pgp_key_deleted(self, key_id):
        log('=====is_pgp_pair_deleted START=====')
        return ukey.is_pgp_key_deleted(self.db, key_id)

    def encrypt_ssl_sertificat(self, full_path):
        log('====encrypt_ssl_sertificat START====')
        return ukey.encrypt_file(self.db, full_path)

    def check_hash(self, blbx_name, path_to_file):
        log('====Check Hash START====')
        return ukey.check_hash(self.db, blbx_name, path_to_file)

#===================REPORTS=========================


    def generate_programming_report(self, pttp_id, start_devc, end_devc, report_name, fw=None):
        log('=====generate_programming_report START=====')
        return report.generate_programming_report(int(pttp_id), int(start_devc), int(end_devc), str(report_name), fw)

    def generate_prorgaming_report_all_ok(self, pttp_id, start_devc, end_devc, report_name, fw=None):
        log('=====generate_programming_report START=====')
        return report.generate_prorgaming_report_all_ok(int(pttp_id), int(start_devc), int(end_devc), str(report_name), fw)

    def check_statuses_after_programming_import(self,pttp_id, start_devc, end_devc, report_name, not_exported=None):
        log('=====check_statuses_after_import START=====')
        return report.check_statuses_after_programming_import(self.db, int(pttp_id), int(start_devc), int(end_devc),report_name, not_exported)

    def check_statuses_after_manufacturing_report(self, btch_name, pttp_id, report_name, start_devc = None, end_devc = None):
        log('====check_statuses_after_manufacturing_report START====')
        try:
            return report.check_statuses_after_manufacturing_report(self.db, btch_name, int(pttp_id), report_name, start_devc, end_devc)
        except Exception, E:
            log('ERROR in check_statuses_after_manufacturing_report: %s' % E)

    def get_not_exported_devices(self, pttp_id):
        log('=====get_not_exported_devices START=====')
        return report.get_not_exported_devices(self.db, int(pttp_id))

    def generate_manufacturing_report(self, pttp_id, start_devc, end_devc, report_name, second_pttp = 0, co_processor=None):
        log('=====generate_manufacturing_report START=====')
        try:
            return report.generate_manufacturing_report(self.db, int(pttp_id), int(start_devc), int(end_devc), str(report_name), int(second_pttp), co_processor)
        except Exception as e:
            log('ERROR in generate manufacturing report: %s' % e)
            return 'ERROR in generate manufacturing report'

    def generate_wrong_manufacturing_report(self, pttp_id, start_devc, end_devc, report_name, second_pttp = 0, co_processor=None, version=1, secondstring=1, laststring=1):
        log('=====generate_manufacturing_report START=====')
        try:
            return report.generate_wrong_manufacturing_report(self.db, int(pttp_id), int(start_devc), int(end_devc), str(report_name), int(second_pttp), co_processor,
                                                              int(version), int(secondstring), int(laststring))
        except Exception as e:
            log('ERROR in generate manufacturing report: %s' % e)
            return 'ERROR in generate manufacturing report'

    def genereta_internal_manufacturing_report(self, pttp_id, stb_id, manuf_id, start_devc, end_devc, report_name):
        log('=====generate_manufacturing_report START=====')
        return report.genereta_internal_manufacturing_report(self.db, int(pttp_id), int(stb_id), int(manuf_id), int(start_devc), int(end_devc), str(report_name))

    def pipe_check_statuses_after_manufacturing_report(self, pttp_id, report_name, co_proc=None, second_pttp=0):
        try:
            log('=====check_statuses_after_PIPE_import_manufacturing_report START====')
            return report.pipe_check_statuses_after_manufacturing_report(self.db, pttp_id, report_name, co_proc, int(second_pttp))
        except Exception as e:
            log('ERROR in pipe_check_statuses_after_manufacturing_report^ %s' %e)
            return 0

#==================ExternalServer====================

    def encrypt_and_check_data_by_ext_server_keyladder(self, filename, extserver_id, filesize):
        path_to_clean_file, path_to_enc_file, clean_data = Helpers.ExternalServers.create_empty_file_by_size(filename, int(filesize))
        try:
            dal.kmi_encryptByKeyLadderForExtServer(str(path_to_clean_file), str(path_to_enc_file), int(extserver_id))
        except:
            return 0
        return Helpers.ExternalServers.check_encrypted_data_by_ext_server_keyladder(self.db, path_to_enc_file, clean_data, int(extserver_id))


#===================DATABASE=========================

    def check_subsystem_versions(self):
        engine = create_engine('postgresql://postgres:@192.168.14.42:5434/kmi', client_encoding='utf8')
        # engine = create_engine('postgresql://postgres:@192.168.10.112:5433/kmi', client_encoding='utf8')
        #Session = sessionmaker(bind=engine)
        #self.session = Session()
        conn = engine.connect()
        log('Connect to DB = %s on host = %s successfully' % ('kmi', '192.168.14.42'))
        # log('Connect to DB = %s on host = %s successfully' % ('kmi', '192.168.10.112'))
        query = "select count(*) from kmi_subsystem_versions"
        count_line = conn.execute(query).fetchone()[0]
        assert(count_line==1), 'Wrong count line in kmi_subsystem_versions: possible install_full.sh NOT executed success'
        return 1

#################################################################################
#################################################################################
#################################################################################


    def file_copy_to_ftp(self, full_path):
        log('====Copy file to ftp START====')
        return Helpers.PyFTP.FTP_conn().copy_ftp(str(full_path), 'to')

    def file_copy_from_ftp(self, filename):
        log('====Copy file from ftp START====')
        return Helpers.PyFTP.FTP_conn().copy_ftp(str(filename), 'from')

    def encrypt_file(self, path_to_key, filename):
        log('====Encrypt file START====')
        return Helpers.PyFTP.encrypt_file(str(path_to_key), str(filename))

    def decrypt_file(self, path_to_key, filename):
        log('====Decrypt file START====')
        return Helpers.PyFTP.decrypt_file(str(path_to_key), str(filename))

    def check_lock_wf_managment(self, wf_name):
        log('====Check_lock_wf START====')
        return Helpers.WfLock.check_lock(self.db, wf_name)

    def get_max_released_device(self, pttp_id):
        log('====get_max_released_device START====')
        return get_max_released_device(self.db, pttp_id)


#====================FirmWare keys========================


    def check_generated_fw_key(self, fw_key_id):
        log('====check_generated_fw_key START====')
        return Helpers.FirmwareKeys.check_generated_fw_key(self.db, fw_key_id)


#====================TestRail KW==========================

    def get_test_data(self, case_id):
        log('====get_test_data START====')
        return get_test_data(case_id)


    def create_keymap_for_akms(self,case_id, dvcl_id):
        log('====create_keymap_for_akms START====')
        create_keymap_for_akms(case_id, dvcl_id)


    def clear_pttp_for_akms(self):
        log('====clear_pttp_for_akms START====')
        clear_pttp_for_akms(self.db, 10)

    def link_pttp_to_dvcl(self, pttp_id, dvcl_id):
        log('====link_pttp_to_dvcl START====')
        link_pttp_to_dvcl(self.db, int(pttp_id), int(dvcl_id))

    def check_imported_common_keys(self, pttp_id, commonkeys_file, aes_file):
        log('=====check_imported_common_keys=====')
        return genkeys.check_common_keys_in_db(self.db, str(commonkeys_file), int(pttp_id), str(aes_file))


    def check_imported_unique_keys(self, pttp_id, start_devc, end_devc, uniq_file, aes_file):
        log('=====check_imported_unique_keys=====')
        return genkeys.check_imported_unique_keys(self.db, int(pttp_id), int(start_devc), int(end_devc), str(uniq_file), str(aes_file))

    def drop_all_wf_lock(self):
        lock_ids = Helpers.Management.get_lock_ids(self.db)
        if len(lock_ids) != 0:
            for item in lock_ids:
                dal.kmi_deleteWorkflowLock(item)
        return 1

    def get_plain_fw_by_id(self):
        Helpers.ExportKeys.get_plain_fw_by_id(self.db)