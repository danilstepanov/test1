__author__ = 'stepanov'
from DB_ORM_classes import *
from KeyLadder import KeyLadder
from Crypto.Hash import SHA256
import random, re, struct, os
import Helpers.KmiHelper as kmihelper
from Logger import log
from itertools import tee
from sqlalchemy.sql.expression import case


class PartnerDRM(object):

    def __init__(self, sql_obj):
        self.db = sql_obj


    def get_number_active_partners(self):
        return self.db.session.query(Partner).filter(Partner.del_date == None).count()

    def get_number_all_partners(self):
        return self.db.session.query(Partner).count()

    def get_number_ivs(self):
        return self.db.session.query(PartnerParttype).count()



    def get_any_partner_id_from_db(self):
        query = self.db.session.query(Partner.prtnr_name).filter(Partner.del_date == None)
        count = query.count()
        if count == 1:
            rand = 0
        else:
            rand = random.randint(0, count - 1)
        name = query[rand][0]
        return name

    def get_partner_name_by_id(self, partnr_id):
        return self.db.session.query(Partner.prtnr_name).filter(Partner.prtnr_id == partnr_id).one()[0]

    def get_partner_id_by_name(self, partnr_name):
        return self.db.session.query(Partner.prtnr_id).filter(Partner.prtnr_name == partnr_name).one()[0]

    def is_partner_in_db(self, partner):
        try:
            self.db.session.query(Partner).filter(Partner.prtnr_id == partner.partnerId, Partner.prtnr_name == partner.partnerName).one()
            return 1
        except Exception,e:
            log('ERROR in is_partner_in_db: %s' %e)
            return 0


    def is_partner_active(self, prtnr_id):
        try:
            self.db.session.query(Partner).filter(Partner.prtnr_id == prtnr_id, Partner.del_date == None).one()
            return 1
        except Exception,e:
            log('ERROR in is_partner_active: %s' % e)
            return 0

    def is_iv_active(self, prtnr_id, pttp_id):
        try:
            self.db.session.query(PartnerParttype).filter(PartnerParttype.prtnr_prtnr_id == prtnr_id, PartnerParttype.pttp_pttp_id == pttp_id, PartnerParttype.del_date == None).one()
            return 1
        except Exception,e:
            log('ERROR in is_iv_active: %s' % e)
            return 0

    def check_partner_list(self, kmi_partner_list):
        count_prtnrs_in_db = self.db.session.query(Partner).filter(Partner.del_date == None).count()
        if len(kmi_partner_list) != count_prtnrs_in_db:
            log('In DB %s partners, from kmi returned %s' % (count_prtnrs_in_db, len(kmi_partner_list)))
            return 0
        for partner in kmi_partner_list:
            log('Checking partner: %s - %s' % (partner.partnerId, partner.partnerName))
            if self.is_partner_in_db(partner) == 0:
                log('In db NO partner_id %s' % partner.partnerId)
                return 0
        return 1

    def get_iv_length(self, partnr_id, pttp_id):
        try:
            iv = self.db.session.query(PartnerParttype.prtnr_iv_value).filter(PartnerParttype.prtnr_prtnr_id == partnr_id, PartnerParttype.pttp_pttp_id == pttp_id).one()
            return len(iv[0])
        except Exception,e:
            log('ERROR in get_iv_length: %s' % e)
            return 0

    def get_iv(self, partnr_id, pttp_id):
        try:
            return self.db.session.query(PartnerParttype.prtnr_iv_value).filter(PartnerParttype.prtnr_prtnr_id == partnr_id, PartnerParttype.pttp_pttp_id == pttp_id, PartnerParttype.del_date == None).one()[0]
        except Exception,e:
            log('ERROR in get_iv: %s' % e)
            return 0

    def check_partner_iv_info(self, prtnr_id, pttp_id, kmi_partner_iv_info):
        partnr_name = self.get_partner_name_by_id(prtnr_id)
        pttp_name = self.db.session.query(PartType.pttp_name).filter(PartType.pttp_id == pttp_id).one()[0]
        iv = self.get_iv(prtnr_id, pttp_id)
        iv_from_kmi = kmi_partner_iv_info.initVector
        log(iv_from_kmi)
        return kmi_partner_iv_info.partnerId == prtnr_id and kmi_partner_iv_info.partnerName == partnr_name and kmi_partner_iv_info.partTypeId == pttp_id and kmi_partner_iv_info.partTypeName == pttp_name and iv_from_kmi == iv

    def check_list_partner_iv_info(self, kmi_partner_iv_info_list, prtnr_id, pttp_id):
        if (prtnr_id == 0 and pttp_id != 0):
            db_partner_iv_info_tuple = self.db.session.query(PartnerParttype.prtnr_prtnr_id, Partner.prtnr_name, PartnerParttype.pttp_pttp_id, PartType.pttp_name, PartnerParttype.prtnr_iv_value).filter(PartnerParttype.pttp_pttp_id == pttp_id, PartType.pttp_id == pttp_id, Partner.prtnr_id == PartnerParttype.prtnr_prtnr_id, PartnerParttype.del_date == None).all()
        elif (prtnr_id != 0 and pttp_id == 0):
            db_partner_iv_info_tuple = self.db.session.query(PartnerParttype.prtnr_prtnr_id, Partner.prtnr_name, PartnerParttype.pttp_pttp_id, PartType.pttp_name, PartnerParttype.prtnr_iv_value).filter(PartnerParttype.prtnr_prtnr_id == prtnr_id, Partner.prtnr_id == prtnr_id, PartType.pttp_id == PartnerParttype.pttp_pttp_id, PartnerParttype.del_date == None).all()
        elif (prtnr_id == 0 and pttp_id == 0):
            db_partner_iv_info_tuple = self.db.session.query(PartnerParttype.prtnr_prtnr_id, Partner.prtnr_name, PartnerParttype.pttp_pttp_id, PartType.pttp_name, PartnerParttype.prtnr_iv_value).filter(Partner.prtnr_id == PartnerParttype.prtnr_prtnr_id, PartType.pttp_id == PartnerParttype.pttp_pttp_id, PartnerParttype.del_date == None).all()
        else:
            db_partner_iv_info_tuple = self.db.session.query(PartnerParttype.prtnr_prtnr_id, Partner.prtnr_name, PartnerParttype.pttp_pttp_id, PartType.pttp_name, PartnerParttype.prtnr_iv_value).filter(PartnerParttype.prtnr_prtnr_id == prtnr_id, Partner.prtnr_id ==prtnr_id, PartnerParttype.pttp_pttp_id == pttp_id, PartType.pttp_id == pttp_id, PartnerParttype.del_date == None).all()
        if len(kmi_partner_iv_info_list) != len(db_partner_iv_info_tuple):
            log('In db there are %s IVs, from KMI %s IVs' % (len(db_partner_iv_info_tuple), len(kmi_partner_iv_info_list)))
            return 0
        for item1 in db_partner_iv_info_tuple:
            i = 0
            for item2 in kmi_partner_iv_info_list:
                i += 1
                if (item1.prtnr_prtnr_id == item2.partnerId and item1.prtnr_name == item2.partnerName and item1.pttp_pttp_id == item2.partTypeId and item1.pttp_name == item2.partTypeName and item1.prtnr_iv_value ==item2.initVector):
                    break
                if i == len(kmi_partner_iv_info_list):
                    log('There are no IVinfo in KMI for partner %s and parttype %s' %(item1.prtnr_name, item1.pttp_name))
                    return 0
        log('Checking partner_iv_info_list SUCCESS')
        return 1

    def check_drm_config(self, partner_id, prtnmbr_id, otp_index, config_name, extfile):
        path_to_config = os.path.join(kmihelper.get_homedir_out(), config_name)
        config_list = [line.strip() for line in open(path_to_config)]
        error_list = []
        if config_list[0] != 'Version 2.0':
            error_list.append('Error in first line')
        if config_list[1] != '':
            error_list.append('Error in second line, must be empty')
        kl = KeyLadder(self.db)
        pttp_id = self.db.session.query(PartNumber.pttp_pttp_id).filter(PartNumber.ptnm_id == prtnmbr_id).one()[0]
        partner_iv_from_db = self.db.session.query(PartnerParttype.prtnr_iv_value).filter(PartnerParttype.pttp_pttp_id == pttp_id, PartnerParttype.prtnr_prtnr_id == partner_id).one()[0]
        if config_list[2] != '%-13s: %s' % ('Partner IV', partner_iv_from_db.encode('hex')):
            error_list.append('Error Partner IV: in file line = %s, expected line = %s' % (config_list[2], '%-13s: %s' % ('Partner IV', partner_iv_from_db.encode('hex'))))
        if config_list[3] != '%-13s: %d' % ('OTP Key ID', otp_index):
            error_list.append('Error OTP Key ID: in file line = %s, expected line = %s' % (config_list[3], '%-13s: %d' % ('OTP Key ID', otp_index)))
        if config_list[4] != '%-13s: %s' % ('OTP Key Type', kl.get_otp_key_type(pttp_id, otp_index)):
            error_list.append('Error OTP Key Type: in file line = %s, expected line = %s' % (config_list[4], '%-13s: %s' % ('OTP Key Type', kl.get_otp_key_type(pttp_id, otp_index))))
        part_nmb_name_db = self.db.session.query(PartNumber.part_number).filter(PartNumber.ptnm_id == prtnmbr_id).one()[0]
        if extfile is None:
            if config_list[5] != '%-13s: %s' % ('PartNumber', part_nmb_name_db):
                error_list.append('Error PartNumber: in file line = %s, expected line = %s' % (config_list[5], '%-13s: %s' % ('PartNumber', part_nmb_name_db)))
        if config_list[6] != '%-13s: %08X' % ('PartType', pttp_id):
            error_list.append('Error PartType: in file line = %s, expected line = %s' % (config_list[6], '%-13s: %08X' % ('PartType', pttp_id)))
        seed_from_file = config_list[7].split(':')[1].strip()
        if len(seed_from_file) != 64 and config_list[7].split(':')[0].strip() != 'SeedValue':
            error_list.append('Error SeedValue')
        if len(error_list) == 0:
            log('check_drm_config SUCCESS')
            return 1
        else:
            log('check_drm_config NOT SUCCESS :%s ' % error_list)
            return 0


    def check_drm_data_stbm(self, partner_id, prtnmbr_id, otp_index, stbm_id, config_name, data_name, operation, ext_srv_id, drmw):
        pttp_id = self.db.session.query(PartNumber.pttp_pttp_id).filter(PartNumber.ptnm_id == prtnmbr_id).one()[0]
        try:
            amlogic_pttp = self.db.conn.execute("select value_number from kmi_resource_params where rprm_code='AMLOGIC_PATCH_PTTP'").fetchone()[0]
        except Exception as E:
            log('Error in getting AMLOGIC_PATCH_PTTP: %s' % E)
            amlogic_pttp = 0
        out_home_dir = kmihelper.get_homedir_out()
        path_to_data = os.path.join(out_home_dir, data_name)
        path_to_config = os.path.join(out_home_dir, config_name)
        conf_seed = self.get_seed_from_config(path_to_config)
        if pttp_id == amlogic_pttp:
            log('Using patch!!!!!')
            # path_to_data2 = os.path.join(out_home_dir, 'DRM-W_%s' % data_name)
            path_to_data2 = os.path.join(out_home_dir, drmw)
            assert(self.check_file_with_drmkeys_stbm(partner_id, pttp_id, otp_index, stbm_id, conf_seed, path_to_data2, operation, ext_srv_id, 1) == 1), 'Checking file with drm_keys for AMLOGIK from file %s UNSUCCESS' % path_to_data2
        assert(self.check_file_with_drmkeys_stbm(partner_id, pttp_id, otp_index, stbm_id, conf_seed, path_to_data, operation, ext_srv_id) == 1), 'Checking file with drm_keys  from file %s UNSUCCESS' % path_to_data

# partner_id, pttp_id, otp_index, start_dev, end_dev, config_seed, path_to_data, operation, ext_srv_id, is_amlogik=0
    def check_file_with_drmkeys_stbm(self, partner_id, pttp_id, otp_index, stbm_id, config_seed, path_to_data, operation, ext_srv_id, is_amlogik=0):
        key_ladder = KeyLadder(self.db)
        partner_iv = self.db.session.query(PartnerParttype.prtnr_iv_value).filter(PartnerParttype.pttp_pttp_id == pttp_id, PartnerParttype.prtnr_prtnr_id == partner_id).one()[0]
        stbd_id = self.db.session.query(StbDevice.stbd_id).filter(StbDevice.stbm_stbm_id == stbm_id).all()
        # devices_from_db = self.db.session.query(Device.devc_num).filter(Device.pttp_pttp_id == pttp_id,
        #                                                                 Device.dvst_dvst_id == 5).all()

        try:
            stbd_list = []
            for item in stbd_id:
                stbd_list.append(item[0])
            devices_from_db = self.db.session.query(Device.devc_num).filter(Device.pttp_pttp_id == pttp_id, Device.dvst_dvst_id == 5,
                                                                            Device.stbd_stbd_id.in_(stbd_list)).all()
        except Exception as e:
            return e
        with open(path_to_data) as file:
            number_line_in_file = 0
            current_devc = 0
            list_current_devc = []
            fst, snd = tee(file)
            for line in fst:
                if ';' in line:
                    if ext_srv_id == 0:
                        list_current_devc.append(int(line.split(';')[0], base=16))
                    else:
                        list_current_devc.append(int(line.split(';')[1], base=16))
            assert (len(devices_from_db) == len(list_current_devc)), 'ERROR different count devices device from db %s device from file %s' % (len(devices_from_db), len(list_current_devc))
            for line in snd:
                if number_line_in_file == 0:
                    assert (line.rstrip() == 'Version 1.0'), 'Wrong version in file with drm keys'
                    number_line_in_file += 1
                    continue
                if is_amlogik:
                    plain_otp_key = key_ladder.get_plain_otp_key_for_amlogik(pttp_id, otp_index, list_current_devc[current_devc])[:16]
                else:
                    plain_otp_key = key_ladder.get_plain_otp_key(pttp_id, otp_index, list_current_devc[current_devc])[:16]
                clear_drm_key = key_ladder.crypt_buf(plain_otp_key, partner_iv, operation=operation)
                if ext_srv_id == 0:
                    if number_line_in_file == 1:
                        assert (line.rstrip() == ''), 'Wrong second line in file with drm keys'
                        number_line_in_file += 1
                        continue
                    calc_key_value = self.drmkeys_calc_key_value_light_encryption(line, config_seed, key_ladder, clear_drm_key)
                    expected_line_re = '^%08X;[0-9a-f]{32};%s[;]?\\n?$' % (list_current_devc[current_devc], calc_key_value.encode('hex').rjust(32,'0'))
                else:
                    if line.rstrip() == '':
                        number_line_in_file += 1
                        continue
                    calc_key_value = self.drmkeys_calc_key_value_tde_encryption(current_devc, pttp_id, otp_index, ext_srv_id, line, key_ladder, clear_drm_key, list_current_devc)
                    expected_line_re = '^%08X;%016X;%s[;]?\\n?$' % (pttp_id, list_current_devc[current_devc], calc_key_value.encode('hex'))
                assert (re.search(expected_line_re, line) is not None), 'Error in line: %s, expected :%s' % (line, expected_line_re)
                number_line_in_file += 1
                current_devc += 1
            assert(current_devc == len(list_current_devc)), 'Wrong number devices in file in export %s count in test %s count' % (current_devc, len(list_current_devc))
        log('Check drm_data for devices stbm: %s devc SUCCESS' % (len(list_current_devc)))
        return 1

    def check_drm_data_from_ext_file(self, partner_id, pttp_id, otp_index, start_dev, end_dev, config_name, data_name, operation, ext_srv_id):
        return self.drm_data_check(partner_id, pttp_id, otp_index, start_dev, end_dev, config_name, data_name, operation, ext_srv_id)

    def check_drm_data(self, partner_id, prtnmbr_id, otp_index, start_dev, end_dev, config_name, data_name, operation, ext_srv_id):
        pttp_id = self.db.session.query(PartNumber.pttp_pttp_id).filter(PartNumber.ptnm_id == prtnmbr_id).one()[0]
        return self.drm_data_check(partner_id, pttp_id, otp_index, start_dev, end_dev, config_name, data_name, operation, ext_srv_id)

    def drm_data_check(self, partner_id, pttp_id, otp_index, start_dev, end_dev, config_name, data_name, operation, ext_srv_id):
        try:
            amlogic_pttp = self.db.conn.execute(
                "select value_number from kmi_resource_params where rprm_code='AMLOGIC_PATCH_PTTP'").fetchone()[0]
        except Exception as E:
            log('Error in getting AMLOGIC_PATCH_PTTP: %s' % E)
            amlogic_pttp = 0
        out_home_dir = kmihelper.get_homedir_out()
        path_to_data = os.path.join(out_home_dir, data_name)
        path_to_config = os.path.join(out_home_dir, config_name)
        conf_seed = self.get_seed_from_config(path_to_config)
        if pttp_id == amlogic_pttp:
            log('Using patch!!!!!')
            path_to_data2 = os.path.join(out_home_dir, 'DRM-W_%s' % data_name)
            assert (self.check_file_with_drmkeys(partner_id, pttp_id, otp_index, start_dev, end_dev, conf_seed, path_to_data2, operation, ext_srv_id,1) == 1), 'Checking file with drm_keys for AMLOGIK from file %s UNSUCCESS' % path_to_data2
        assert (self.check_file_with_drmkeys(partner_id, pttp_id, otp_index, start_dev, end_dev, conf_seed, path_to_data, operation, ext_srv_id) == 1), 'Checking file with drm_keys  from file %s UNSUCCESS' % path_to_data
        return 1

    def check_file_with_drmkeys(self, partner_id, pttp_id, otp_index, start_dev, end_dev, config_seed, path_to_data, operation, ext_srv_id, is_amlogik=0):
        key_ladder = KeyLadder(self.db)
        partner_iv = self.db.session.query(PartnerParttype.prtnr_iv_value).filter(PartnerParttype.pttp_pttp_id == pttp_id, PartnerParttype.prtnr_prtnr_id == partner_id).one()[0]
        with open(path_to_data) as file:
            number_line_in_file = 0
            current_devc = start_dev
            is_blacklisted_count = 0
            for line in file:
                if number_line_in_file == 0:
                    assert (line.rstrip() == 'Version 1.0'), 'Wrong version in file with drm keys'
                    number_line_in_file += 1
                    continue
                dvst_id, blacklisted = self.db.session.query(Device.dvst_dvst_id, Device.is_blacklisted).filter(Device.devc_num == current_devc, Device.pttp_pttp_id == pttp_id).one()
                while dvst_id == 6 and blacklisted == 1:
                    number_line_in_file += 1
                    current_devc += 1
                    is_blacklisted_count += 1
                    dvst_id, blacklisted = self.db.session.query(Device.dvst_dvst_id, Device.is_blacklisted).filter(
                        Device.devc_num == current_devc, Device.pttp_pttp_id == pttp_id).one()

                if is_amlogik:
                    plain_otp_key = key_ladder.get_plain_otp_key_for_amlogik(pttp_id, otp_index, current_devc)[:16]
                else:
                    plain_otp_key = key_ladder.get_plain_otp_key(pttp_id, otp_index, current_devc)[:16]
                clear_drm_key = key_ladder.crypt_buf(plain_otp_key, partner_iv, operation=operation)
                if ext_srv_id == 0:
                    #self.logger.info('Ligth encryption!!!!')
                    if number_line_in_file == 1:
                        assert (line.rstrip() == ''), 'Wrong second line in file with drm keys'
                        number_line_in_file += 1
                        continue
                    calc_key_value = self.drmkeys_calc_key_value_light_encryption(line, config_seed, key_ladder, clear_drm_key)
                    expected_line_re = '^%08X;[0-9a-f]{32};%s[;]?\\n?$' % (current_devc, calc_key_value.encode('hex').rjust(32,'0'))
                else:
                    #self.logger.info('TDE encryption!!!!')
                    if line.rstrip() == '':
                        number_line_in_file += 1
                        continue
                    calc_key_value = self.drmkeys_calc_key_value_tde_encryption(current_devc, pttp_id, otp_index, ext_srv_id, line, key_ladder, clear_drm_key)
                    expected_line_re = '^%08X;%016X;%s[;]?\\n?$' % (pttp_id, current_devc, calc_key_value.encode('hex'))
                #self.logger.info('calculated key for line %s = %s' % (number_line_in_file, calc_key_value.encode('hex')))
                assert (re.search(expected_line_re, line) is not None), 'Error in line: %s, expected :%s' % (line, expected_line_re)
                #self.logger.info('Processing line %s SUCCESS' % number_line_in_file)
                number_line_in_file += 1
                current_devc += 1
            assert(current_devc -1 == end_dev), 'Wrong number devices in file: expected %s but %s' % (str(current_devc-1), str(end_dev))
        log('Check drm_data for devices: %s - %s SUCCESS' % (start_dev, end_dev))
        return 1


    def drmkeys_calc_key_value_light_encryption(self, line, config_seed, key_ladder, clear_drm_key):
        mk = SHA256.new(config_seed).digest()
        iv_from_file = line.split(';')[1]
        calc_key_value = key_ladder.crypt_buf(mk, clear_drm_key, iv_from_file.decode('hex'), 'CBC')
        return calc_key_value

    def drmkeys_calc_key_value_tde_encryption(self,current_devc, pttp_id, otp_index, ext_srv_id, line, key_ladder, clear_drm_key, list_current_devc=None):
        buf = line.split(';')[2].decode('hex')
        kmbh_ind = struct.unpack('<H', buf[:2])[0]
        kmbe_ind = struct.unpack('<H', buf[2:4])[0]
        otp_type = key_ladder.get_otp_key_type(pttp_id, otp_index)
        if list_current_devc is not None:
            param_iv = pttp_id if otp_type == 'common' else list_current_devc[current_devc]
        else:
            param_iv = pttp_id if otp_type == 'common' else current_devc
        calc_key_value = key_ladder.signe_and_encrypt_buf_by_extsrv_ladder(clear_drm_key, ext_srv_id, param_iv, kmbe_ind, kmbh_ind)
        return calc_key_value


    def get_seed_from_config(self, path_to_config):
        file = open(path_to_config)
        lines = file.readlines()
        if lines[7].split(':')[0].strip() != 'SeedValue':
            print lines[-1]
            log('Error in getting seed_value')
            return 0
        else:
            return lines[7].split(':')[1].strip().decode('hex')
        file.close()

    def clear_partners(self):
        try:
            self.db.session.query(PartnerParttype).delete()
            self.db.session.query(Partner).delete()
            #self.db.session.query(Partner).update({Partner.del_date:time.ctime()})
            self.db.session.commit()
        except Exception as e:
            log('ERROR in deleting table %s, rollbacking: %s' % ('kmi_partners',e))
            self.db.session.rollback()

    def get_nextfree_partner_id(self):
        prtnrs_tuples = self.db.session.query(Partner.prtnr_id).order_by(Partner.prtnr_id).all()
        prtnr_list = [item[0] for item in prtnrs_tuples]
        free_prtnr_id = kmihelper.get_nextfree_value_from_list(prtnr_list)
        log('Next free partnr = %s' % free_prtnr_id)
        return free_prtnr_id