from sqlalchemy import asc, desc

from DB_ORM_classes import Device, DeviceStatus, Operator, StbModel, StbDevice, BlackBox, DeviceHistory, \
    Batch, Manufacturer, StbmodelParttype
import re, time, os, random
from Logger import log
from KmiHelper import get_int_ranges_from_list, get_homedir_in



def check_devices_in_blacklist(sqlalchemy_con, pttp_id, path_to_exported_file):
    blacklist_devices = sqlalchemy_con.session.query(Device.devc_num, DeviceStatus.dvst_name).filter(Device.dvst_dvst_id == DeviceStatus.dvst_id, Device.is_blacklisted == 1, Device.pttp_pttp_id == pttp_id).order_by(Device.devc_num).all()
    list_blacklist_devices = [item[0] for item in blacklist_devices]
    filename = path_to_exported_file.split('/')[-1]
    filename_re = '^%sT[0-2][0-9][0-5][0-9]_PTID-%08X_blacklisted_devices_\(%d\)\.csv$' %((time.strftime('%Y%m%d'), pttp_id, len(list_blacklist_devices)))
    assert(re.search(filename_re, filename) is not None), 'Wrong filename with devices in blacklist'
    with open(path_to_exported_file) as file:
        number_line_in_file = 0
        for line in file:
            if number_line_in_file == 0:
                assert(line.rstrip() == 'Version 1.0'), 'Wrong version in file with blacklisted devices'
                number_line_in_file += 1
                continue
            expected_line = '%02X%08X;%s;' % (pttp_id, blacklist_devices[number_line_in_file-1][0],blacklist_devices[number_line_in_file-1][1])
            assert(line.rstrip() == expected_line), 'Wrong line number=%d in file with blacklisted_devices:expected - %s, in file - %s' % ((number_line_in_file+1), expected_line, line)
            log('Checking line %s SUCCESS' % line.rstrip())
            number_line_in_file += 1
        assert(number_line_in_file - 1 == len(blacklist_devices)), 'Wrong number lines in file with blacklisted devices: in DB - %s, in file - %s' % (len(blacklist_devices), number_line_in_file-1)
    log('=====check_devices_in_blacklist SUCCESS=====')


def check_current_device_statuses(sqlalchemy_con, pttp_id, start_devc, end_devc, path_to_exported_file):
    list_devices = list(range(start_devc,end_devc+1))
    query = sqlalchemy_con.session.query(Device.devc_num, DeviceStatus.dvst_name, Device.is_committed, Device.is_backed_up, Device.is_blacklisted, Operator.oper_name,StbModel.stbm_name, StbDevice.serial_number,BlackBox.blbx_name, Device.ins_date)
    query= query.join(DeviceStatus, Device.dvst_dvst_id==DeviceStatus.dvst_id)
    query = query.outerjoin(StbDevice, Device.stbd_stbd_id==StbDevice.stbd_id)
    query = query.outerjoin(Operator,Device.oper_oper_id == Operator.oper_id)
    query = query.outerjoin(BlackBox ,Device.blbx_blbx_id == BlackBox.blbx_id)
    query = query.outerjoin(StbModel, StbDevice.stbm_stbm_id==StbModel.stbm_id)
    query = query.filter(Device.pttp_pttp_id == pttp_id, Device.devc_num.in_(list_devices)).order_by(Device.devc_num)
    devices = query.all()

    filename_re = '^%sT[0-2][0-9][0-5][0-9]_PTID-%08X_current_statuses_\(%d\)\.csv$' % (
        (time.strftime('%Y%m%d'), pttp_id, len(devices)))
    filename = path_to_exported_file.split('/')[-1]
    assert (re.search(filename_re, filename) is not None), 'Wrong filename with current_device_statuses: expected %s, in actual %s' %(filename_re, filename)
    with open(path_to_exported_file) as file:
        number_line_in_file = 0
        i = 0
        for line in file:
            if number_line_in_file == 0:
                assert(line.rstrip() == 'Version 1.0'), 'Wrong version in file with current_device_statuses'
                number_line_in_file += 1
                continue
            if number_line_in_file == 1:
                assert(line.rstrip() == 'PartTypeID;DeviceNumber;DeviceStatus;IsCommitted;IsBackedUp;IsBlacklisted;Operator;STB Model;STB S/N;Blackbox;DateTime;'), 'Wrong second line in file with current_device_statuses'
                number_line_in_file+=1
                continue
            device = devices[i]
            date_re ='%s%s%sT[0-2][0-9]%s' % (device[9].year, str(device[9].month).rjust(2,'0'),
                                              str(device[9].day).rjust(2, '0'), str(device[9].minute).rjust(2,'0'))
            expected_line_re = '^%08X;%08X;%s;%d;%d;%d;%s;%s;%s;%s;%s;$' % (
                pttp_id,device[0],device[1],device[2],device[3],device[4],device[5] if device[5] else '',
                device[6] if device[6] else '',device[7] if device[7] else '',device[8] if device[8] else '', date_re)
            #log('expected_line: %s' % expected_line_re)
            assert(re.search(expected_line_re,line.rstrip()) is not None), 'Error in line: %s, expected: %s' % (line, expected_line_re)
            i+=1
            number_line_in_file+=1
        assert(number_line_in_file == len(devices)+2), 'Wrong number line in file for current_device_statuses'
    log('=====check_current_device_statuses SUCCESS=====')


def check_device_status_report_v2(sqlalchemy_con, pttp_id, kmi_report_items, start_dev, end_dev, too_long=False):
    report_items = []
    for status in range(1,8):
        report_item = []
        devices = [item[0] for item in sqlalchemy_con.session.query(Device.devc_num).filter(Device.dvst_dvst_id == status, Device.pttp_pttp_id == pttp_id, Device.devc_num >= start_dev, Device.devc_num <= end_dev).order_by(Device.devc_num).all()]
        tot_amount = len(devices)
        ranges = get_int_ranges_from_list(devices)
        report_item.append(sqlalchemy_con.session.query(DeviceStatus.dvst_name).filter(DeviceStatus.dvst_id == status).one()[0])
        report_item.append(tot_amount)
        report_item.append(ranges)
        if tot_amount:
            report_items.append(report_item)
    assert (len(report_items) == len(kmi_report_items)), 'Wrong number different statuses in report V2'
    if too_long is True:
        count = 0
        for item1 in kmi_report_items:
            for item2 in report_items:
                if (item1.deviceStatusName == item2[0] and item1.totalAmount == item2[1] and item1.rangeStr == 'Too long'):
                    count+=1
                    log('For status %s ranges: %s' % (item1.deviceStatusName, item1.rangeStr))
                    break
        assert (count == len(kmi_report_items)),'No "Too long" in report'
        return 1
    for item1 in kmi_report_items:
        i = 0
        for item2 in report_items:
            i += 1
            if (item1.deviceStatusName == item2[0] and item1.totalAmount == item2[1] and item1.rangeStr == item2[2]):
                log('For status %s ranges: %s' % (item1.deviceStatusName, item1.rangeStr))
                break
            assert(i != len(kmi_report_items)), 'Error with status %s' % item1.deviceStatusName
    log('=====check_device_status_report_v2 SUCCESS=====')


def check_devices_history(sqlalchemy_con, pttp_id, list_devices, out_path):
    print list_devices
    query = sqlalchemy_con.session.query(DeviceHistory.devc_num, DeviceHistory.dvst_dvst_id, DeviceHistory.is_committed, DeviceHistory.is_backed_up, DeviceHistory.is_blacklisted, Operator.oper_name, StbModel.stbm_name, StbDevice.serial_number, BlackBox.blbx_name, Batch.btch_name, DeviceHistory.ins_date)
    query = query.join(Batch, DeviceHistory.btch_btch_id == Batch.btch_id)
    query = query.outerjoin(StbDevice, DeviceHistory.stbd_stbd_id == StbDevice.stbd_id)
    query = query.outerjoin(Operator, DeviceHistory.oper_oper_id == Operator.oper_id)
    query = query.outerjoin(BlackBox, DeviceHistory.blbx_blbx_id == BlackBox.blbx_id)
    query = query.outerjoin(StbModel, StbDevice.stbm_stbm_id == StbModel.stbm_id)
    query = query.filter(DeviceHistory.pttp_pttp_id == pttp_id, DeviceHistory.devc_num.in_(list_devices)).order_by(DeviceHistory.devc_num)
    devices = query.all()
    devices = sorted(devices, key=lambda x: (int(x[0]), int(x[1])))
    devices_sort = []
    uniq_devc_num = []
    for device in devices:
        device = list(device)
        dvst_id = device[1]
        devc_num = device[0]
        if devc_num not in uniq_devc_num:
            uniq_devc_num.append(devc_num)
        device[1] = sqlalchemy_con.session.query(DeviceStatus.dvst_name).filter(DeviceStatus.dvst_id == dvst_id).one()[0]
        devices_sort.append(device)
    filename_re = '^%sT[0-2][0-9][0-5][0-9]_%02X%08X_devices_history_\(%d\)\.csv$' % (
        (time.strftime('%Y%m%d'), pttp_id, devices_sort[0][0], len(uniq_devc_num)))
    filename = out_path.split('/')[-1]
    assert (re.search(filename_re,
                      filename) is not None), 'Wrong filename with device_histories: expected %s, in actual %s' % (
    filename_re, filename)
    with open(out_path) as file:
        number_line_in_file = 0
        i = 0
        for line in file:
            if number_line_in_file == 0:
                assert (line.rstrip() == 'Version 1.0'), 'Wrong version in file with device_histories'
                number_line_in_file += 1
                continue
            if number_line_in_file == 1:
                assert (line.rstrip() == 'PartTypeID;DeviceNumber;DeviceStatus;IsCommitted;IsBackedUp;IsBlacklisted;Operator;STB Model;STB S/N;Blackbox;Batch;DateTime;'), 'Wrong second line in file with device_histories'
                number_line_in_file += 1
                continue
            device = devices_sort[i]
            date_re = '%s%s%sT[0-2][0-9]%s' % (device[10].year, str(device[10].month).rjust(2, '0'),
                                               str(device[10].day).rjust(2, '0'), str(device[10].minute).rjust(2, '0'))
            expected_line_re = '^%08X;%08X;%s;%d;%d;%d;%s;%s;%s;%s;%s;%s;$' % (
                pttp_id, device[0], device[1], device[2], device[3], device[4], device[5] if device[5] else '',
                device[6] if device[6] else '', device[7] if device[7] else '', device[8] if device[8] else '', device[9], date_re)
            #log('expected_line: %s' % expected_line_re)
            assert (re.search(expected_line_re, line.rstrip()) is not None), 'Error in line: %s, expected: %s' % (
            line, expected_line_re)
            i += 1
            number_line_in_file += 1
        assert (number_line_in_file == len(devices_sort) + 2), 'Wrong number line in file for current_device_statuses'
    log('=====check_current_device_statuses SUCCESS=====')


def generate_programming_report(pttp_id, start_devc, end_devc, report_name, fw):
    full_path = os.path.join(get_homedir_in(), report_name)
    expected_statuses = ['OK', 'NOK', '03', '04']
    with open(full_path,'w') as f:
        f.write('Version 1.0\n')
        pttp = '%08X'%pttp_id
        for devc in range(start_devc, end_devc+1):
            if fw is None:
                line = '%s;%08x;%s;%s\n' % (pttp, devc, random.choice(expected_statuses), time.strftime('%Y-%m-%d %H:%M:%S'))
            else:
                line = '%s;%08x;%s;%s;%s\n' % (pttp, devc, random.choice(expected_statuses), time.strftime('%Y-%m-%d %H:%M:%S'), fw)
            f.write(line)
    return full_path

def generate_prorgaming_report_all_ok(pttp_id, start_devc, end_devc, report_name, fw):
    full_path = os.path.join(get_homedir_in(), report_name)
    expected_statuses=['OK', '03']
    with open(full_path,'w') as f:
        f.write('Version 1.0\n')
        pttp = '%08X'%pttp_id
        for devc in range(start_devc, end_devc+1):
            if fw is None:
                line = '%s;%08x;%s;%s\n' % (pttp, devc, random.choice(expected_statuses), time.strftime('%Y-%m-%d %H:%M:%S'))
            else:
                line = '%s;%08x;%s;%s;%s\n' % (pttp, devc, random.choice(expected_statuses), time.strftime('%Y-%m-%d %H:%M:%S'), fw)
            f.write(line)
    return full_path

def generate_manufacturing_report(db,pttp_id,start_devc,end_devc,report_name,second_pttp,co_processor):
    stb_id = random.choice(db.session.query(StbmodelParttype.stbm_stbm_id).filter(StbmodelParttype.pttp_pttp_id == pttp_id, StbmodelParttype.del_date == None).all())[0]
    stbm_name = db.session.query(StbModel.stbm_name).filter(StbModel.del_date == None, StbModel.stbm_id == stb_id).one()[0]
    mnfct_id = random.choice(db.session.query(StbModel.mfct_mfct_id).filter(StbModel.stbm_name == stbm_name).all())[0]
    manufacturer = db.session.query(Manufacturer.mfct_name).filter(Manufacturer.mfct_id == mnfct_id).one()[0]
    operator = random.choice(db.session.query(Operator.oper_name).filter(Operator.del_date == None).all()[0])
    full_path = os.path.join(get_homedir_in(), report_name)
    expected_statuses=['OK', 'NOK']
    with open(full_path,'w') as f:
        f.write('Version 1.0\n')
        if co_processor == None:
            f.write('Manufacturer;Operator;Hardware model;Manuf S/N;CAS STB ID;Lockdown status (OK / NOK)\n')
        else:
            f.write('Manufacturer;Operator;Hardware model;Manuf S/N;CAS STB ID;CAS Co-Processor ID;Lockdown status (OK / NOK)\n')
        for devc in range(start_devc, end_devc+1):
            stb_id = '%02X%08X' % (pttp_id, devc)
            cs = '%03d%08d' % (second_pttp, devc)
            if co_processor is None:
                line = '%s;%s;%s;%s;%s;%s\n' % (manufacturer, operator, stbm_name, "%0.13d" % random.randint(0,9999999999999), stb_id, random.choice(expected_statuses))
            elif co_processor == "co_proc_8":
                co_proc = '%02X%06X' % (second_pttp, devc)
                line = '%s;%s;%s;%s;%s;%s;%s\n' % (manufacturer, operator, stbm_name, "%0.13d" % random.randint(0,9999999999999), stb_id, co_proc, random.choice(expected_statuses))
            elif co_processor == "co_proc_13":
                number = 0
                for item in cs:
                    number += int(item)
                co_proc = '%02d%s' % (number % 100, cs)
                line = '%s;%s;%s;%s;%s;%s;%s\n' % (manufacturer, operator, stbm_name, "%0.13d" % random.randint(0, 9999999999999), stb_id, co_proc, random.choice(expected_statuses))
            f.write(line)
    return full_path

def generate_wrong_manufacturing_report(db,pttp_id,start_devc,end_devc,report_name,second_pttp,co_processor, version, secondstring, laststring):
    stb_id = random.choice(db.session.query(StbmodelParttype.stbm_stbm_id).filter(StbmodelParttype.pttp_pttp_id == pttp_id, StbmodelParttype.del_date == None).all())[0]
    stbm_name = db.session.query(StbModel.stbm_name).filter(StbModel.del_date == None, StbModel.stbm_id == stb_id).one()[0]
    mnfct_id = random.choice(db.session.query(StbModel.mfct_mfct_id).filter(StbModel.stbm_name == stbm_name).all())[0]
    manufacturer = db.session.query(Manufacturer.mfct_name).filter(Manufacturer.mfct_id == mnfct_id).one()[0]
    operator = random.choice(db.session.query(Operator.oper_name).filter(Operator.del_date == None).all()[0])
    full_path = os.path.join(get_homedir_in(), report_name)
    expected_statuses=['OK', 'NOK']
    with open(full_path,'w') as f:
        if version == 1:
            f.write('Version 1.0\n')
        else:
            f.write('Version 2.0\n')

        if co_processor == None:
            if secondstring == 0:
                pass
            else:
                f.write('Manufacturer;Operator;Hardware model;Manuf S/N;CAS STB ID;Lockdown status (OK / NOK)\n')
        else:
            if secondstring == 0:
                pass
            else:
                f.write('Manufacturer;Operator;Hardware model;Manuf S/N;CAS STB ID;CAS Co-Processor ID;Lockdown status (OK / NOK)\n')
        for devc in range(start_devc, end_devc+1):
            stb_id = '%02X%08X' % (pttp_id, devc)
            cs = '%03d%08d' % (second_pttp, devc)
            if co_processor is None:
                line = '%s;%s;%s;%s;%s;%s\n' % (manufacturer, operator, stbm_name, "%0.13d" % random.randint(0,9999999999999), stb_id, random.choice(expected_statuses))
            elif co_processor == "co_proc_8":
                co_proc = '%02X%06X' % (second_pttp, devc)
                line = '%s;%s;%s;%s;%s;%s;%s\n' % (manufacturer, operator, stbm_name, "%0.13d" % random.randint(0,9999999999999), stb_id, co_proc, random.choice(expected_statuses))
            elif co_processor == "co_proc_13":
                number = 0
                for item in cs:
                    number += int(item)
                co_proc = '%02d%s' % (number % 100, cs)
                line = '%s;%s;%s;%s;%s;%s;%s\n' % (manufacturer, operator, stbm_name, "%0.13d" % random.randint(0, 9999999999999), stb_id, co_proc, random.choice(expected_statuses))
            if laststring == 0:
                pass
            else:
                f.write(line)
    return full_path

def genereta_internal_manufacturing_report(db, pttp_id, stb_id, manuf_id, start_devc, end_devc, report_name):
    parttype_id = '%08X'%pttp_id
    copttp_id = '%08X'%0
    codevice_num = '%08X'%0
    manuf_statuses=['05', '06']
    oper_id ='%08X' % random.choice(db.session.query(Operator.oper_id).filter(Operator.del_date == None).all())[0]
    manf_id = '%08X' % manuf_id
    full_path = os.path.join(get_homedir_in(), report_name)
    with open(full_path, 'w') as f:
        for devc in range(start_devc, end_devc + 1):
            codev_num = '%08X'%devc
            line = '%s;%s;%s;%s;%s;%s;%s;%s;%s;\n' % (parttype_id, codev_num, copttp_id, codevice_num, random.choice(manuf_statuses), oper_id, manf_id, '%08X' % stb_id, ''.join([random.choice(list('1234567890')) for x in range(13)]))
            f.write(line)
    return full_path

def check_statuses_after_programming_import(db, pttp_id, start_devc, end_devc, report_name, not_exported):
    full_path = os.path.join(get_homedir_in(), report_name)
    devices = db.session.query(Device.devc_num, Device.dvst_dvst_id).filter(Device.pttp_pttp_id==pttp_id, Device.devc_num>=start_devc, Device.devc_num<=end_devc).all()
    dict_devices = {}
    for device in devices:
        dict_devices[device[0]] = device[1]
    with open(full_path) as file:
        number_devices_in_file=0
        assert(file.readline().strip()=='Version 1.0'), 'Wrong first line in file'
        list_not_exported = not_exported.keys() if not_exported else []
        for line in file:
            number_devices_in_file += 1
            dvc_num = int(line.split(';')[1], 16)
            dvc_st = line.split(';')[2]
            dvc_st_num = 3 if dvc_st=='OK' or dvc_st=='03' else 4
            if dvc_num not in list_not_exported:
                assert(dict_devices[dvc_num]==dvc_st_num), 'Wrong status for device %s in pttp %s' % (dvc_num, pttp_id)
            else:
                dict_devices[dvc_num] == not_exported[dvc_num]
    return 1

def pipe_check_statuses_after_manufacturing_report(sqlalchemy_con, pttp_id, report_name, co_proc, second_pttp):
    full_path = os.path.join(get_homedir_in(), report_name)
    stb_id = sqlalchemy_con.session.query(StbmodelParttype.stbm_stbm_id).filter(StbmodelParttype.pttp_pttp_id == pttp_id, StbmodelParttype.del_date == None).one()[0]
    stb_model = sqlalchemy_con.session.query(StbModel.stbm_name).filter(StbModel.stbm_id == stb_id, StbModel.del_date == None).one()[0]
    manuf_id = sqlalchemy_con.session.query(StbModel.mfct_mfct_id).filter(StbModel.stbm_id == stb_id, StbModel.del_date == None).one()[0]
    manuf_name = sqlalchemy_con.session.query(Manufacturer.mfct_name).filter(Manufacturer.mfct_id == manuf_id, Manufacturer.del_date == None).one()[0]
    oper_id = sqlalchemy_con.session.query(Device.oper_oper_id).order_by(asc(Device.devc_num))\
        .filter(Device.pttp_pttp_id == pttp_id, Device.stbd_stbd_id != None).all()[0][0]
    oper_name = sqlalchemy_con.session.query(Operator.oper_name).filter(Operator.oper_id == oper_id, Operator.del_date == None).one()[0]
    dvst = sqlalchemy_con.session.query(Device.dvst_dvst_id).order_by(asc(Device.devc_num)).filter(Device.pttp_pttp_id == pttp_id).all()
    if co_proc is None:
        assert (check_status(full_path, stb_model, manuf_name, oper_name, dvst) == 1)
    else:
        second_dvst = sqlalchemy_con.session.query(Device.dvst_dvst_id).order_by(asc(Device.devc_num)).filter(Device.pttp_pttp_id == second_pttp).all()
        assert (check_status(full_path, stb_model, manuf_name, oper_name, dvst, second_dvst, co_proc) == 1)


    return 1

def check_status(full_path, stb_model, manuf_name, oper_name, dvst, second_dvst=None, co_proc=None):
    count = 0
    with open(full_path) as file:
        assert (file.readline().strip() == 'Version 1.0'), 'Wrong first line in file'
        if co_proc is not None:
            assert (file.readline().strip() == 'Manufacturer;Operator;Hardware model;Manuf S/N;CAS STB ID;CAS Co-Processor ID;Lockdown status (OK / NOK)'), 'Wrong second line in file, check file format!!!'
        else:
            assert (file.readline().strip() == 'Manufacturer;Operator;Hardware model;Manuf S/N;CAS STB ID;Lockdown status (OK / NOK)'), 'Wrong second line in file, check file format!!!'
        for line in file:
            assert(line.split(';')[2] == stb_model), 'Wrong stb model in file'
            assert(line.split(';')[0] == manuf_name), 'Wrong manuf name in db'
            assert(line.split(';')[1] == oper_name),  'Wrong operator name in db'
            if co_proc is not None:
                if line.split(';')[6].strip() == "OK":
                    assert(dvst[count][0] == 5), 'Wrong dvst in db'
                    assert(second_dvst[count][0] == 5), 'Wrong second_dvst in db'
                elif line.split(';')[6].strip() == "NOK":
                    assert(dvst[count][0] == 6), 'Wrong dvst in db'
                    assert(second_dvst[count][0] == 6), 'Wrong second_dvst in db'
            else:
                if line.split(';')[5].strip() == "OK":
                    assert(dvst[count][0] == 5), 'Wrong dvst in db'
                elif line.split(';')[5].strip() == "NOK":
                    assert(dvst[count][0] == 6), 'Wrong dvst in db'
            count += 1
    return 1

def check_statuses_after_manufacturing_report(sqlalchemy_con, btch_name, pttp_id, report_name, start_devc, end_devc):
    full_path = os.path.join(get_homedir_in(), report_name)
    btch_id = sqlalchemy_con.session.query(Batch.btch_id).filter(Batch.btch_name == btch_name, Batch.del_date == None).one()[0]
    devices_history = sqlalchemy_con.session.query(DeviceHistory.devc_num, DeviceHistory.dvst_dvst_id, DeviceHistory.oper_oper_id)\
        .order_by(asc(DeviceHistory.devc_num))\
        .filter(DeviceHistory.pttp_pttp_id == pttp_id, DeviceHistory.btch_btch_id == btch_id, DeviceHistory.stbd_stbd_id != None).all()
    if start_devc is not None and end_devc is not None:
        devises = sqlalchemy_con.session.query(Device.devc_num, Device.dvst_dvst_id, Device.oper_oper_id)\
            .order_by(asc(Device.devc_num))\
            .filter(Device.pttp_pttp_id == pttp_id, Device.stbd_stbd_id != None, Device.devc_num >= start_devc, Device.devc_num <= end_devc).all()
    else:
        devises = sqlalchemy_con.session.query(Device.devc_num, Device.dvst_dvst_id, Device.oper_oper_id) \
            .order_by(asc(Device.devc_num)) \
            .filter(Device.pttp_pttp_id == pttp_id, Device.stbd_stbd_id != None).all()
    dev_in_db = 0
    if len(devices_history) != len(devises):
        log('the lists are not equal')
    elif len(devises) == 0 or len(devices_history) == 0:
        return 0
    with open(full_path) as file:
        for line in file:
            dvc_num = int(line.split(';')[1], 16)
            dvc_st = int(line.split(';')[4], 16)
            operator_id = int(line.split(';')[5], 16)
            assert(devices_history[dev_in_db][0] == dvc_num), 'Wrong status for devc_num in db table kmi_devises_history'
            assert(devices_history[dev_in_db][1] == dvc_st), 'Wrong status dvst_dvst_id in db table kmi_devises_history'
            assert(devices_history[dev_in_db][2] == operator_id), 'Wrong oper_id in db table kmi_devises_history'
            assert(devises[dev_in_db][0] == dvc_num), 'Wrong status for devc_num in db table kmi_devises'
            assert(devises[dev_in_db][1] == dvc_st), 'Wrong status dvst_dvst_id in db table kmi_devises'
            assert(devises[dev_in_db][2] == operator_id), 'Wrong oper_id in db table kmi_devises'
            dev_in_db += 1
    return 1

def get_not_exported_devices(db, pttp_id):
    dict={}
    devices = db.session.query(Device.devc_num, Device.dvst_dvst_id).filter(Device.pttp_pttp_id==pttp_id, Device.dvst_dvst_id!=2).all()
    for item in devices:
        dict[item[0]] = item[1]
    return dict

