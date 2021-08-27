import re, subprocess, sys
import time

class Menu(object):

    title = ''

    def __init__(self):
        self.items = []
        self.default_value = ''


class Pipehelper(object):

    process = None

    #def __new__(cls):
    #    if not hasattr(cls, 'instance'):
    #        cls.instance = super(Pipehelper, cls).__new__(cls)
    #    return cls.instance


    def __init__(self, process):
        self.process = process
        self.process.pid += 1
        self.menu = Menu()
        self.parse_lines_from_stdout()
        print '__init__ PIPE Success'


    def __get_list_lines_from_proc(self):
        list_lines = []
        data = ''
        while True:
            data += self.process.stdout.read(1)
            if data == '> ':
                sys.stdout.write(data)
                break
            if data.endswith('\n') and data.strip():
                print data[:-1]
                list_lines.append(data[:-1])
                data = ''
            if 'Press Enter to continue...' in data:
                list_lines.append(data)
                break
        return list_lines

    def parse_lines_from_stdout(self):
        self.menu = Menu()
        lines = self.__get_list_lines_from_proc()
        it = lines.__iter__()
        count = 0
        while True:
            cur_line = it.next().strip()
            count += 1
            if cur_line == '':
                continue
            if re.search('\*\s+(\w+\s?)+\s+\*', cur_line):
                Menu.title = cur_line[1:-1].strip()
                continue
            if re.search('Working with OTP/Firmware keys', cur_line):
                Menu.title = cur_line[1:-1].strip()
                continue
            if cur_line.startswith('Choose') or cur_line.startswith('Enter') or cur_line.endswith('(y/n)'):
                try:
                    cur_line = it.next()
                except StopIteration as e:
                    self.menu.items.append(cur_line)
                    break
                operation_re = '\s+\d+\s+[-]\s+[a-zA-Z0-9_:]+'
                items_re = '(\w+\s*[|])+'
                cur_line_pos = lines.index(cur_line)
                heads = []
                operation_dict = {}
                for line in lines[cur_line_pos:]:
                    if re.search(operation_re, line) is not None:
                        items = line.split('-')
                        operation_dict[items[0].strip()] = items[1].strip().lower()
                    elif re.search(items_re, line) is not None:
                        if len(heads) == 0:
                            heads = [item.strip().lower() for item in line.split('|')[1:-1]]
                            continue
                        items = [item.strip().lower() for item in line.split('|')[1:-1]]
                        data_dict = {}
                        for item, head in zip(items, heads):
                            data_dict[head] = item
                        self.menu.items.append(data_dict)
                if len(operation_dict) > 0:
                    self.menu.items.append(operation_dict)
                break
            else:
                if count == len(lines):
                    self.menu.items = lines
                    break
        if 'default: ' in cur_line:
            self.menu.default_value = cur_line[cur_line.rfind('default: ') + 8:-1].strip()

    def send_to_pipe(self, data, signal=None):
        time.sleep(0.1)
        if signal is not None:
            self.process.send_signal(signal)
        else:
            self.process.stdin.write(str(data) + '\n')
        self.parse_lines_from_stdout()