# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

import sys

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    # my_string_setting = StringSetting()
    # my_number_setting = NumberSetting(min_value=0, max_value=127)
    pcf8583_addr_string = ChoicesSetting(label="PCF8583 Address", choices=('0x50', '0x51'))
    pcf8583_addr = 0x50
    
    weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Unknown']

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        },
        'indexReg': {
            'format': 'Set IndexReg={{data.register}}'
        },
        'data': {
            'format': 'R={{data.register}}, D={{data.value}}'
        },
        'hour': {
            'format': 'hour={{data.value}}{{data.ampm}}'
        },
        'minute': {
            'format': 'minute={{data.value}}'
        },
        'second': {
            'format': 'seconds={{data.value}}'
        },
        'msecond': {
            'format': 'mseconds={{data.value}}'
        },
        'time': {
            'format': '{{data.hour}}:{{data.minute}}:{{data.second}}{{data.ampm}}'
        },
        'yearday': {
            'format': 'Year={{data.year}}, Day={{data.day}}'
        },
        'weekdaymonth': {
            'format': 'Weekday={{data.weekday}}, Month={{data.month}}'
        },
        'date': {
            'format': '{{data.year}}-{{data.month}}-{{data.day}} ({{data.weekday}})'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        with open("/tmp/pcf.log", "a+") as f:
            # f.write(f'Settings: {self.my_string_setting}');
            f.write(f'Choice={self.pcf8583_addr_string}, Addr = {self.pcf8583_addr}\n')

        if self.pcf8583_addr_string == '0x51':
            self.pcf8583_addr = 0x51

        self.last_address = 0
        # What register address we use currently
        self.register_addr = 0
        # if the last frame was a write to the I2C address of the PCF
        # Next data is register index
        self.last_was_index_write = False

        self.second=0
        self.minute=0
        self.hour=0
        self.year=0
        self.month=0
        self.day=0
        self.time_start_time=None
        self.date_start_time=None

    # def dump(obj):
    #     with open("/tmp/pcf.log", "a+") as f:
    #         for attr in dir(obj):
    #             f.write(f"obj.{attr} = {getattr(obj, attr)}")

    def __bcd_to_int(self, b):
        return (b>>4)*10+(b&0x0f)
    def __frame_data_to_int(self, f):
        return self.__bcd_to_int(int.from_bytes(f.data['data'], byteorder='little'))

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        # print(frame);
        # dump(frame)

        with open("/tmp/pcf.log", "a+") as f:
            f.write(f"addr={self.pcf8583_addr}, last_address={self.last_address}\n")
            for attr in dir(frame):
                f.write(f"frame.{attr} = {getattr(frame, attr)}\n")

        if frame.type == 'address':
            self.last_address = int.from_bytes(frame.data['address'], byteorder='little')
            if self.last_address == self.pcf8583_addr and not frame.data['read']:
                self.last_was_index_write = True
                self.register_addr = 0
            return
            # return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
            #     'input_type': frame.type
            # })

        if self.last_address == self.pcf8583_addr:
            if frame.type == 'data':
                if self.last_was_index_write:
                    self.register_addr = int.from_bytes(frame.data['data'], byteorder='little')
                    self.last_was_index_write = False
                    return AnalyzerFrame('indexReg', frame.start_time, frame.end_time, {
                        'register': self.register_addr
                    })
                else:
                    self.register_addr = self.register_addr+1
                    if self.register_addr-1 == 1:
                        return AnalyzerFrame('msecond', frame.start_time, frame.end_time, {
                            'value': self.__frame_data_to_int(frame)*10
                        })
                    if self.register_addr-1 == 2:
                        self.second=self.__bcd_to_int(int.from_bytes(frame.data['data'], byteorder='little'))
                        self.time_start_time = frame.start_time
                        return AnalyzerFrame('second', frame.start_time, frame.end_time, {
                            'value': self.__bcd_to_int(int.from_bytes(frame.data['data'], byteorder='little'))
                        })
                    if self.register_addr-1 == 3:
                        self.minute=self.__bcd_to_int(int.from_bytes(frame.data['data'], byteorder='little'))
                        return AnalyzerFrame('minute', frame.start_time, frame.end_time, {
                            'value': self.__bcd_to_int(int.from_bytes(frame.data['data'], byteorder='little'))
                        })
                    # Here comes the hour, try to combine with seconds and minutes we
                    # probably got earlier
                    if self.register_addr-1 == 4:
                        d = int.from_bytes(frame.data['data'], byteorder='little')
                        self.hour = self.__bcd_to_int(d & 0x3f)
                        if d & 0x80:
                            if d & 0x40:
                                ampm='pm'
                            else:
                                ampm='am'
                        else:
                            ampm=''
                        if self.time_start_time:
                            return AnalyzerFrame('time', self.time_start_time, frame.end_time, {
                                'second': self.second,
                                'minute': self.minute,
                                'hour': self.hour,
                                'ampm': ampm
                            })
                        else:
                            return AnalyzerFrame('hour', frame.start_time, frame.end_time, {
                                'value': self.hour,
                                'ampm': ampm
                            })

                    # Year+Date
                    if self.register_addr-1 == 5:
                        self.date_start_time = frame.start_time
                        d = int.from_bytes(frame.data['data'], byteorder='little')
                        self.year = 2020 + (d>>6)
                        self.day = self.__bcd_to_int(d & 0x3f)
                        return AnalyzerFrame('yearday', frame.start_time, frame.end_time, {
                            'year': self.year,
                            'day': self.day
                        })
                    # Weekday+Month
                    # Try to combine with Year+Date data
                    if self.register_addr-1 == 6:
                        d=int.from_bytes(frame.data['data'], byteorder='little')
                        self.month = self.__bcd_to_int(d & 0x1f)
                        self.weekday = self.weekdays[d>>5]
                        if self.date_start_time:
                            return AnalyzerFrame('date', self.date_start_time, frame.end_time, {
                                'year': self.year,
                                'month': self.month,
                                'day': self.day,
                                'weekday': self.weekday
                            })
                        return AnalyzerFrame('weekdaymonth', frame.start_time, frame.end_time, {
                            'month': self.month,
                            'weekday': self.weekday
                        })

                # Anything else we don't recognize
                return AnalyzerFrame('data', frame.start_time, frame.end_time, {
                    'register': self.register_addr-1,
                    'value': hex(int.from_bytes(frame.data['data'], byteorder='little'))
                })

        # Return the data frame itself
        return
        # return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
        #     'input_type': frame.type
        # })
