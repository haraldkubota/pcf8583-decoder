# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # my_string_setting = StringSetting()
    # my_number_setting = NumberSetting(min_value=0, max_value=127)
    pcf8583_addr_string = ChoicesSetting(label="PCF8583 Address",
                                         choices=('0x50', '0x51'))
    pcf8583_addr = 0x50

    weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Unknown']

    result_types = {
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
            'format':
            '{{data.hour}}:{{data.minute}}:{{data.second}}{{data.ampm}}'
        },
        'yearday': {
            'format': 'Year={{data.year}}, Day={{data.day}}'
        },
        'weekdaymonth': {
            'format': 'Weekday={{data.weekday}}, Month={{data.month}}'
        },
        'date': {
            'format':
            '{{data.year}}-{{data.month}}-{{data.day}} ({{data.weekday}})'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        if self.pcf8583_addr_string == '0x51':
            self.pcf8583_addr = 0x51

        self.last_address = 0
        # What register address we use currently
        self.register_addr = 0
        # if the last frame was a write to the I2C address of the PCF
        # Next data is register index
        self.last_was_index_write = False

        self.second = 0
        self.minute = 0
        self.hour = 0
        self.year = 0
        self.month = 0
        self.day = 0
        self.time_start_time = None
        self.date_start_time = None

    def __bcd_to_int(self, b):
        return (b >> 4) * 10 + (b & 0x0f)

    def __frame_data_to_int(self, f):
        return self.__bcd_to_int(
            int.from_bytes(f.data['data'], byteorder='little'))

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'address':
            self.last_address = int.from_bytes(frame.data['address'],
                                               byteorder='little')
            if self.last_address == self.pcf8583_addr and not frame.data[
                    'read']:
                self.last_was_index_write = True
                self.register_addr = 0
            return

        if self.last_address == self.pcf8583_addr:
            if frame.type == 'data':
                if self.last_was_index_write:
                    self.register_addr = int.from_bytes(frame.data['data'],
                                                        byteorder='little')
                    self.last_was_index_write = False
                    return AnalyzerFrame('indexReg', frame.start_time,
                                         frame.end_time,
                                         {'register': self.register_addr})
                else:
                    self.register_addr = self.register_addr + 1
                    if self.register_addr - 1 == 1:
                        return AnalyzerFrame(
                            'msecond', frame.start_time, frame.end_time,
                            {'value': self.__frame_data_to_int(frame) * 10})
                    if self.register_addr - 1 == 2:
                        self.second = self.__bcd_to_int(
                            int.from_bytes(frame.data['data'],
                                           byteorder='little'))
                        self.time_start_time = frame.start_time
                        return AnalyzerFrame(
                            'second', frame.start_time, frame.end_time, {
                                'value':
                                self.__bcd_to_int(
                                    int.from_bytes(frame.data['data'],
                                                   byteorder='little'))
                            })
                    if self.register_addr - 1 == 3:
                        self.minute = self.__bcd_to_int(
                            int.from_bytes(frame.data['data'],
                                           byteorder='little'))
                        return AnalyzerFrame(
                            'minute', frame.start_time, frame.end_time, {
                                'value':
                                self.__bcd_to_int(
                                    int.from_bytes(frame.data['data'],
                                                   byteorder='little'))
                            })
                    # Here comes the hour, try to combine with seconds and minutes we
                    # probably got earlier
                    if self.register_addr - 1 == 4:
                        d = int.from_bytes(frame.data['data'],
                                           byteorder='little')
                        self.hour = self.__bcd_to_int(d & 0x3f)
                        if d & 0x80:
                            if d & 0x40:
                                ampm = 'pm'
                            else:
                                ampm = 'am'
                        else:
                            ampm = ''
                        if self.time_start_time:
                            return AnalyzerFrame(
                                'time', self.time_start_time, frame.end_time, {
                                    'second': str(self.second).zfill(2),
                                    'minute': str(self.minute).zfill(2),
                                    'hour': str(self.hour).zfill(2),
                                    'ampm': ampm
                                })
                        else:
                            return AnalyzerFrame('hour', frame.start_time,
                                                 frame.end_time, {
                                                     'value': self.hour,
                                                     'ampm': ampm
                                                 })

                    # Year+Date
                    if self.register_addr - 1 == 5:
                        self.date_start_time = frame.start_time
                        d = int.from_bytes(frame.data['data'],
                                           byteorder='little')
                        self.year = 2020 + (d >> 6)
                        self.day = self.__bcd_to_int(d & 0x3f)
                        return AnalyzerFrame('yearday', frame.start_time,
                                             frame.end_time, {
                                                 'year': self.year,
                                                 'day': self.day
                                             })
                    # Weekday+Month
                    # Try to combine with Year+Date data
                    if self.register_addr - 1 == 6:
                        d = int.from_bytes(frame.data['data'],
                                           byteorder='little')
                        self.month = self.__bcd_to_int(d & 0x1f)
                        self.weekday = self.weekdays[d >> 5]
                        if self.date_start_time:
                            return AnalyzerFrame(
                                'date', self.date_start_time, frame.end_time, {
                                    'year': self.year,
                                    'month': self.month,
                                    'day': self.day,
                                    'weekday': self.weekday
                                })
                        return AnalyzerFrame('weekdaymonth', frame.start_time,
                                             frame.end_time, {
                                                 'month': self.month,
                                                 'weekday': self.weekday
                                             })

                # Anything else we don't recognize
                return AnalyzerFrame(
                    'data', frame.start_time, frame.end_time, {
                        'register':
                        self.register_addr - 1,
                        'value':
                        hex(
                            int.from_bytes(frame.data['data'],
                                           byteorder='little'))
                    })

        return
