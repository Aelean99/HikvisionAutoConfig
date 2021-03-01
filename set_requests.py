import json
import logging
import sys

import requests
import xmltodict
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

import get_requests
from textwrap import wrap

log = logging.getLogger("set_requests")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('[%(asctime)s %(filename)s:%(lineno)d] %(levelname)-8s %(message)s'))
log.addHandler(console_handler)


def to_json(response):
    xml_dict = xmltodict.parse(response.content)
    json_response = json.loads(json.dumps(xml_dict))
    return json_response


class SetRequests:
    def __init__(self, ip_address):
        self.base_address = f"http://{ip_address}/ISAPI/"
        self.basic_auth = HTTPBasicAuth("admin", "tvmix333")
        self.digest_auth = HTTPDigestAuth("admin", "tvmix333")
        self.session = requests.Session()
        self.get = get_requests.GetRequests(ip_address)

    def set_eth_config(self, dns=None):
        if dns is None:
            dns = ["217.24.176.230", "217.24.177.2"]

        current_eth_data = self.get.get_eth_config()
        if current_eth_data == 701:
            return 701
        addressing_type = current_eth_data['IPAddress']['addressingType']

        if addressing_type != "static":
            return f"Addressing type is {addressing_type}. Can`t set DNS"
        ip_address = current_eth_data['IPAddress']['ipAddress']
        subnet_mask = current_eth_data['IPAddress']['subnetMask']
        gateway = current_eth_data['IPAddress']['DefaultGateway']['ipAddress']

        xml_data = f'''<IPAddress>
                    <ipVersion>v4</ipVersion>
                    <addressingType>static</addressingType>
                    <ipAddress>{ip_address}</ipAddress>
                    <subnetMask>{subnet_mask}</subnetMask>
                    <DefaultGateway>
                        <ipAddress>{gateway}</ipAddress>
                    </DefaultGateway>
                    <PrimaryDNS>
                        <ipAddress>{dns[0]}</ipAddress>
                    </PrimaryDNS>
                    <SecondaryDNS>
                        <ipAddress>{dns[1]}</ipAddress>
                    </SecondaryDNS>
                    <Ipv6Mode>
                        <ipV6AddressingType>ra</ipV6AddressingType>
                        <ipv6AddressList>
                            <v6Address>
                                <id>1</id>
                                <type>manual</type>
                                <address>::</address>
                                <bitMask>0</bitMask>
                            </v6Address>
                        </ipv6AddressList>
                    </Ipv6Mode>
                </IPAddress>'''

        try:
            response = self.session.put(f"{self.base_address}System/Network/interfaces/1/ipAddress", data=xml_data,
                                        auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def set_stream_config(self, mic="false"):
        xml_data = f'''
            <StreamingChannel>
                <Video>
                    <videoCodecType>H.264</videoCodecType>
                    <videoResolutionWidth>1280</videoResolutionWidth>
                    <videoResolutionHeight>720</videoResolutionHeight>
                    <videoQualityControlType>VBR</videoQualityControlType>
                    <fixedQuality>100</fixedQuality>
                    <vbrUpperCap>1024</vbrUpperCap>
                    <maxFrameRate>1200</maxFrameRate>
                    <GovLength>20</GovLength>
                </Video>
                <Audio>
                    <enabled>{mic}</enabled>
                    <audioCompressionType>MP2L2</audioCompressionType>
                </Audio>
            </StreamingChannel>'''

        try:
            response = self.session.put(f"{self.base_address}Streaming/channels/101", data=xml_data,
                                        auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def set_email_config(self):
        device_info = self.get.device_info()
        if device_info is None:
            return "device_info is empty"
        serial_number = device_info['DeviceInfo']['serialNumber']
        cam_email = f"HK-{serial_number}@camera.ru"
        xml_data = f'''
                <mailing>
                    <id>1</id>
                    <sender>
                        <emailAddress>{cam_email}</emailAddress>
                        <name>camera</name>
                        <smtp>
                            <enableAuthorization>false</enableAuthorization>
                            <enableSSL>false</enableSSL>
                            <addressingFormatType>hostname</addressingFormatType>
                            <hostName>alarm.profintel.ru</hostName>
                            <portNo>15006</portNo>
                            <accountName></accountName>
                            <enableTLS>false</enableTLS>
                            <startTLS>false</startTLS>
                        </smtp>
                    </sender>
                    <receiverList>
                        <receiver>
                            <id>1</id>
                            <name>camera</name>
                            <emailAddress>{cam_email}</emailAddress>
                        </receiver>
                    </receiverList>
                    <attachment>
                        <snapshot>
                            <enabled>false</enabled>
                            <interval>2</interval>
                        </snapshot>
                    </attachment>
                </mailing>'''
        try:
            response = self.session.put(f"{self.base_address}System/Network/mailing/1", data=xml_data,
                                        auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def set_ntp_config(self):
        xml_data = '''
            <NTPServer>
                <id>1</id>
                <addressingFormatType>ipaddress</addressingFormatType>
                <ipAddress>217.24.176.232</ipAddress>
                <portNo>123</portNo>
                <synchronizeInterval>30</synchronizeInterval>
            </NTPServer>'''
        try:
            response = self.session.put(f"{self.base_address}System/time/NtpServers/1", data=xml_data,
                                        auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)


    def set_time_config(self, timezone=None):
        if timezone is None:
            timezone = "5"

        xml_data = f'''
            <Time>
                <timeMode>NTP</timeMode>
                <timeZone>CST-{timezone}:00:00</timeZone>
            </Time>
        '''

        try:
            response = self.session.put(f"{self.base_address}System/time", data=xml_data, auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def set_osd_channel_config(self):
        xml_data = '''
        <channelNameOverlay>
            <enabled>false</enabled>
            <positionX>512</positionX>
            <positionY>64</positionY>
        </channelNameOverlay>
        '''

        try:
            response = self.session.put(
                f"{self.base_address}System/Video/inputs/channels/1/overlays/channelNameOverlay",
                data=xml_data, auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def set_osd_datetime_config(self):
        xml_data = '''
        <DateTimeOverlay>
            <enabled>true</enabled>
            <positionX>0</positionX>
            <positionY>544</positionY>
            <dateStyle>DD-MM-YYYY</dateStyle>
            <timeStyle>24hour</timeStyle>
            <displayWeek>false</displayWeek>
        </DateTimeOverlay> 
        '''
        try:
            response = self.session.put(f"{self.base_address}System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                        data=xml_data, auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def set_alarm_notifications_config(self):
        xml_data = '''
        <EventTriggerNotificationList>
            <EventTriggerNotification>
                <id>email</id>
                <notificationMethod>email</notificationMethod>
                <notificationRecurrence>recurring</notificationRecurrence>
            </EventTriggerNotification>
        </EventTriggerNotificationList>
        '''

        try:
            response = self.session.put(f"{self.base_address}Event/triggers/VMD-1/notifications",
                                        data=xml_data, auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    # Настройка конфигурации детекции движения
    # Включается функционал отлова движения, заполняется маска детекции
    def set_detection_config(self):
        xml_data = '''
        <MotionDetection>
            <enabled>true</enabled>
            <enableHighlight>false</enableHighlight>
            <samplingInterval>2</samplingInterval>
            <startTriggerTime>500</startTriggerTime>
            <endTriggerTime>500</endTriggerTime>
            <regionType>grid</regionType>
            <Grid>
                <rowGranularity>18</rowGranularity>
                <columnGranularity>22</columnGranularity>
            </Grid>
            <MotionDetectionLayout>
                <sensitivityLevel>60</sensitivityLevel>
                <layout>
                    <gridMap>fffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffc</gridMap>
                </layout>
            </MotionDetectionLayout>
        </MotionDetection>
        '''

        try:
            response = self.session.put(f"{self.base_address}System/Video/inputs/channels/1/motionDetection",
                                        data=xml_data, auth=self.basic_auth, timeout=3)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    # Цель метода - сменить маску детекции на камере, когда клиент её поменял через ЛК
    # На вход должна поступить маска детекции в виде строки из 396 символов.
    # Знчение символа: либо 1 либо 0. Если 1 - значит ячейка в ЛК активирована, и её нужно отрисовать на камере
    def set_detection_mask(self, mask_from_lk=None):
        if mask_from_lk is None:
            mask_from_lk = \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111"

        # hex_values - это внутренние значения с камеры.
        # Grid маска внутри камеры представлена в виде 22 стобцов, и 18 строк
        # Каждая строка из 22 ячеек делится ещё по 4.
        # Из этих 4х ячеек вычислияется hex decimal(шестнадцатеричное значение)
        # Первая ячейка = 8, вторая = 4, третья = 2, четвертая = 1
        hex_values = [8, 4, 2, 1]
        grid_for_cam = []  # Маска для камеры, будет вычислена далее в коде

        try:
            array_22chars = wrap(mask_from_lk, 22)  # массив в ввиде ['1111111111111111111111']
            for sub_array in array_22chars:
                array_4chars = wrap(sub_array, 4)  # массив в виде ['1111', '1111', '1111', '1111', '1111', '11']
                for sub_array1 in array_4chars:  # '1111'
                    index = 0  # Для обращения по индексу
                    sum = 0  # Сумма hex_values, объявлена чтобы её можно было использовать в коде
                    for value in sub_array1:  # перебор значений в sub_array чтобы выяснить сумму
                        if int(value) == 1:
                            sum += hex_values[index]
                        else:
                            sum += 0
                        index += 1
                    grid_for_cam.append(hex(sum).split('x')[-1])  # Добавление hex значения в конец массива
                    sum = 0  # сбрасываем результат предыдущих вычислений

            final_grid = str.join("", grid_for_cam)
            xml_data = f'''
            <MotionDetectionGridLayout>
                <MotionDetectionLayout>
                    <sensitivityLevel>60</sensitivityLevel>
                    <gridMap>{final_grid}</gridMap>
                </MotionDetectionLayout>
            </MotionDetectionGridLayout>
            '''

            response = \
                self.session.put(f"{self.base_address}System/Video/inputs/channels/1/motionDetection/layout/gridLayout",
                                 data=xml_data, auth=self.basic_auth, timeout=5)
            json_response = to_json(response)
            print("test")
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)
