import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import json
import xmltodict


def to_json(response):
    xml_dict = xmltodict.parse(response.content)
    json_response = json.loads(json.dumps(xml_dict))
    return json_response


class Hikvision(Resource):
    def __init__(self):
        self.base_address = "http://10.195.17.92/ISAPI/"
        self.basic_auth = HTTPBasicAuth("admin", "tvmix333")
        self.digest_auth = HTTPDigestAuth("admin", "tvmix333")
        self.current_password = ""
        self.session = requests.Session()

    def user_check(self):
        with open(os.path.abspath('passwords.json'), "r") as passwords:
            password_list = json.load(passwords)

        for password in password_list['values']:
            try:
                response = self.session.get(f"{self.base_address}Security/userCheck",
                                            auth=HTTPBasicAuth("admin", password))
                if response.status_code == 200:
                    self.current_password = password
                    log.debug("Auth: Success")
                    return 200, "OK"
                elif response.status_code == 401:
                    log.debug("Auth: Unauthorized")
                elif response.status_code == 404:
                    log.debug("Auth: Device is not supported")
                    return 404, "Device is not supported"
                else:
                    log.debug("Default error")

            except requests.exceptions.RequestException as e:
                log.exception(e)
                raise e

    def change_password(self):
        xml_data = '''
        <User>
            <id>1</id>
            <userName>admin</userName>
            <password>tvmix333</password>
        </User>
        '''
        response = self.session.put(f"{self.base_address}Security/users/1", xml_data,
                                    auth=HTTPBasicAuth("admin", self.current_password))
        return response.status_code

    def get_cam_config(self):
        auth_status = self.user_check()
        if auth_status[0] == 200:
            if self.current_password != "tvmix333":
                self.change_password()
            big_cam_json = (
                get.get_time_config(),
                get.get_ntp_config(),
                get.get_stream_config(),
                get.get_email_config(),
                get.get_osd_datetime_config(),
                get.get_osd_channel_name_config(),
                get.get_detection_config(),
                get.get_event_notification_config()
            )
            log.debug(json.dumps(big_cam_json, indent=4))

    @staticmethod
    def set_cam_config():
        big_cam_json = (
            put.set_email_config(),
            put.set_ntp_config(),
            put.set_eth_config(),
            put.set_stream_config(),
            put.set_time_config(),
            put.set_osd_channel_config(),
            put.set_osd_datetime_config(),
            put.set_alarm_notifications_config(),
            put.set_detection_config()
        )
        print(json.dumps(big_cam_json, indent=4))


class GetRequests(Hikvision):
    def device_info(self):
        try:
            response = self.session.get(f"{self.base_address}System/deviceInfo", auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_eth_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Network/interfaces/1/ipAddress",
                                        auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_stream_config(self):
        try:
            response = self.session.get(f"{self.base_address}Streaming/channels/101", auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_time_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/time", auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_ntp_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/time/NtpServers/1", auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_email_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Network/mailing/1", auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_detection_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Video/inputs/channels/1/motionDetection",
                                        auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_wifi_list(self):
        try:
            response = self.session.get(f"{self.base_address}System/Network/interfaces/2/wireless/accessPointList",
                                        auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_osd_datetime_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                        auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_osd_channel_name_config(self):
        try:
            response = self.session.get(
                f"{self.base_address}System/Video/inputs/channels/1/overlays/channelNameOverlay",
                auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)

    def get_event_notification_config(self):
        try:
            response = self.session.get(f"{self.base_address}Event/triggers/VMD-1/notifications",
                                        auth=self.basic_auth)
            return to_json(response)
        except Exception as e:
            log.exception(e)


class SetRequests(Hikvision):
    def set_eth_config(self, dns=None):
        if dns is None:
            dns = ["217.24.176.230", "217.24.177.2"]
        current_eth_data = GetRequests().get_eth_config()
        if current_eth_data is None:
            raise
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
            response = requests.put(f"{self.base_address}System/Network/interfaces/1/ipAddress", data=xml_data,
                                    auth=self.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
            response = requests.put(f"{self.base_address}Streaming/channels/101", data=xml_data, auth=self.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

    def set_email_config(self):
        device_info = GetRequests().device_info()
        if device_info is None:
            raise
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
                                        auth=self.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
                                        auth=self.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
            response = self.session.put(f"{self.base_address}System/time", data=xml_data, auth=self.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
                data=xml_data, auth=get.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
                                        data=xml_data, auth=get.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
                                        data=xml_data, auth=get.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
                                        data=xml_data, auth=get.basic_auth)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)

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
                                 data=xml_data, auth=self.basic_auth)
            json_response = to_json(response)
            print("test")
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except Exception as e:
            log.exception(e)


api.add_resource(Hikvision, '/', '/get_cam_config')

if __name__ == '__main__':
    h = Hikvision()
    put = SetRequests()
    get = GetRequests()

    app.run(debug=True)
    # log.debug(get.get_time_config())
    # log.debug(get.get_ntp_config())
    # log.debug(get.get_stream_config())
    # log.debug(get.get_wifi_list())
    # log.debug(get.get_email_config())
    # log.debug(get.get_osd_datetime_config())
    # log.debug(get.get_osd_channel_name_config())
    # log.debug(get.get_detection_config())
    # log.debug(get.get_event_notification_config())
    #
    # log.debug(sett.set_email_config())
    # log.debug(sett.set_ntp_config())
    # log.debug(sett.set_eth_config())
    # log.debug(sett.set_stream_config())
    # log.debug(sett.set_time_config())
    # log.debug(sett.set_osd_channel_config())
    # log.debug(sett.set_osd_datetime_config())
    # log.debug(sett.set_alarm_notifications_config())
    # log.debug(sett.set_detection_config())

    # h.get_cam_config()
    # h.set_cam_config()
