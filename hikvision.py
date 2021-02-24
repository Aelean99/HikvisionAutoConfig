import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import json
import xmltodict


class Hikvision:
    def __init__(self):
        self.base_address = "http://10.195.17.92/ISAPI/"
        self.basic_auth = HTTPBasicAuth("admin", "tvmix333")
        self.digest_auth = HTTPDigestAuth("admin", "tvmix333")
        self.current_password = ""
        self.session = requests.Session()

    def user_check(self):
        with open("C:/Users/Huawei/PycharmProjects/HikvisionAutoConfig/venv/passwords.json", "r") as passwords:
            password_list = json.load(passwords)

        for password in password_list['values']:
            response = self.session.get(f"{self.basic_auth}Security/userCheck", auth=HTTPBasicAuth("admin", password))
            if response.status_code == 200:
                self.current_password = password
                print(200, "OK")
                return 200, "OK"
            elif response.status_code == 401:
                print(401, "Unauthorized")
            elif response.status_code == 404:
                print(404, "Device is not supported")
                return 404, "Device is not supported"
            else:
                print("Default error")

    def change_password(self):
        data = {"User": {"id": "1", "userName": "admin", "password": "tvmix333"}}
        xml_data = xmltodict.unparse(data)
        response = self.session.put(f"{self.BaseAddress}Security/users/1", xml_data, auth=self.basic_auth)
        return response.status_code

    def to_json(self, response):
        xml_dict = xmltodict.parse(response.content)
        json_response = json.loads(json.dumps(xml_dict))
        return json_response


class GetRequests(Hikvision):
    def device_info(self):
        response = self.session.get(f"{self.base_address}System/deviceInfo", auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_eth_config(self):
        response = self.session.get(f"{self.base_address}System/Network/interfaces/1/ipAddress", auth=self.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response

    def get_stream_config(self):
        response = self.session.get(f"{self.base_address}Streaming/channels/101", auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_time_config(self):
        response = self.session.get(f"{self.base_address}System/time", auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_ntp_config(self):
        response = self.session.get(f"{self.base_address}System/time/NtpServers/1", auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_email_config(self):
        response = self.session.get(f"{self.base_address}System/Network/mailing/1", auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_detection_config(self):
        response = self.session.get(f"{self.base_address}System/Video/inputs/channels/1/motionDetection", auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_wifi_list(self):
        response = self.session.get(f"{self.base_address}System/Network/interfaces/2/wireless/accessPointList", auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_osd_datetime_config(self):
        response = self.session.get(f"{self.base_address}System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                    auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_osd_channel_name_config(self):
        response = self.session.get(f"{self.base_address}System/Video/inputs/channels/1/overlays/channelNameOverlay",
                                    auth=self.basic_auth)
        return Hikvision().to_json(response)

    def get_event_notification_config(self):
        response = self.session.get(f"{self.base_address}Event/triggers/VMD-1/notifications",
                                    auth=self.basic_auth)
        return Hikvision().to_json(response)


class SetRequests(Hikvision):
    def set_eth_config(self, dns=None):
        if dns is None:
            dns = ["217.24.176.230", "217.24.177.2"]
        current_eth_data = GetRequests().get_eth_config()
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

        response = requests.put(f"{self.base_address}System/Network/interfaces/1/ipAddress", data=xml_data,
                                auth=self.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']

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

        response = requests.put(f"{self.base_address}Streaming/channels/101", data=xml_data, auth=self.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']


    def set_email_config(self):
        device_info = GetRequests().device_info()
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

        response = self.session.put(f"{self.base_address}System/Network/mailing/1", data=xml_data, auth=self.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']

    def set_ntp_config(self):
        xml_data = '''
            <NTPServer>
                <id>1</id>
                <addressingFormatType>ipaddress</addressingFormatType>
                <ipAddress>217.24.176.232</ipAddress>
                <portNo>123</portNo>
                <synchronizeInterval>30</synchronizeInterval>
            </NTPServer>'''
        response = self.session.put(f"{self.base_address}System/time/NtpServers/1", data=xml_data, auth=self.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']

    def set_time_config(self, timezone=None):
        if timezone is None:
            timezone = "5"

        xml_data = f'''
            <Time>
                <timeMode>NTP</timeMode>
                <timeZone>CST-{timezone}:00:00</timeZone>
            </Time>'''
        response = self.session.put(f"{self.base_address}System/time", data=xml_data, auth=self.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']

    def set_osd_channel_config(self):
        xml_data = '''
        <channelNameOverlay>
            <enabled>false</enabled>
            <positionX>512</positionX>
            <positionY>64</positionY>
        </channelNameOverlay>
        '''

        response = self.session.put(f"{self.base_address}System/Video/inputs/channels/1/overlays/channelNameOverlay", data=xml_data, auth=get.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']

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
        response = self.session.put(f"{self.base_address}System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                    data=xml_data, auth=get.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']

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

        response = self.session.put(f"{self.base_address}Event/triggers/VMD-1/notifications",
                                    data=xml_data, auth=get.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']

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

        response = self.session.put(f"{self.base_address}System/Video/inputs/channels/1/motionDetection",
                                    data=xml_data, auth=get.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']


if __name__ == '__main__':
    sett = SetRequests()
    get = GetRequests()
    print(get.get_time_config())
    print(get.get_ntp_config())
    print(get.get_stream_config())
    print(get.get_wifi_list())
    print(get.get_email_config())
    print(get.get_osd_datetime_config())
    print(get.get_osd_channel_name_config())
    print(get.get_detection_config())
    print(get.get_event_notification_config())

    print(sett.set_email_config())
    print(sett.set_ntp_config())
    print(sett.set_eth_config())
    print(sett.set_stream_config())
    print(sett.set_time_config())
    print(sett.set_osd_channel_config())
    print(sett.set_osd_datetime_config())
    print(sett.set_alarm_notifications_config())
    print(sett.set_detection_config())


