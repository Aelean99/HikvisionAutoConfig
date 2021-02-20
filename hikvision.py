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

    def user_check(self):
        with open("C:/Users/Huawei/PycharmProjects/HikvisionAutoConfig/venv/passwords.json", "r") as passwords:
            password_list = json.load(passwords)

        for password in password_list['values']:
            response = requests.get(f"{self.basic_auth}Security/userCheck", auth=HTTPBasicAuth("admin", password))
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
        response = requests.put(f"{self.BaseAddress}Security/users/1", xml_data, auth=self.basic_auth)
        return response.status_code

    def to_json(self, response):
        xml_dict = xmltodict.parse(response.content)
        json_response = json.loads(json.dumps(xml_dict))
        return json_response


class GetRequests(Hikvision):
    def device_info(self):
        response = requests.get(f"{self.BaseAddress}System/deviceInfo", auth=self.basic_auth)

        xml_dict = xmltodict.parse(response.content)
        # print(json.dumps(xml_dict, indent=4))
        device_info = json.loads(json.dumps(xml_dict))
        serial_number = device_info['DeviceInfo']['serialNumber']
        mac_address = device_info['DeviceInfo']['macAddress']
        return serial_number, mac_address

    def get_eth_config(self):
        response = requests.get(f"{self.base_address}System/Network/interfaces/1/ipAddress", auth=self.basic_auth)
        json_response = Hikvision().to_json(response)
        return json_response

    def get_stream_config(self):
        response = requests.get(f"{self.base_address}Streaming/channels/101", auth=self.basic_auth)
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


if __name__ == '__main__':
    sett = SetRequests()
    get = GetRequests()
