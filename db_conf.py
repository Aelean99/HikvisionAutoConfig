import json
import os

import requests


def cam_info_from_db(id):
    dbconf = ""
    with open(os.path.abspath("dbconf.json"), "r") as conf:
        dbconf = json.load(conf)
    json_data = \
        {
            "hash": f"{dbconf['hash']}",
            "signature": f"{dbconf['signature']}",
            "data": {"id": id}
        }
    db_response = json.loads(requests.post(f"{dbconf['url'] + dbconf['cameraGet']}", json=json_data).content)
    ip_address = db_response['message'][0]['rtsp_ip']
    return ip_address
