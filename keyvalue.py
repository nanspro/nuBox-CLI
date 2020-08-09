import requests 

api_key = 'uxq594kh'

def set_value(key, value):
    url = f"https://keyvalue.immanuel.co/api/KeyVal/UpdateValue/{api_key}/{key}/{value}"
    x = requests.post(url, data="")
    if x.text == 'true':
        return True
    return False


def get_value(key):
    url = f"https://keyvalue.immanuel.co/api/KeyVal/GetValue/{api_key}/{key}"
    x = requests.get(url)
    return x.json()
