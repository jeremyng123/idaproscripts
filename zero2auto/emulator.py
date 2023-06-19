import requests


class Emulator():

    def __init__(self, url):
        self.url = url

    def send_request(self,
                     method,
                     url,
                     body=None,
                     headers=None,
                     params=None,
                     timeout=None):
        pass