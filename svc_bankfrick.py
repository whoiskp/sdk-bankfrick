import os
import json
import requests
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

class SVC_Bankfrick(object):
    def __init__(self, api_key, private_key_path, public_key_path, sandbox=True):

        self.api_key = api_key
        self.sandbox = sandbox
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.private_key = None
        self.public_key = None

        if self.sandbox:
            self.uri = "https://olbtest.bankfrick.li/webapi"
        else:
            self.uri = "https://olb.bankfrick.li/webapi"

        self.access_token = ""

        self._load_private_key()
        self._load_public_key()


    def _load_private_key(self):
        with open(self.private_key_path, 'rb') as private_key_file:
            private_key = load_pem_private_key(private_key_file.read(), password=None)
        self.private_key = private_key


    def _load_public_key(self):
        with open(self.public_key_path, 'rb') as public_key_file:
            public_key = load_pem_public_key(public_key_file.read())
        self.public_key = public_key


    def get_signature(self, body: bytes):
        signature = self.private_key.sign(
            body,
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        return base64.b64encode(signature).decode()


    def is_valid(self, body, signature):
        signature_bytes = base64.b64decode(signature)
        try:
            self.public_key.verify(
                signature_bytes,
                body,
                padding.PKCS1v15(),
                hashes.SHA512()
            )
            return True
        except Exception:
            return False


    def authorize(self):
        _endpoint = "/v2/authorize"
        _payload = {
            "key" : self.api_key,
            # "password" : "3dM6fqSP"
        }

        _signature = self.get_signature(json.dumps(_payload).encode("utf-8"))
        # check is valid
        is_valid = self.is_valid(json.dumps(_payload).encode("utf-8"), _signature)

        print("signature: ")
        print(_signature)
        print("valid signature: ")
        print(is_valid)

        _header = {
            "Content-Type": "application/json",
            "Signature": _signature,
            "algorithm": "rsa-sha512"
        }

        print("===== API call Info ======")
        print(f"{self.uri}{_endpoint}")
        print(_payload)
        print(_header)

        resp = requests.post(
            f"{self.uri}{_endpoint}",
            headers=_header,
            json=_payload,
        )

        print(resp.content)
        print(resp.status_code)
        # self.access_token = f"{py_.get(resp.json(), 'token_type')} {py_.get(resp.json(), 'access_token')}"
        # print(self.access_token)

        return resp


    def create_order(self, item_name, item_quantity, currency, amount, unit_amount):
        _endpoint = "v2/checkout/orders"
        _payload = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "items": [
                        {
                            "name": item_name,
                            "description": "",
                            "quantity": str(abs(item_quantity)),
                            "unit_amount": {
                                "currency_code": currency,
                                "value": str(abs(unit_amount))
                            }
                        }
                    ],
                    "amount": {
                        "currency_code": currency,
                        "value": str(abs(amount)),
                        "breakdown": {
                            "item_total": {
                                "currency_code": currency,
                                "value": str(abs(unit_amount) * abs(item_quantity))
                            }
                        }
                    }
                }
            ],
            "application_context": {
                "return_url": "",
                "cancel_url": ""
            }
        }

        resp = self.make_request_api("POST", _endpoint, _payload, timeout=10, auth=self.access_token)
        print("=====")
        print(resp)
        return resp


    def make_request_api(self, method='GET', endpoint='', payload={}, headers={}, params={}, timeout=None, auth=None):
        timeout = timeout or 10
        api_url = "{}/{}".format(self.uri, endpoint)

        headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": self.access_token
        })

        # print(headers)
        # print(api_url)
        # print(method)

        if method == 'GET':
            resp = requests.get(
                api_url,
                params=params,
                headers=headers,
                timeout=timeout,
            )
        else:
            resp = requests.request(
                method,
                api_url,
                json=payload,
                headers=headers,
                timeout=timeout,
            )

        if resp.status_code == 401:
            self.authen()
            return self.make_request_api(method, endpoint, payload, headers, params, timeout)
        return resp.json()


if __name__ == "__main__":
    print("main")

    svc = SVC_Bankfrick(
        api_key="65w3cw6cg58d7pmHpFg52w92E",
        private_key_path="cert/private.key",
        public_key_path="cert/public.pem",
        sandbox=True
    )

    resp_authorize = svc.authorize()
    print(resp_authorize)

