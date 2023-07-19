import os
import uuid
import json
import requests
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

import pydash as py_


class SVC_Bankfrick(object):
    def __init__(self, api_key, private_key_path, public_key_path, sandbox=True):

        self.api_key = api_key
        self.sandbox = sandbox
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.private_key = None
        self.public_key = None

        if self.sandbox:
            self.uri = "https://olbsandbox.bankfrick.li/webapi"
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
            "key": self.api_key,
            # "password" : "3dM6fqSP"
        }

        _signature = self.get_signature(json.dumps(_payload).encode("utf-8"))
        # check is valid
        # is_valid = self.is_valid(json.dumps(_payload).encode("utf-8"), _signature)

        # print("signature: ")
        # print(_signature)
        # print("valid signature: ")
        # print(is_valid)

        _header = {
            "Content-Type": "application/json",
            "Signature": _signature,
            "algorithm": "rsa-sha512"
        }

        # print("===== API call Info ======")
        # print(f"{self.uri}{_endpoint}")
        # print(_payload)
        # print(_header)

        resp = requests.post(
            f"{self.uri}{_endpoint}",
            headers=_header,
            json=_payload,
        )

        # print("content", resp.content)
        token_bytes = resp.content
        token_string = token_bytes.decode("utf-8")
        token_obj = json.loads(token_string)
        token = token_obj["token"]
        self.access_token = token

        # print("token", token)
        # print(resp.status_code)
        # self.access_token = f"{py_.get(resp.json(), 'token_type')} {py_.get(resp.json(), 'access_token')}"
        # print(self.access_token)

        return resp

    def create_single_transaction(self, custom_id: str, amount: float, currency: str, express: bool, charge: str, reference: str,
                                  debitor_iban: str, creditor_name: str, creditor_iban: str):
        # https://developers.bankfrick.li/docs#data-types-transaction-new-instance
        '''
        {
            "transactions" : [ {
                "customId" : "A4711",
                "type" : "SEPA",
                "amount" : 1000.00,
                "currency" : "EUR",
                "express" : true,
                "valuta" : "2020-01-03",
                "valutaIsExecutionDate" : true,
                "reference" : "some individual text",
                "charge" : "SHA",
                "debitor" : {
                    "iban" : "LI6808811000000001234"
                },
                "creditor" : {
                    "name" : "Satoshi Nakamoto",
                    "iban" : "DE12500105170648489890"
                }
            } ]
        }
        '''
        # type in ["INTERNAL", "BANK_INTERNAL", "SEPA", "FOREIGN", "RED", "QR_BILL"]

        transaction = {
            "customId": custom_id,
            "type": "FOREIGN",
            "amount": amount,
            "currency": currency,
            "express": express,
            # "valuta" : "2020-01-03",
            # "valutaIsExecutionDate" : true,
            "reference": reference,
            "charge": charge,
            "debitor": {
                "iban": debitor_iban
            },
            "creditor": {
                "name": creditor_name,
                "iban": creditor_iban,
                "address": "text",
                "city": "text",
                "postalcode": "text",
                "country": "Vietnam",
            }
        }

        _payload = {
            "transactions": [transaction]
        }

        ''' sample response
        sample_resp = {
            "moreResults" : false,
            "resultSetSize" : 1,
            "transactions" : [ {
                "orderId" : 9775,
                "customId" : "b9bdc14a-2412-425b-8e92-fbf08c1a960a",
                "type" : "FOREIGN",
                "state" : "PREPARED",
                "amount" : 1.0,
                "currency" : "USD",
                "valuta" : "2023-07-18",
                "valutaIsExecutionDate" : true,
                "express" : true,
                "reference" : "b9bdc14a-2412-425b-8e92-fbf08c1a960a",
                "charge" : "BEN",
                "direction" : "outgoing",
                "debitor" : {
                "accountNumber" : "0103253/001.000.840",
                "name" : "0103253 *VORNAME* 0103253 *NAME*",
                "iban" : "LI20088110103253K000U"
                },
                "creditor" : {
                "accountNumber" : "0103253/001.000.826",
                "name" : "0103253 *VORNAME* 0103253 *NAME*",
                "address" : "text",
                "postalcode" : "TEXT",
                "city" : "text",
                "country" : "VN",
                "iban" : "LI10088110103253K000G",
                "bic" : "BFRILI22XXX",
                "creditInstitution" : "BANK FRICK AND CO AKTIENGESELLSCHAFT"
                },
                "creator" : "20025 *VORNAME* *NAME*",
                "createDate" : "2023-07-18T10:37:43",
                "right" : "110 - Sole signature rights",
                "groupPolicy" : "No constraint",
                "quorum" : 1
            } ]
            }
        '''
        resp_transactions = self.make_request_api('PUT', '/v2/transactions', _payload, {"test": "true"})
        rt_transaction = py_.get(resp_transactions, "transactions.0")

        return rt_transaction

    def sign_transaction_without_tan(self, order_ids: list):
        _payload = {
            "orderIds": order_ids
        }

        return self.make_request_api("POST", "/v2/signTransactionWithoutTan", _payload)

    def make_request_api(self, method='GET', endpoint='', payload={}, headers={}, params={}, timeout=None, sign_payload=True):
        timeout = timeout or 10
        api_url = "{}{}".format(self.uri, endpoint)

        headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {self.access_token}"
        })

        if sign_payload:
            _signature = self.get_signature(json.dumps(payload).encode("utf-8"))

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
            if sign_payload:
                _signature = self.get_signature(json.dumps(payload).encode("utf-8"))
                headers.update({
                    "Signature": _signature,
                    "algorithm": "rsa-sha512"
                })

            resp = requests.request(
                method,
                api_url,
                json=payload,
                headers=headers,
                timeout=timeout,
            )

        if resp.status_code == 401:
            self.authorize()
            return self.make_request_api(method, endpoint, payload, headers, params, timeout, sign_payload)
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
    # print(resp_authorize)

    # svc.make_request_api(endpoint='/v2/transactions', params={"transactionNr": 1234})
    # "LI20088110103253K000U"
    custom_id = str(uuid.uuid4())
    transaction = svc.create_single_transaction(custom_id, 1.0, "USD", True, "BEN", custom_id, "LI20088110103253K000U", "20028 DatNLQ", "LI10088110103253K000G")
    # create transaction
    print(transaction)

    # sign
    order_id = py_.get(transaction, "orderId")
    sign_resp = svc.sign_transaction_without_tan([order_id])
    print(sign_resp)
