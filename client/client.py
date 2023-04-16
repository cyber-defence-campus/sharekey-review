import websocket
import time
import json
import base64
import hashlib
import nacl.raw as nacl
from pprint import pprint
import unicodedata
import random
import string
import time
import urllib
import requests
from tqdm import tqdm
import os
import cv2
import datetime


class ShareKeyWS:
    def __init__(
        self,
        url="ws://localhost:3000/sockjs/906/yfai9ebm/websocket",
    ):
        self.ws = None
        self.url = url

    def __enter__(self):
        self.ws = websocket.WebSocket()
        self.ws.connect(self.url)
        self.ws.recv()
        return self

    def __exit__(self, *args, **kwargs):
        self.ws.close()
        self.ws = None

    def recv(self):
        response = self.ws.recv()
        print(response)
        return json.loads(json.loads(response[1:])[0])

    def send(self, cmd):
        print(cmd)
        self.ws.send(json.dumps([json.dumps(cmd)]))

    @staticmethod
    def randstr(l=17):
        return "".join(
            random.choice(string.ascii_letters + string.digits) for i in range(l)
        )

    def sub(self, sub, *params, throw_error=True):
        cmd = {"msg": "sub", "id": self.randstr(), "name": sub, "params": list(params)}
        self.send(cmd)
        out = []
        resp = self.recv()
        # pprint(cmd)
        # pprint(resp)
        while not "msg" in resp or resp["msg"] != "ready":
            if resp["msg"] == "error" or "error" in resp:
                if throw_error:
                    raise ValueError(f"{resp}\n(CMD: {cmd})")
                else:
                    return resp
            out.append(resp)
            resp = self.recv()
            # pprint(resp)
        if cmd["id"] not in resp["subs"]:
            if throw_error:
                ValueError("Expected Sub")
            else:
                return resp
        # pprint(out)
        return out

    def method(self, method, *params, throw_error=True):
        cmd = {
            "msg": "method",
            "id": str(random.randint(0, 100000)),
            "method": method,
            "params": list(params),
        }
        self.send(cmd)
        resp = self.recv()
        # pprint(cmd)
        # pprint(resp)
        while (
            not "msg" in resp
            or resp["msg"] != "result"
            or "id" not in resp
            or resp["id"] != cmd["id"]
        ):
            if resp["msg"] == "error":
                if throw_error:
                    raise ValueError(str(resp))
                else:
                    return resp
            resp = self.recv()
            # pprint(resp)
        if "error" in resp:
            if throw_error:
                raise ValueError(str(resp))
            else:
                return resp

        if "result" in resp:
            if throw_error:
                return resp["result"]
            else:
                return resp
        else:
            if throw_error:
                return None
            else:
                return resp


class ShareKeyClient:
    def __init__(
        self,
        url="ws://localhost:3000/sockjs/290/vkgfxpes/websocket",
        file_server_url="http://localhost:6080/",
    ):
        self.url = url
        self.file_server_url = file_server_url
        self.skws = ShareKeyWS(self.url)
        self._contacts = None
        self.keys = set()

    @property
    def contacts(self):
        if self._contacts is None:
            self._contacts = self.get_user_contacts()
        return self._contacts

    def login_keyring(self, email, meteorLoginToken, eMainKeyRing):
        """Logs in to an account with the provided credentials
        """
        self.encrypt_pk = base64.b64decode(eMainKeyRing["ECDHPK"]["$binary"])
        self.encrypt_sk = base64.b64decode(eMainKeyRing["ECDHSK"]["$binary"])
        self.sign_pk = base64.b64decode(eMainKeyRing["ECDSAPK"]["$binary"])
        self.sign_sk = base64.b64decode(eMainKeyRing["ECDSASK"]["$binary"])
        self.passphrase = eMainKeyRing["passphrase"]
        self.email = email
        self.meteorLoginToken = meteorLoginToken

        self.keys.add(self.encrypt_sk)

        passphrase_hash = hashlib.sha512(self.passphrase.encode()).digest()
        email_hash = hashlib.sha512(self.email.encode()).digest()
        cpu_cost = 2**15
        memoryCost = 4
        parallelCost = 1

        self.secret_key = hashlib.scrypt(
            passphrase_hash,
            salt=email_hash,
            n=cpu_cost,
            r=memoryCost,
            p=parallelCost,
            dklen=32,
        )

        self.user = self.get_user_by_email(self.email)
        self.id = self.user["_id"]

        encrypted_email = base64.b64decode(
            self.user["profile"]["crypto"]["encryptedEmail"]["$binary"]
        )
        nonce_email = base64.b64decode(
            self.user["profile"]["crypto"]["nonceEmail"]["$binary"]
        )

        email_hash = base64.b64encode(hashlib.sha512(self.email.encode()).digest())
        decrypted_email_hash = nacl.crypto_box_open(
            encrypted_email, nonce_email, self.encrypt_pk, self.secret_key
        )
        if email_hash != decrypted_email_hash:
            print(email_hash)
            print(decrypted_email_hash)
            pprint(self.user)
            # raise ValueError("Wrong Passphrase or something, idk")

        self.skws.method("login", {"resume": self.meteorLoginToken})

    def sign(self, message: bytes, sign_sk: bytes = None):
        """Signs a message with the given signing key
        """
        # If no key is provided, use key of `self` as default
        if sign_sk is None:
            sign_sk = self.sign_sk

        # Sign message and truncate signature
        return nacl.crypto_sign(message, sign_sk)[:64]

    def encrypt(self, message, encrypt_sk=None, **kwargs):
        """Encrypts a message with the givven encryption key
        """
        if encrypt_sk is None:
            encrypt_sk = self.encrypt_sk
        nonce = nacl.randombytes(nacl.crypto_box_NONCEBYTES)
        encryption = nacl.crypto_secretbox(message, nonce, encrypt_sk)
        return encryption, nonce

    def decrypt(self, cipher, nonce, encrypt_sk=None):
        """Decrypts a message with the given encryption key
        """
        if encrypt_sk is None:
            encrypt_sk = self.encrypt_sk

        return nacl.crypto_secretbox_open(cipher, nonce, encrypt_sk)

    def encrypt_then_sign(self, message, **kwargs):
        """Encrypts then signs a message with the given encryption and singature key
        """
        encryption, nonce = self.encrypt(message, **kwargs)
        signature = self.sign(encryption, **kwargs)
        return encryption, nonce, signature

    def get_user_by_email_hash(self, email_hash):
        """Queries the back-end for a given email hash
        """
        result = self.skws.method(
            "people.getUserByEmailHash", {"emailHash": email_hash}
        )
        return result

    def get_user_by_id(self, user_id):
        """Gets information about a user given its user id
        """
        result = self.skws.method("people.getUserById", {"userId": user_id})
        return result

    def get_user_by_email(self, email):
        """Hashes an email address and queries the back-end for that address
        """
        email_hash = base64.b64encode(
            hashlib.sha512(
                unicodedata.normalize("NFKC", email).encode("utf-8")
            ).digest()
        ).decode()
        result = self.skws.method(
            "people.getUserByEmailHash", {"emailHash": email_hash}
        )
        return result

    def get_user_channels(self):
        """Obtains a list of channels of the current user, decrypting any data that the user knows the key of
        """
        c = self.skws.sub("messages.currentUserChannels")
        print("CHANNELS", c)
        channels = [self.decrypt_channel(channel) for channel in c]
        return [channel for channel in channels if channel is not None]

    def get_user_contacts(self):
        """Obtains a list of al contacts of the current user
        """
        return self.skws.sub("people.currentUserContacts")

    def get_messages(self, channel):
        """Obtains a list of all messages within a channel, decrypting them with the channel key
        """
        messages = self.skws.sub("messages.getForChannel", channel["id"], 100)
        return [self.decrypt_all(message, channel["key"]) for message in messages]

    def decrypt_all(self, obj, sk):
        if isinstance(obj, dict):
            if "hash" in obj:
                del obj["hash"]
            if len(obj) == 3:
                nonce = None
                signature = None
                cipher = None
                for k, v in obj.items():
                    if isinstance(v, int):
                        continue
                    if "nonce" in k.lower() and "$binary" in v:
                        nonce = base64.b64decode(v["$binary"])
                    elif "sign" in k.lower() and "$binary" in v:
                        signature = base64.b64decode(v["$binary"])
                    elif "$binary" in v:
                        cipher = base64.b64decode(v["$binary"])

                if nonce is not None and signature is not None and cipher is not None:
                    try:
                        return nacl.crypto_secretbox_open(cipher, nonce, sk)
                    except Exception as e:
                        return str(e)
                else:
                    pass
            else:
                for k, v in obj.items():
                    obj[k] = self.decrypt_all(obj[k], sk)
                return obj
        else:
            return obj

    def channel_key(self, channel):
        """Obtains the channel key from a channel object by decrypting the right encrypted key
        """
        if channel["fields"]["isDirect"]:
            if self.id not in channel["fields"]["participants"]:
                return None

            other_ids = [k for k in channel["fields"]["participants"] if k != self.id]
            if len(other_ids) != 1:
                pprint(channel)
                pprint(other_ids)
                pprint(self.id)
                raise ValueError("Too many ids")
            other_id = other_ids[0]
            other_pk = base64.b64decode(
                channel["fields"]["participants"][other_id]["ECDHPK"]["$binary"]
            )
            return nacl.crypto_box_beforenm(other_pk, self.encrypt_sk)
        else:
            owner = channel["fields"]["owner"]
            if owner == self.id:
                sk = self.encrypt_sk
            else:
                sk = nacl.crypto_box_beforenm(
                    base64.b64decode(
                        channel["fields"]["participants"][owner]["ECDHPK"]["$binary"]
                    ),
                    self.encrypt_sk,
                )

            eSSK = channel["fields"]["participants"][self.id]["eSSK"]
            channelECDHSK = base64.b64decode(eSSK["channelECDHSK"]["$binary"])
            nonce = base64.b64decode(eSSK["nonce"]["$binary"])
            return nacl.crypto_secretbox_open(channelECDHSK, nonce, sk)

    def decrypt_channel(self, channel):
        """Obtains the channel key and decrypts all decryptable information about it
        """
        channel_key = self.channel_key(channel)
        if channel_key is None:
            return None
        decrypted_channel = self.decrypt_all(channel, self.channel_key(channel))
        decrypted_channel["key"] = channel_key
        return decrypted_channel

    def invalidate(self, data):
        data = data[:-1] + chr(data[-1] + 1).encode()
        return data

    def send_message(
        self,
        channel,
        newJson,
        timestamp=None,
        id=None,
        msg_sig_valid=True,
        msg_enc_valid=True,
        ts_sig_valid=True,
        ts_enc_valid=True,
    ):
        """Sends a message to a given channel, with the possibility to invalidate signatures or ciphertexts of the message and timestamp.
        """
        if timestamp is None:
            timestamp = str(int(time.time() * 1000)).encode()

        print(timestamp)

        if id is None:
            id = ShareKeyWS.randstr(24)

        encryption, nonce, signature = self.encrypt_then_sign(
            json.dumps(newJson).encode(), encrypt_sk=channel["key"]
        )

        ts_encryption, ts_nonce, ts_signature = self.encrypt_then_sign(
            timestamp, encrypt_sk=channel["key"]
        )

        if not msg_enc_valid:
            encryption = self.invalidate(encryption)
        if not msg_sig_valid:
            signature = self.invalidate(signature)
        if not ts_enc_valid:
            ts_encryption = self.invalidate(ts_encryption)
        if not ts_sig_valid:
            ts_signature = self.invalidate(ts_signature)

        new_message = {
            "eMessage": {
                "_id": id,
                "channelId": channel["id"],
                "eContent": {
                    "eText": {
                        "text": {"$binary": base64.b64encode(encryption).decode()},
                        "Nonce": {"$binary": base64.b64encode(nonce).decode()},
                        "Signature": {
                            "$binary": base64.b64encode(ts_signature).decode()
                        },
                    }
                },
                "eTimestamp": {
                    "eTime": {"$binary": base64.b64encode(ts_encryption).decode()},
                    "Nonce": {"$binary": base64.b64encode(ts_nonce).decode()},
                    "Signature": {"$binary": base64.b64encode(ts_signature).decode()},
                },
            }
        }

        return self.skws.method(
            "messages.send",
            new_message,
        )

    def edit_message(self, message, channel, newJson, new_timestamp=None):
        """Sends a given message, inserting a new JSON instead
        """

        encryption, nonce, signature = self.encrypt_then_sign(
            json.dumps(newJson).encode(), encrypt_sk=channel["key"]
        )

        if new_timestamp is None:
            new_timestamp = str(int(time.time() * 1000)).encode()

        ts_encryption, ts_nonce, ts_signature = self.encrypt_then_sign(
            new_timestamp, encrypt_sk=channel["key"]
        )

        new_message = {
            "eMessage": {
                "_id": message["id"],
                "channelId": channel["id"],
                "eContent": {
                    "eText": {
                        "text": {"$binary": base64.b64encode(encryption).decode()},
                        "Nonce": {"$binary": base64.b64encode(nonce).decode()},
                        "Signature": {
                            "$binary": base64.b64encode(ts_signature).decode()
                        },
                    }
                },
                "eTimestamp": {
                    "eTime": {"$binary": base64.b64encode(ts_encryption).decode()},
                    "Nonce": {"$binary": base64.b64encode(ts_nonce).decode()},
                    "Signature": {"$binary": base64.b64encode(ts_signature).decode()},
                },
            }
        }

        return self.skws.method(
            "messages.edit",
            new_message,
        )

    def delete_message(self, message):
        """Deletes a given message
        """
        return self.skws.method(
            "messages.delete",
            {"messageId": message["id"]},
        )

    def sendInvite(self, emails_list, custom_message):
        """Send an invitation E-Mail to the given email list
        """
        return self.skws.method(
            "PersonalInvitationCode.sendEmails",
            {"emailsList": emails_list, "customMessage": custom_message},
        )


    def get_user_by_invitation(self, invitation):
        """Get a list of users by invitation
        """
        self.skws.method("people.user.getByInvitation", {})

    def change_name(self, first_name, last_name):
        """Changes the name of the current user
        """
        return self.skws.method(
            "people.user.editProfile",
            {"profileUpdates": {"firstName": first_name, "lastName": last_name}},
        )

    def spam_mail(self, subject1, subject2, emails_list, message, tracking_image=None):
        """Sends a mail address to a list of users, with any message, adding the HTML escape code
        to remove indicators that the E-Mail was sent through Sharekey
        """
        message_breaks = message.replace("\n", "<br/>\n")
        if tracking_image is None:
            message_div = f'<div style="text-align: left;">\n{message_breaks}\n</div>'
        else:
            message_div = f"<div style=\"text-align: left; background-image: url('{tracking_image}');\">\n{message_breaks}\n</div>"
        message_escaped = f"""
            </td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table>
            {message_div}
            <table style="display:none"><tbody><tr><td><table><tbody><tr><td><table><tbody><tr><td>         
        """

        self.change_name(subject1, subject2)
        print(message_escaped)
        return self.sendInvite(emails_list, message_escaped)

    def search_people(self, regex):
        """Searches people by RegEx
        """
        return self.skws.method("people.search", {"stringToSearch": regex})

    def get_all_public(self):
        """Returns a list of all people with public profiles
        """
        return self.search_people(".*")

    def upload_chunk(self, file_id, chunk_id, offset, data, encrypt_sk):
        """Uploads a chunk given a file id and a chunk id, signing it with the user's signature key"""
        chunk_start = offset
        chunk_end = min(chunk_start + 10 * 1024 * 1024, len(data))

        encryption, nonce, signature = self.encrypt_then_sign(
            data[chunk_start:chunk_end], encrypt_sk=encrypt_sk
        )

        response = requests.post(
            os.path.join(self.file_server_url, "v1/chunks/upload"),
            json={
                "fileId": file_id,
                "chunkId": chunk_id,
                "offset": offset,
                "nonce": base64.b64encode(nonce).decode(),
                "signature": base64.b64encode(signature).decode(),
                "payload": base64.b64encode(encryption).decode(),
            },
        )
        response.raise_for_status()
        print(response)

    def upload_file(
        self,
        data,
        name,
        mime_type,
        is_public=False,
        original_dimensions=None,
        parent_folder_id="",
        preview_dimensions=(160, 160),
        upload_for_sharing=False,
        with_preview=True,
        with_thumbnails=True,
    ):
        """Uploads a new file to sharekey"""
        file_sk = nacl.randombytes(32)
        file_sk_wrong = nacl.randombytes(32)
        sk_e, sk_n, sk_s = self.encrypt_then_sign(file_sk, encrypt_sk=self.encrypt_sk)

        meta = {
            "name": name,
            "createdAt": int(time.time() * 1000),
            "changedAt": int(time.time() * 1000),
        }

        meta_e, meta_n, meta_s = self.encrypt_then_sign(
            json.dumps(meta).encode(),
            encrypt_sk=file_sk,
        )

        resp = self.skws.method(
            "safe.upload.encryptedChunks",
            {
                "MIMEtype": mime_type,
                "ECDSAPK": {"$binary": base64.b64encode(self.sign_pk).decode()},
                "eECDHSK": {
                    "eUInt8Array": {"$binary": base64.b64encode(sk_e).decode()},
                    "nonce": {"$binary": base64.b64encode(sk_n).decode()},
                    "signature": {"$binary": base64.b64encode(sk_s).decode()},
                },
                "eMeta": {
                    "eUInt8Array": {"$binary": base64.b64encode(meta_e).decode()},
                    "nonce": {"$binary": base64.b64encode(meta_n).decode()},
                    "signature": {"$binary": base64.b64encode(meta_s).decode()},
                    "hash": {
                        "$binary": base64.b64encode(
                            hashlib.sha512(b"hihi").digest()
                        ).decode()
                    },
                },
                "isPublic": is_public,
                "originalDimensions": original_dimensions,
                "parentFolderId": parent_folder_id,
                "previewDimensions": {
                    "width": 99999,
                    "height": 99999,
                },
                "size": len(data),
                "uploadedForSharing": upload_for_sharing,
                "withPreview": with_preview,
                "withThumbnails": with_thumbnails,
            },
        )

        pprint(resp)

        file_id = resp["_id"]

        for file_chunk in tqdm(resp["original"]["chunks"]):
            self.upload_chunk(
                file_id, file_chunk["id"], file_chunk["offset"], data, file_sk
            )

        if with_preview:
            preview_chunk = resp["preview"]["chunk"]
            self.upload_chunk(
                file_id,
                preview_chunk["id"],
                preview_chunk["offset"],
                b"<div>Hello World</div>",
                file_sk,
            )

        if with_thumbnails:
            thumbnail128_chunk = resp["thumbnail128"]["chunk"]
            thumbnail64_chunk = resp["thumbnail64"]["chunk"]
            self.upload_chunk(
                file_id,
                thumbnail128_chunk["id"],
                thumbnail128_chunk["offset"],
                b"<div>Hello World</div>",
                file_sk,
            )
            self.upload_chunk(
                file_id,
                thumbnail64_chunk["id"],
                thumbnail64_chunk["offset"],
                b"<div>Hello World</div>",
                file_sk,
            )
        return resp

    def reverse_chunks(self, file_id, chunks):
        """Given a file id reverses the chunks of that file"""
        chunk_data = [
            requests.get(
                f"http://localhost:9000/fileuploader/{file_id}/{chunk['id']}"
            ).content
            for chunk in chunks
        ]

        for chunk, chunk_rev, chunk_data_rev in zip(
            chunks, reversed(chunks), reversed(chunk_data)
        ):
            pprint(chunk)
            pprint(chunk_rev)

            requests.post(
                os.path.join(self.file_server_url, "v1/chunks/upload"),
                json={
                    "fileId": file_id,
                    "chunkId": chunk["id"],
                    "offset": chunk["offset"],
                    "nonce": chunk_rev["nonce"],
                    "signature": chunk_rev["signature"],
                    "payload": base64.b64encode(chunk_data_rev).decode(),
                },
            )

    def delete_files(self, parent_folder=None, file_ids=[], folder_ids=[]):
        """Deletes a list of files or folders owned by the user"""
        if parent_folder is None:
            parent_id = ""
            new_ts = None
        else:
            parent_id = parent_folder["id"]

            timestamp = str(int(time.time() * 1000)).encode()
            if "encrypt_sk" in parent_folder:
                ts_encryption, ts_nonce, ts_signature = self.encrypt_then_sign(
                    timestamp, encrypt_sk=parent_folder["encrypt_sk"]
                )
            else:
                ts_encryption, ts_nonce, ts_signature = self.encrypt_then_sign(
                    timestamp, encrypt_sk=self.encrypt_sk
                )
            new_ts = {
                "eTimestamp": {"$binary": base64.b64encode(ts_encryption).decode()},
                "eTimestampNonce": {"$binary": base64.b64encode(ts_nonce).decode()},
                "eTimestampSignature": {
                    "$binary": base64.b64encode(ts_signature).decode()
                },
            }

        return self.skws.method(
            "safe.bulk.delete",
            {
                "filesIdsToDelete": file_ids,
                "foldersIdsToDelete": folder_ids,
                "parentFolderId": parent_id,
                "newETimeForParentFolder": new_ts,
            },
        )

    def get_root_folder(self):
        """Obtain the root folder of that user"""
        folder = self.skws.sub("SAFE_ROOT_FOLDER")
        for collection in folder:
            pprint(collection)
            encrypt_sk = self.decrypt_all(
                collection["fields"]["eECDHSK"], self.encrypt_sk
            )["byUser"]
            del collection["fields"]["eECDHSK"]
            collection_decrypted = self.decrypt_all(collection, encrypt_sk)
            collection_decrypted["encrypt_sk"] = self.encrypt_sk
            yield collection_decrypted

    def get_folder(self, folder_id, parent_sk=None):
        """Obtain a folder by folder id, decrypting its fields if the secret key is known"""
        folder = self.skws.sub("safe.folderContent.byId", folder_id)

        for collection in folder:
            if collection["fields"]["owner"] == self.id:
                encrypt_sk = self.decrypt_all(
                    collection["fields"]["eECDHSK"], self.encrypt_sk
                )["byUser"]
            elif parent_sk is not None:
                encrypt_sk = self.decrypt_all(
                    collection["fields"]["eECDHSK"], parent_sk
                )["byFolder"]
            else:
                if parent_sk is not None:
                    collection["encrypt_sk"] = parent_sk
                yield collection
                continue

            del collection["fields"]["eECDHSK"]
            collection_decrypted = self.decrypt_all(collection, encrypt_sk)
            collection_decrypted["encrypt_sk"] = encrypt_sk
            yield collection_decrypted

    def get_object(self, object_id, parent_sk=None):
        """Return a file file by ID"""
        return self.skws.method("safe.get.object", {"fileId": object_id})

    def get_folders_with_rights(self, folder_ids):
        """Return a folder with rights by ID"""
        return self.skws.method(
            "safe.get.folders_with_rights", {"foldersIds": folder_ids}
        )

    def get_tree(self, item):
        """Recursively list all children of any folder and its subfolders etc"""
        if "encrypt_sk" in item:
            encrypt_sk = item["encrypt_sk"]
        else:
            encrypt_sk = None

        if item["collection"] == "Folders":
            item["children"] = [
                self.get_tree(item)
                for item in self.get_folder(item["id"], parent_sk=encrypt_sk)
            ]
        return item

    def get_root_tree(self):
        """List all files owned by the user""""
        return [self.get_tree(item) for item in self.get_root_folder()]

    def __enter__(self):
        self.skws.__enter__()
        self.skws.send(
            {"msg": "connect", "version": "1", "support": ["1", "pre2", "pre1"]}
        )
        self.session = self.skws.recv()["session"]

        return self

    def __exit__(self, *args, **kwargs):
        self.skws.__exit__(*args, **kwargs)


existing = {}


class Item:
    def __init__(
        self,
        item_id,
        data=None,
        encrypted_data=None,
        encrypted_sks=None,
        client=None,
        parent=None,
        encrypt_sk=None,
        child_keys=None,
    ):
        existing[item_id] = self
        self.item_id = item_id
        self._parent = parent
        if client is None and parent is not None:
            self.client = parent.client
        else:
            self.client = client

        if self.client is not None:
            self.client.keys.add(encrypt_sk)

        self.child_keys = child_keys
        self.encrypted_data = encrypted_data
        self.data = data
        self.decrypted = False
        if self.encrypted_data is not None:
            self.encrypted_sks = encrypted_sks

            self.encrypt_sk = encrypt_sk
            for sk in self.get_possible_sks():
                if self.is_valid(sk):
                    self.encrypt_sk = sk
                    if self.client is not None:
                        if "eECDHSK" in data:
                            del data["eECDHSK"]
                        if "fields" in data and "eECDHSK" in data["fields"]:
                            del data["fields"]["eECDHSK"]
                        self.data = self.client.decrypt_all(data, self.encrypt_sk)
                        self.decrypted = True
                    break
            else:
                self.encrypt_sk = None
        else:
            self.encrypt_sk = encrypt_sk

        if self.client is not None:
            self.client.keys.add(self.encrypt_sk)

    def get_possible_sks(self):
        out = {self.encrypt_sk}
        if self.child_keys is not None:
            out |= set(self.child_keys)
        if self.parent is not None:
            out |= self.parent.get_possible_sks()
        if self.client is not None:
            out.add(self.client.encrypt_sk)
            out |= self.client.keys

        if self.encrypted_sks is not None:
            for _, encrypted_sk in self.encrypted_sks.items():
                cipher = base64.b64decode(encrypted_sk["eUInt8Array"]["$binary"])
                nonce = base64.b64decode(encrypted_sk["nonce"]["$binary"])
                new = set()
                for sk in out:
                    try:
                        new.add(nacl.crypto_secretbox_open(cipher, nonce, sk))
                    except Exception as e:
                        pass
                out |= new
        return out

    def is_valid(self, encrypt_sk):
        cipher = base64.b64decode(self.encrypted_data[0]["$binary"])
        nonce = base64.b64decode(self.encrypted_data[1]["$binary"])
        try:
            nacl.crypto_secretbox_open(cipher, nonce, encrypt_sk)
            return True
        except Exception as e:
            return False

    @classmethod
    def from_json(cls, data, *args, **kwargs):
        if "collection" in data:
            if data["collection"] == "Folders":
                if data["id"] in existing:
                    return existing[data["id"]]
                return Folder(
                    data["id"],
                    encrypted_data=(
                        data["fields"]["eName"]["text"],
                        data["fields"]["eName"]["Nonce"],
                    ),
                    encrypted_sks=data["fields"]["eECDHSK"],
                    data=data,
                    *args,
                    **kwargs,
                )
            elif data["collection"] == "Safe":
                if data["id"] in existing:
                    return existing[data["id"]]
                return File(
                    data["id"],
                    encrypted_data=(
                        data["fields"]["eMeta"]["eUInt8Array"],
                        data["fields"]["eMeta"]["nonce"],
                    ),
                    encrypted_sks=data["fields"]["eECDHSK"],
                    data=data,
                    *args,
                    **kwargs,
                )
        if data["_id"] in existing:
            return existing[data["_id"]]
        if "eName" in data:
            return cls(
                data["_id"],
                encrypted_data=(data["eName"]["text"], data["eName"]["Nonce"]),
                data=data,
                *args,
                **kwargs,
            )
        else:
            return cls(
                data["_id"],
                encrypted_data=(data["eMeta"]["eUInt8Array"], data["eMeta"]["nonce"]),
                encrypted_sks=data["eECDHSK"],
                data=data,
                *args,
                **kwargs,
            )

    @property
    def parent(self):
        if self._parent is None:
            parent_id = self.data["parentFolderId"]
            if parent_id != "":
                self._parent = Folder.from_id(
                    self.client,
                    self.data["parentFolderId"],
                    encrypt_sk=self.encrypt_sk,
                    child_keys=[self.encrypt_sk],
                )
        return self._parent

    def owner(self):
        if "owner" in self.data:
            return self.data["owner"]
        else:
            pprint(data)
            return None


class Folder(Item):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._children = None

    @property
    def children(self):
        if self._children is not None:
            return self._children

        self._children = [
            Folder.from_json(child, parent=self)
            for child in self.client.skws.sub("safe.folderContent.byId", self.item_id)
            if not child["id"] == self.item_id
        ]
        return self._children

    @staticmethod
    def from_id(client, folder_id, *args, **kwargs):
        folder_data = client.get_folders_with_rights([folder_id])[0]
        return Folder.from_json(folder_data, *args, client=client, **kwargs)

    def __str__(self):
        if self.decrypted:
            if "fields" in self.data:
                name = self.data["fields"]["eName"].decode()
                date_string = date_string = datetime.datetime.fromtimestamp(
                    int(self.data["fields"]["eCreatedAt"].decode()) / 1000
                ).strftime("%Y-%m-%d %H:%M")
            else:
                name = self.data["eName"].decode()
                date_string = date_string = datetime.datetime.fromtimestamp(
                    int(self.data["eCreatedAt"].decode()) / 1000
                ).strftime("%Y-%m-%d %H:%M")
        else:
            name = "???"
            date_string = "???"

        if "fields" in self.data:
            owner = self.data["fields"]["owner"]
        else:
            owner = self.data["owner"]

        if self.client is not None:
            contact_map = {
                contact["id"]: contact["fields"]["profile"]["names"]
                for contact in self.client.contacts
            }
            if owner == self.client.id:
                owner = "You"
            elif owner in contact_map:
                owner = contact_map[owner]
            else:
                owner = owner

        out = f'🗀 "{name}" ({owner} @ {date_string})'
        for child in self.children:
            out += "\n| " + str(child).replace("\n", "\n| ")
        return out


class File(Item):
    def __str__(self):
        if "fields" in self.data:
            fields = self.data["fields"]
        else:
            fields = self.data

        if self.decrypted:
            meta = json.loads(fields["eMeta"])
            name = meta["name"]
        else:
            name = "???"

        if self.client is not None:
            contact_map = {
                contact["id"]: contact["fields"]["profile"]["names"]
                for contact in self.client.contacts
            }
            if fields["owner"] == self.client.id:
                owner = "You"
            elif fields["owner"] in contact_map:
                owner = contact_map[fields["owner"]]
            else:
                owner = fields["owner"]

        if "MIMEtype" in fields:
            mime = fields["MIMEtype"]
        else:
            mime = "???"

        date_string = datetime.datetime.fromtimestamp(
            fields["uploadingInitialized"] / 1000
        ).strftime("%Y-%m-%d %H:%M")

        return f'"{name}" ({mime}) ({owner} @ {date_string})'

    @staticmethod
    def from_id(client, file_id, *args, **kwargs):
        file_data = client.get_object(file_id)
        # pprint(file_data)
        return File.from_json(file_data, *args, client=client, **kwargs)


def urlencode(s):
    return "".join("%" + hex(ord(c))[2:].upper() for c in s)

if __name__ == "__main__":
    from credentials import *

    with ShareKeyClient(url=URL, file_server_url=FILE_SERVER_URL) as sharekey:
        pass