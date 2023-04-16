from pprint import pprint
from client import ShareKeyClient
import subprocess
import re
import json
import random
import string
import os
import hashlib
import time
import pprint


def indent(s, indent):
    return indent + s.replace("\n", "\n" + indent)

with open("blns.json") as f:
    NAUGHTY_STRINGS = json.load(f)

class Response:
    def __init__(self, request, response, authenticated, duration):
        self.request = request
        self.response = response
        self.duration = duration
        self.authenticated = authenticated

    def to_json(self):
        return {
            "authenticated": self.authenticated,
            "request": self.request,
            "response": self.response,
            "duration": self.duration,
        }

    @classmethod
    def from_json(cls, data):
        return Response(
            data["request"], data["response"], data["authenticated"], data["duration"]
        )

    def to_markdown(self):
        return f"""  - Authenticated:
    - {self.authenticated}
  - Duration:
    - {int(self.duration*1000)}ms
  - Sent:
    ```json
{indent(json.dumps(self.request, indent=2), '    ')}
    ```
  - Recieved:
    ```json
{indent(json.dumps(self.response, indent=2), '    ')}
    ```
"""


class FuzzingItem:
    name_names = {"method": "method", "sub": "name"}
    CACHE_FOLDER = ".fuzzer_cache"
    VERSION = "0.2"

    def __init__(self, request, item_type, name, params, parent=None):
        self.item_type = item_type
        self.name = name
        self.params = params
        self.response_authenticated = None
        self.response_unauthenticated = None
        self.parent = None
        self.identifier = self.get_id()
        self._load_cache()
        self.request = request

    @classmethod
    def from_json(cls, data):
        return cls(
            request=data,
            item_type=data["msg"],
            name=data[cls.name_names[data["msg"]]],
            params=data["params"],
        )

    def _save_cache(self):
        if not os.path.exists(self.CACHE_FOLDER):
            os.makedirs(self.CACHE_FOLDER)

        filename = f"{self.item_type}_{self.name}_{self.identifier}.json"
        filepath = os.path.join(self.CACHE_FOLDER, filename)
        if os.path.exists(filepath):
            with open(filepath) as f:
                data = json.load(f)
            if "version" not in data or data["version"] != self.VERSION:
                data = {}
        else:
            data = {}

        data["version"] = self.VERSION
        data["parent"] = self.parent.identifier if self.parent is not None else None
        data["type"] = self.item_type
        data["name"] = self.name
        data["id"] = self.identifier
        data["params"] = self.params
        if self.response_authenticated is not None:
            data["response_authenticated"] = self.response_authenticated.to_json()
        if self.response_unauthenticated is not None:
            data["response_unauthenticated"] = self.response_unauthenticated.to_json()
        with open(filepath, "w+") as f:
            json.dump(data, f)

    def _load_cache(self):
        if not os.path.exists(self.CACHE_FOLDER):
            return

        filename = f"{self.item_type}_{self.name}_{self.identifier}.json"
        filepath = os.path.join(self.CACHE_FOLDER, filename)
        if not os.path.exists(filepath):
            return

        with open(filepath) as f:
            data = json.load(f)
        if "version" not in data or data["version"] != self.VERSION:
            return

        if "response_authenticated" in data:
            self.response_authenticated = Response.from_json(
                data["response_authenticated"]
            )
        if "response_unauthenticated" in data:
            self.response_unauthenticated = Response.from_json(
                data["response_unauthenticated"]
            )
        # print("loaded cache")

    @staticmethod
    def get_fuzzable(addr, params):
        if isinstance(params, str):
            yield addr
        elif isinstance(params, list):
            for i, item in enumerate(params):
                for f in FuzzingItem.get_fuzzable((*addr, i), item):
                    yield f
        elif isinstance(params, dict):
            for k, v in params.items():
                if k != "$binary":
                    for f in FuzzingItem.get_fuzzable((*addr, k), v):
                        yield f

    @staticmethod
    def copy_json(data):
        return json.loads(json.dumps(data))

    @staticmethod
    def set_pos(data, addr, value):
        if len(addr) == 1:
            data[addr[0]] = value
        else:
            data[addr[0]] = FuzzingItem.set_pos(data[addr[0]], addr[1:], value)
        return data

    def fuzz(self, seed=None):
        if seed is not None:
            random.seed(seed)
        fuzzable_addrs = list(FuzzingItem.get_fuzzable([], self.params))
        if len(fuzzable_addrs) == 0:
            return self
        addr = random.choice(fuzzable_addrs)
        value = random.choice(NAUGHTY_STRINGS)
        new_params = FuzzingItem.copy_json(self.params)
        new_params = FuzzingItem.set_pos(self.params, addr, value)
        new_request = FuzzingItem.copy_json(self.request)
        new_request["params"] = new_params
        return FuzzingItem(self.request, self.item_type, self.name, new_params, self)

    def get_id(self):
        return hashlib.md5(
            f"{self.item_type}{self.name}{self.params}".encode()
        ).hexdigest()

    @staticmethod
    def random_id(length):
        return "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(length)
        )

    def to_json(self):
        return {
            "msg": self.item_type,
            "id": self.identifier,
            self.name_names[self.item_type]: self.name,
            "params": self.params,
        }

    def unauthenticated_access(self):
        self.send(authenticate=False)
        self.send(authenticate=True)
        r1 = self.response_authenticated.to_json()["response"]
        r2 = self.response_unauthenticated.to_json()["response"]

        if isinstance(r1, list):
            for o in r1:
                if "id" in o:
                    del o["id"]
        else:
            if "id" in r1:
                del r1["id"]

        if isinstance(r2, list):
            for o in r2:
                if "id" in o:
                    del o["id"]
        else:
            if "id" in r2:
                del r2["id"]

        if r1 == []:
            return False
        if str(r1) == str(r2):
            return True
        return False

    def send(self, authenticate=False):
        if authenticate and self.response_authenticated is not None:
            return self.response_authenticated
        elif not authenticate and self.response_unauthenticated is not None:
            return self.response_unauthenticated

        from credentials import URL

        with ShareKeyClient(url=URL) as sharekey:
            if authenticate:
                from credentials import EMAIL, METEOR_TOKEN, KEYRING
                sharekey.login_keyring(EMAIL, METEOR_TOKEN, KEYRING)

            starttime = time.time()
            if self.item_type == "sub":
                out = sharekey.skws.sub(self.name, *self.params, throw_error=False)
            else:
                out = sharekey.skws.method(self.name, *self.params, throw_error=False)
            endtime = time.time()

        if authenticate:
            self.response_authenticated = Response(
                self.request, out, authenticate, endtime - starttime
            )
        else:
            self.response_unauthenticated = Response(
                self.request, out, authenticate, endtime - starttime
            )
        self._save_cache()
        return out


class Finding:
    def __init__(self, responses, title, description):
        self.responses = responses
        self.title = title
        self.description = description

    def to_markdown(self):
        return f"""# {self.title}
{self.description}

## Requests
""" + "\n".join(
            f"- {i+1}:\n{response.to_markdown()}"
            for i, response in enumerate(self.responses)
        )


def load_sample_traffic(filename):
    with open(filename) as f:
        for line in f:
            if line.startswith("["):
                for msg_str in json.loads(line):
                    msg = json.loads(msg_str)
                    if msg["msg"] in ["method", "sub"]:
                        yield msg


def load_har_traffic(filename):
    with open(filename) as f:
        data = json.load(f)

    for entry in data["log"]["entries"]:
        if "_webSocketMessages" in entry:
            for message in entry["_webSocketMessages"]:
                if message["type"] == "send":
                    if message["data"].startswith("["):
                        for msg_str in json.loads(message["data"]):
                            msg = json.loads(msg_str)
                            if msg["msg"] in ["method", "sub"]:
                                yield msg

def report_unauthenticated_access(items):
    for item in items:
        if item.unauthenticated_access():
            yield Finding(
                [item.response_unauthenticated],
                f"Unauthenticated access to `{item.name}`",
                f"The API function `{item.name}` can be activated without logging in to a sharekey account.",
            )

reported_slow = set()
def report_slow_issues(items):
    global reported_slow
    
    for item in items:
        if item.name in reported_slow:
            continue
        unauthenticated = item.unauthenticated_access()
        affected = []
        if item.response_authenticated.duration > 0.1:
            affected.append(item.response_authenticated)
        if item.response_unauthenticated.duration > 0.1:
            affected.append(item.response_unauthenticated)
        if len(affected) > 0:
            reported_slow.add(item.name)
            yield Finding(
                affected,
                f"Slow response at `{item.name}`",
                f"The API function `{item.name}` took {int(1000*affected[0].duration)}ms to respond.",
            )

reported_errors = {}
def report_server_errors(items):
    global reported
    for item in items:
        # if item.name in reported_errors:
        #     continue

        item.send(authenticate=True)
        r = item.response_authenticated.response
        if "error" in r:
            e = False
            if "error" in r["error"] and not isinstance(r["error"]["error"], str):
                e = True
            if "object" in r["error"]["message"]:
                e = True
            if r["error"]["message"] == "Match failed [400]":
                e = False
            if e:
                if item.name not in reported_errors:
                    reported_errors[item.name] = set()
                msg = r["error"]["message"]
                if msg not in reported_errors[item.name]:
                    reported_errors[item.name].add(msg)
                    
                    yield Finding(
                        [item.response_authenticated],
                        f"Server error at `{item.name}`",
                        f"The API function `{item.name}` caused an internal error.",
                    )


def report_all(functions, items):
    for item in items:
        for function in functions:
            for finding in function([item]):
                yield finding

# Don't scan these, as they could break something
ignore = {
    "login",
    "meteor.loginServiceConfiguration" "meteor_autoupdate_clientVersions",
    "meteor.loginServiceConfiguration",
    "meteor_autoupdate_clientVersions",
    "calls.initiate",
    "safe.get.safe_iems_with_rights",
    "notifications.update",
    "safe.folder.update.copied",
    "messages.getForChannel",
    "messages.sendWithAttachments",
    "PersonalInvitationCode.sendEmails",
    "messages.getForChannel",
    "auth.removeToken",
    "externalLinks.internal.getForOwner",
    "safe.get.folders_with_rights"
}

def generate_items(items):
    for item in items:
        yield item
    s = 0
    for i in range(0):
        print(i)
        for item in items:
            yield item.fuzz(seed=s)
        s += 1

if __name__ == "__main__":
    seen = set()
    items = []
    for m in list(load_sample_traffic("recorded-traffic/sample_traffic.txt")) + list(
        load_har_traffic("recorded-traffic/websockets.har")
    ) + list(
        load_har_traffic("recorded-traffic/websockets-2.har")
    ):
        if m["msg"] in ["method", "sub"]:
            item = FuzzingItem.from_json(m)
            if item.name not in ignore:
                items.append(item)
            elif item.response_authenticated is not None and item.response_unauthenticated is not None:
                items.append(item)

    for finding in report_all([report_server_errors, report_slow_issues, report_unauthenticated_access], generate_items(items)):
        print(finding.to_markdown())


"""
WITH ERRORS:
{'PersonalInvitationCode.create': 'not-authorized',
 'PersonalInvitationCode.sendEmails': '400',
 'auth.checkAccessKey': '400',
 'auth.checkSignedCode': '400',
 'auth.generateToken': '400',
 'auth.removeToken': '400',
 'auth.requestAccountDeletion': 'not-authorized',
 'auth.requestLoginAuthCode': '400',
 'calls.checkCallsInQueue': 'not-authorized',
 'calls.dropCall': '500',
 'calls.initiate': '500',
 'channel.removeAvatar': '400',
 'email.requestConfirmationLink': '400',
 'externalLinks.external.getBasicInfo': '400',
 'externalLinks.external.getFolderContent': '400',
 'externalLinks.external.open': '400',
 'externalLinks.internal.create': '400',
 'externalLinks.internal.getForOwner': '400',
 'externalLinks.internal.remove': '400',
 'externalLinks.internal.update': '400',
 'messages.addToChannel': '400',
 'messages.addToChannel.v2': '400',
 'messages.changeChannelInfo': '400',
 'messages.channel.getKMessagesChunk': 'not-authorized',
 'messages.channel.getShared': '400',
 'messages.channels.get': '400',
 'messages.delete': 'not-authorized',
 'messages.deleteChannel': '400',
 'messages.deleteWithAttachments': '400',
 'messages.drafts.delete': '400',
 'messages.drafts.deleteMany': '400',
 'messages.drafts.updateDevicesCount': '400',
 'messages.drafts.upsert': '400',
 'messages.drafts.upsertMany': '400',
 'messages.edit': '400',
 'messages.editWithAttachments': '400',
 'messages.getMessagesViaIdsList': '400',
 'messages.leaveChannel': '400',
 'messages.leaveChannel.v2': '400',
 'messages.read': '400',
 'messages.removeFromChannel': '400',
 'messages.removeFromChannel.v2': '400',
 'messages.send': '400',
 'messages.sendWithAttachments': '400',
 'messages.voiceMessage.listen': '400',
 'notifications.create.many': '400',
 'notifications.remove': '400',
 'notifications.update': '400',
 'notifications.v2.get': '400',
 'people.addToContacts': '400',
 'people.approve': '400',
 'people.cancel': '400',
 'people.connectWithInviter': '400',
 'people.get20FromAllUsers': '400',
 'people.getUserByEmailHash': '400',
 'people.getUserById': '400',
 'people.getUserProfileByPublicKey': '400',
 'people.getUsersById': '400',
 'people.refuse': '400',
 'people.removeUserAvatar': '500',
 'people.search': '400',
 'people.user.addNotificationsData': '400',
 'people.user.cleanRemovedChannels': 'not-authorized',
 'people.user.editProfile': '400',
 'people.user.generateNewPID': 'not-authorized',
 'people.user.getByInvitation': '400',
 'people.user.getByPID': '400',
 'people.user.getInviterToConnect': '400',
 'people.user.getSettings': 'not-authorized',
 'people.user.getStorageSize': 'You should be authorized in app '
                               '[not-authorized]',
 'people.user.lock': 'not-authorized',
 'people.user.removeAvatar': '404',
 'people.user.setDiscoverVisibility': '400',
 'people.user.setSettings': '400',
 'people.user.unlock': 'not-authorized',
 'people.user.updateInviterConnection': '400',
 'random.data.get': 'not-authorized',
 'safe.add.to.safe.file': '400',
 'safe.bulk.delete': '400',
 'safe.copy.file': '400',
 'safe.favorites.mark': '400',
 'safe.favorites.unmark': '400',
 'safe.folder.copy': '400',
 'safe.folder.create': '400',
 'safe.folder.create_many': '400',
 'safe.folder.get': '400',
 'safe.folder.get.content': '400',
 'safe.folder.get.keys': '400',
 'safe.folder.get.nestedItemsAmountAndSize': '400',
 'safe.folder.get.size': '400',
 'safe.folder.rename': '400',
 'safe.folder.update.copied': '400',
 'safe.folder.update.eLastModified': '400',
 'safe.get.ancestors_with_keys': '400',
 'safe.get.files': '400',
 'safe.get.files_metas': '400',
 'safe.get.files_with_rights': '400',
 'safe.get.folders': '400',
 'safe.get.folders_with_rights': '400',
 'safe.get.object': '400',
 'safe.get.object_with_rights': '400',
 'safe.get.safe_iems_with_rights': "{'message': 'Match error: Expected object, "
                                   "got undefined', 'path': '', "
                                   "'sanitizedError': {'isClientSafe': True, "
                                   "'error': 400, 'reason': 'Match failed', "
                                   "'message': 'Match failed [400]', "
                                   "'errorType': 'Meteor.Error'}, 'errorType': "
                                   "'Match.Error'}",
 'safe.get.safe_links': '400',
 'safe.get.shared_file': '400',
 'safe.get.thumbnails128': '400',
 'safe.get.users_with_access': '400',
 'safe.get.users_with_access_to_safe_items': '400',
 'safe.move': "{'isClientSafe': True, 'message': '[undefined]', 'errorType': "
              "'Meteor.Error'}",
 'safe.rights.collect': '400',
 'safe.rights.get_for_many': '400',
 'safe.rights.revoke.for_file': '404',
 'safe.rights.revoke.for_folder': '404',
 'safe.rights.revoke.for_link': '404',
 'safe.rights.revokeAccess': '400',
 'safe.safeLinks.create': '400',
 'safe.safeLinks.rename': 'not-authorized',
 'safe.safeLinks.updateCopied': '400',
 'safe.update.file.meta': '400',
 'safe.update.file.thumbnail128': '400',
 'safe.update.files.updateCopied': '400',
 'safe.upload.encryptedChunks': 'not-authorized',
 'safe.upload.publicFile': '400'}

WITHOUT ERRORS:
{'auth.addOnesignalId': "{'msg': 'result', 'id': '34678'}",
 'auth.getBackendVersion': "{'msg': 'result', 'id': '86849', 'result': 8}",
 'auth.removeOnesignalId': "{'msg': 'result', 'id': '84502'}",
 'auth.verifyAuthCode': "{'msg': 'result', 'id': '26819'}",
 'blockchain.newCertificate': "{'msg': 'result', 'id': '9377'}",
 'email.confirm': "{'msg': 'result', 'id': '38718'}",
 'messages.newChannel': "{'msg': 'result', 'id': '45964'}",
 'notifications.channels.state.set': "{'msg': 'result', 'id': '71368'}",
 'notifications.get': "{'msg': 'result', 'id': '72994'}",
 'notifications.set': "{'msg': 'result', 'id': '64809'}",
 'pushNotifications.ids.remove': "{'msg': 'result', 'id': '18727'}",
 'pushNotifications.ids.upsert': "{'msg': 'result', 'id': '22762'}",
 'safe.rights.check_one': "{'msg': 'result', 'id': '78562'}",
 'userConnections.status.set': "{'msg': 'result', 'id': '32899'}"}

BY TYPE
{'Internal server error [500]': ['people.removeUserAvatar',
                                 'calls.initiate',
                                 'calls.dropCall'],
 'Match failed [400]': ['email.requestConfirmationLink',
                        'auth.requestLoginAuthCode',
                        'auth.checkSignedCode',
                        'auth.checkAccessKey',
                        'auth.generateToken',
                        'auth.removeToken',
                        'people.getUserById',
                        'people.getUsersById',
                        'people.getUserProfileByPublicKey',
                        'people.getUserByEmailHash',
                        'people.addToContacts',
                        'people.approve',
                        'people.refuse',
                        'people.cancel',
                        'people.connectWithInviter',
                        'people.search',
                        'people.get20FromAllUsers',
                        'people.user.setDiscoverVisibility',
                        'people.user.editProfile',
                        'people.user.setSettings',
                        'people.user.addNotificationsData',
                        'people.user.getByPID',
                        'people.user.getByInvitation',
                        'people.user.getInviterToConnect',
                        'people.user.updateInviterConnection',
                        'messages.send',
                        'messages.edit',
                        'messages.sendWithAttachments',
                        'messages.editWithAttachments',
                        'messages.deleteWithAttachments',
                        'messages.getMessagesViaIdsList',
                        'messages.read',
                        'messages.voiceMessage.listen',
                        'messages.channels.get',
                        'messages.changeChannelInfo',
                        'messages.addToChannel',
                        'messages.leaveChannel',
                        'messages.deleteChannel',
                        'messages.removeFromChannel',
                        'channel.removeAvatar',
                        'messages.channel.getShared',
                        'messages.addToChannel.v2',
                        'messages.removeFromChannel.v2',
                        'messages.leaveChannel.v2',
                        'messages.drafts.upsert',
                        'messages.drafts.upsertMany',
                        'messages.drafts.delete',
                        'messages.drafts.deleteMany',
                        'messages.drafts.updateDevicesCount',
                        'safe.copy.file',
                        'safe.upload.publicFile',
                        'safe.update.file.meta',
                        'safe.update.file.thumbnail128',
                        'safe.update.files.updateCopied',
                        'safe.add.to.safe.file',
                        'safe.get.object',
                        'safe.get.object_with_rights',
                        'safe.get.users_with_access',
                        'safe.get.users_with_access_to_safe_items',
                        'safe.get.folders',
                        'safe.get.folders_with_rights',
                        'safe.get.ancestors_with_keys',
                        'safe.get.files',
                        'safe.get.files_metas',
                        'safe.get.files_with_rights',
                        'safe.get.shared_file',
                        'safe.get.thumbnails128',
                        'safe.get.safe_links',
                        'safe.bulk.delete',
                        'safe.folder.copy',
                        'safe.folder.create',
                        'safe.folder.create_many',
                        'safe.folder.rename',
                        'safe.folder.get',
                        'safe.folder.get.keys',
                        'safe.folder.update.copied',
                        'safe.folder.update.eLastModified',
                        'safe.folder.get.content',
                        'safe.folder.get.nestedItemsAmountAndSize',
                        'safe.folder.get.size',
                        'safe.safeLinks.create',
                        'safe.safeLinks.updateCopied',
                        'safe.rights.collect',
                        'safe.rights.get_for_many',
                        'safe.rights.revokeAccess',
                        'safe.favorites.mark',
                        'safe.favorites.unmark',
                        'externalLinks.internal.create',
                        'externalLinks.internal.getForOwner',
                        'externalLinks.internal.remove',
                        'externalLinks.internal.update',
                        'externalLinks.external.getBasicInfo',
                        'externalLinks.external.open',
                        'externalLinks.external.getFolderContent',
                        'notifications.v2.get',
                        'notifications.update',
                        'notifications.remove',
                        'notifications.create.many',
                        'PersonalInvitationCode.sendEmails'],
 "Method 'people.user.removeAvatar' not found [404]": ['people.user.removeAvatar'],
 "Method 'safe.rights.revoke.for_file' not found [404]": ['safe.rights.revoke.for_file'],
 "Method 'safe.rights.revoke.for_folder' not found [404]": ['safe.rights.revoke.for_folder'],
 "Method 'safe.rights.revoke.for_link' not found [404]": ['safe.rights.revoke.for_link'],
 'You should be authorized in app [not-authorized]': ['auth.requestAccountDeletion',
                                                      'people.user.getSettings',
                                                      'people.user.lock',
                                                      'people.user.unlock',
                                                      'people.user.generateNewPID',
                                                      'people.user.cleanRemovedChannels',
                                                      'calls.checkCallsInQueue',
                                                      'messages.delete',
                                                      'messages.channel.getKMessagesChunk',
                                                      'safe.upload.encryptedChunks',
                                                      'safe.safeLinks.rename',
                                                      'random.data.get',
                                                      'PersonalInvitationCode.create'],
 '[Error: Match error: Expected object, got undefined]': ['safe.get.safe_iems_with_rights'],
 '[You should be authorized in app [not-authorized]]': ['people.user.getStorageSize'],
 '[undefined]': ['safe.move']}

"""

"""
{'PersonalInvitationCode.create': None,
 'PersonalInvitationCode.sendEmails': [{'customMessage': None,
                                        'emailsList': None}],
 'auth.addOnesignalId': [{'devicePushId': None}],
 'auth.checkAccessKey': None,
 'auth.checkSignedCode': [{'code': None,
                           'emailHash': None,
                           'signedCode': None}],
 'auth.generateToken': None,
 'auth.getBackendVersion': None,
 'auth.removeOnesignalId': [{'devicePushId': None}],
 'auth.removeToken': None,
 'auth.requestAccountDeletion': None,
 'auth.requestLoginAuthCode': None,
 'auth.verifyAuthCode': None,
 'blockchain.newCertificate': None,
 'calls.checkCallsInQueue': None,
 'calls.dropCall': None,
 'calls.initiate': None,
 'channel.removeAvatar': None,
 'email.confirm': [{'confirmationCode': None}],
 'email.requestConfirmationLink': [{'email': None}],
 'externalLinks.external.getBasicInfo': None,
 'externalLinks.external.getFolderContent': [{'externalLinkId': None,
                                              'folderId': None}],
 'externalLinks.external.open': [{'externalLinkId': None,
                                  'openStats': None,
                                  'randomDataId': None,
                                  'signedData': None}],
 'externalLinks.internal.create': [{'externalLink': None, 'isFolder': None}],
 'externalLinks.internal.getForOwner': [{'externalLinkId': None}],
 'externalLinks.internal.remove': [{'externalLinkId': None, 'isFolder': None}],
 'externalLinks.internal.update': [{'': None,
                                    'changedFields': None,
                                    'externalLinkId': None,
                                    'isExpirationDateRemove = false': None,
                                    'isFolder': None,
                                    'isPasswordRemove = false': None}],
 'messages.addToChannel': None,
 'messages.addToChannel.v2': None,
 'messages.changeChannelInfo': [{'avatarInfo': None,
                                 'channelId': None,
                                 'eDescription': None,
                                 'eName': None}],
 'messages.channel.getKMessagesChunk': [{'chatId': None, 'step': None}],
 'messages.channel.getShared': [{'channelId': None,
                                 'fieldsProjection': None,
                                 'step = 0': None,
                                 'types': None}],
 'messages.channels.get': [{'eChannelsIds': None}],
 'messages.delete': [{'messageId': None}],
 'messages.deleteChannel': [{'channelId': None}],
 'messages.deleteWithAttachments': [{'messageId': None}],
 'messages.drafts.delete': [{'draftId': None, 'eTimestamp': None}],
 'messages.drafts.deleteMany': [{'draftsPayloadArray': None}],
 'messages.drafts.updateDevicesCount': [{'_id': None,
                                         'isDecrement = false': None}],
 'messages.drafts.upsert': [{'eDraft': None, 'oldDraftId': None}],
 'messages.drafts.upsertMany': [{'draftsToInsertPayload': None,
                                 'draftsToUpdatePayload': None}],
 'messages.edit': [{'eMessage': None}],
 'messages.editWithAttachments': [{'eMessage': None,
                                   'eMessageAttachmentsInfo': None}],
 'messages.getMessagesViaIdsList': [{'eMessagesIds': None,
                                     'fieldsProjection': None}],
 'messages.leaveChannel': [{'channelId': None}],
 'messages.leaveChannel.v2': [{'...leavePayload': None,
                               'eSystemMessagesData': None}],
 'messages.newChannel': [{'channelInfo': None, 'creatorId = false': None}],
 'messages.read': [{'eMessagesIds': None}],
 'messages.removeFromChannel': [{'channelId': None, 'userId': None}],
 'messages.removeFromChannel.v2': [{'...removePayload': None,
                                    'eSystemMessagesData': None}],
 'messages.send': [{'payloadForSharing': None}],
 'messages.sendWithAttachments': None,
 'messages.voiceMessage.listen': [{'eMessageId': None}],
 'notifications.channels.state.set': [{'channelId': None, 'state': None}],
 'notifications.create.many': [{'notifications': None}],
 'notifications.get': None,
 'notifications.remove': [{'notificationsIds': None}],
 'notifications.set': None,
 'notifications.update': [{'_id': None,
                           'currentRevision': None,
                           'eLastReadNumber': None,
                           'eLastReadNumberNonce': None}],
 'notifications.v2.get': None,
 'people.addToContacts': None,
 'people.approve': [{'channelInfo': None,
                     'eCreated': None,
                     'eSSK': None,
                     'nonceSSK': None,
                     'userToAddID': None}],
 'people.cancel': None,
 'people.connectWithInviter': [{'': None,
                                'invitationCode': None,
                                'userToAddID': None}],
 'people.get20FromAllUsers': [{'padding': None}],
 'people.getUserByEmailHash': [{'emailHash': None}],
 'people.getUserById': [{'userId': None}],
 'people.getUserProfileByPublicKey': [{'userECDHPK': None}],
 'people.getUsersById': [{'usersIds': None}],
 'people.refuse': None,
 'people.removeUserAvatar': None,
 'people.search': [{'stringToSearch': None}],
 'people.user.addNotificationsData': None,
 'people.user.cleanRemovedChannels': None,
 'people.user.editProfile': [{'profileUpdates': None}],
 'people.user.generateNewPID': None,
 'people.user.getByInvitation': [{'invitationCode': None}],
 'people.user.getByPID': [{'PID': None}],
 'people.user.getInviterToConnect': [{'invitationCode': None}],
 'people.user.getSettings': None,
 'people.user.getStorageSize': None,
 'people.user.lock': None,
 'people.user.removeAvatar': None,
 'people.user.setDiscoverVisibility': [{'isVisible': None}],
 'people.user.setSettings': [{'eECDHSK': None, 'eSettings': None}],
 'people.user.unlock': None,
 'people.user.updateInviterConnection': [{'eSSK': None,
                                          'invitedUserId': None,
                                          'nonceSSK': None}],
 'pushNotifications.ids.remove': [{'deviceUUID': None}],
 'pushNotifications.ids.upsert': [{'appBundleId': None,
                                   'deviceUUID': None,
                                   'oneSignalId': None,
                                   'oneSignalVoipId': None}],
 'random.data.get': None,
 'safe.add.to.safe.file': [{'_id': None,
                            'eByFolderECDHSK': None,
                            'isFolder': None,
                            'parentFolderELastModified': None,
                            'parentFolderId': None}],
 'safe.bulk.delete': [{'newETimeForParentFolder': None,
                       'parentFolderId': None}],
 'safe.copy.file': [{'destinationFolderId': None,
                     'eByFolderECDHSK': None,
                     'eByUserECDHSK': None,
                     'eMeta': None,
                     'eTimestamp': None,
                     'fileId': None,
                     'newFileId': None}],
 'safe.favorites.mark': [{'safeItemsToMark': None}],
 'safe.favorites.unmark': [{'idsToUnmark': None}],
 'safe.folder.copy': [{'': None,
                       'destinationFolderId': None,
                       'eByFolderECDHSK': None,
                       'eName': None,
                       'folderToCopyId': None,
                       'newFolderId': None}],
 'safe.folder.create': [{'folderData': None,
                         'parentFolderELastModified': None}],
 'safe.folder.create_many': None,
 'safe.folder.get': [{'folderId': None}],
 'safe.folder.get.content': [{'externalLinkId': None, 'folderId': None}],
 'safe.folder.get.keys': None,
 'safe.folder.get.nestedItemsAmountAndSize': [{'folderId': None}],
 'safe.folder.get.size': [{'folderId': None}],
 'safe.folder.rename': [{'eName': None, 'id': None}],
 'safe.folder.update.copied': [{'copiedFoldersInfo': None}],
 'safe.folder.update.eLastModified': [{'folderId': None,
                                       'newFolderELastModified': None}],
 'safe.get.ancestors_with_keys': [{'isFolder = false': None,
                                   'isLink = false': None,
                                   'safeItemId': None}],
 'safe.get.files': [{'fieldsProjection': None, 'filesIds': None}],
 'safe.get.files_metas': [{'filesIds': None}],
 'safe.get.files_with_rights': [{'filesIds': None}],
 'safe.get.folders': [{'foldersIds': None}],
 'safe.get.folders_with_rights': [{'foldersIds': None}],
 'safe.get.object': [{'fileId': None}],
 'safe.get.object_with_rights': [{'itemId': None, 'userIdToCheckRights': None}],
 'safe.get.safe_iems_with_rights': [{'filesIds': None, 'foldersIds': None}],
 'safe.get.safe_links': [{'safeLinksIds': None}],
 'safe.get.shared_file': [{'withOriginal': None}],
 'safe.get.thumbnails128': [{'filesIds': None}],
 'safe.get.users_with_access': [{'isFolder = false': None,
                                 'isLink = false': None,
                                 'safeItemId': None}],
 'safe.get.users_with_access_to_safe_items': [{'': None,
                                               'filesIds = []': None,
                                               'foldersIds = []': None,
                                               'safeLinksIds = []': None}],
 'safe.move': [{'': None,
                'destinationFolderETime': None,
                'destinationFolderId': None,
                'movingSafeItems': None,
                'previousParentFolderETime': None}],
 'safe.rights.check_one': [{'item': None, 'right': None}],
 'safe.rights.collect': [{'itemId': None}],
 'safe.rights.get_for_many': None,
 'safe.rights.revoke.for_file': None,
 'safe.rights.revoke.for_folder': None,
 'safe.rights.revoke.for_link': None,
 'safe.rights.revokeAccess': [{'safeItemsIds': None, 'userIdToRevoke': None}],
 'safe.safeLinks.create': [{'parentFolderELastModified': None,
                            'safeLinkData': None}],
 'safe.safeLinks.rename': [{'eName': None, 'id': None}],
 'safe.safeLinks.updateCopied': [{'copiedShortcutsInfo': None}],
 'safe.update.file.meta': [{'eMeta': None, 'fileId': None}],
 'safe.update.file.thumbnail128': [{'fileId': None}],
 'safe.update.files.updateCopied': [{'copiedFilesInfo': None}],
 'safe.upload.encryptedChunks': [{'': None,
                                  'ECDSAPK': None,
                                  'MIMEtype': None,
                                  '_id': None,
                                  'eByFolderECDHSK': None,
                                  'eECDHSK': None,
                                  'eMeta': None,
                                  'isFolderUpload': None,
                                  'isPublic': None,
                                  'originalDimensions': None,
                                  'parentFolderId': None,
                                  'previewDimensions': None,
                                  'size': None,
                                  'uploadedForSharing': None,
                                  'withPreview': None,
                                  'withThumbnails': None}],
 'safe.upload.publicFile': [{'generalFileInfo': None, 'imageInfo': None}],
 'userConnections.status.set': None}

routes = {
	"AUTH": {
		"REQUEST_SIGNUP_EMAIL_CONFIRMATION": 'email.requestConfirmationLink',
		"VERIFY_SIGNUP_CONFIRMATION_CODE": 'email.confirm',
		"REQUEST_ACCOUNT_DELETION": 'auth.requestAccountDeletion',
		"REQUEST_LOGIN_AUTH_CODE": 'auth.requestLoginAuthCode',
		"CONFIRM_SIGNED_2FA": 'auth.checkSignedCode',
		"VERIFY_AUTH_CODE": 'auth.verifyAuthCode',
		"ONESIGNAL": {
			"REGISTER_TOKEN": 'auth.addOnesignalId',
			"REMOVE_TOKEN": 'auth.removeOnesignalId',
		},
		"CHECK_ACCESS_KEY": 'auth.checkAccessKey',
		"GET_BACKEND_VERSION": 'auth.getBackendVersion',
		"GENERATE_TOKEN": 'auth.generateToken',
		"REMOVE_TOKEN": 'auth.removeToken',
	},
	"PEOPLE": {
		"GET_USER_BY_ID": 'people.getUserById',
		"GET_USERS_BY_ID": 'people.getUsersById',
		"GET_USER_BY_PK": 'people.getUserProfileByPublicKey',
		"GET_USER_BY_EMAIL_HASH": 'people.getUserByEmailHash',
		"ADD_USER_TO_CONTACTS": 'people.addToContacts',
		"APPROVE_CONTACT": 'people.approve',
		"REFUSE_REQUEST": 'people.refuse',
		"CANCEL_REQUEST": 'people.cancel',
		"CONNECT_WITH_INVITER": 'people.connectWithInviter',
		"SEARCH": 'people.search',
		"DISCOVER_TWENTY": 'people.get20FromAllUsers',
		"REMOVE_AVATAR": 'people.removeUserAvatar',
		"USER": {
			"REMOVE_AVATAR": 'people.user.removeAvatar',
			"SET_DISCOVER_VISIBILITY": 'people.user.setDiscoverVisibility',
			"EDIT_PROFILE": 'people.user.editProfile',
			"SET_SETTINGS": 'people.user.setSettings',
			"GET_SETTINGS": 'people.user.getSettings',
			"ADD_NOTIFICATIONS_DATA": 'people.user.addNotificationsData',
			"LOCK_USER": 'people.user.lock',
			"UNLOCK_USER": 'people.user.unlock',
			"GET_BY_PID": 'people.user.getByPID',
			"GET_STORAGE_SIZE": 'people.user.getStorageSize',
			"GENERATE_NEW_PID": 'people.user.generateNewPID',
			"GET_USER_BY_INVITATION": 'people.user.getByInvitation',
			"GET_INVITER_TO_CONNECT": 'people.user.getInviterToConnect',
			"UPDATE_INVITER_CONNECTION": 'people.user.updateInviterConnection',
			"CLEAN_REMOVED_CHANNELS": 'people.user.cleanRemovedChannels',
		},
	},
	"CALLS": {
		"RETRANSMIT": 'calls.initiate',
		"DROP_CALL": 'calls.dropCall',
		"CHECK_CALLS_IN_QUEUE": 'calls.checkCallsInQueue',
	},
	"MESSAGES": {
		"SEND": 'messages.send',
		"EDIT": 'messages.edit',
		"DELETE": 'messages.delete',
		"SEND_WITH_ATTACHMENTS": 'messages.sendWithAttachments',
		"EDIT_WITH_ATTACHMENTS": 'messages.editWithAttachments',
		"DELETE_WITH_ATTACHMENTS": 'messages.deleteWithAttachments',
		"GET_MESSAGES": 'messages.getMessagesViaIdsList',
		"READ": 'messages.read',
		"VOICE_MESSAGE": {
			"LISTEN": 'messages.voiceMessage.listen',
		},
		"CHANNEL": {
			"GET": 'messages.channels.get',
			"CREATE": 'messages.newChannel',
			"EDIT_INFO": 'messages.changeChannelInfo',
			"ADD_USER": 'messages.addToChannel',
			"LEAVE": 'messages.leaveChannel',
			"DELETE": 'messages.deleteChannel',
			"REMOVE_USER": 'messages.removeFromChannel',
			"REMOVE_AVATAR": 'channel.removeAvatar',
			"GET_SHARED": 'messages.channel.getShared',
			"GET_CHUNK": 'messages.channel.getKMessagesChunk',
			"V2": {
				"ADD_USER": 'messages.addToChannel.v2',
				"REMOVE_USER": 'messages.removeFromChannel.v2',
				"LEAVE": 'messages.leaveChannel.v2',
			},
		},
		"DRAFTS": {
			"UPSERT": 'messages.drafts.upsert',
			"UPSERT_MANY": 'messages.drafts.upsertMany',
			"DELETE": 'messages.drafts.delete',
			"DELETE_MANY": 'messages.drafts.deleteMany',
			"UPDATE_DEVICES_COUNT": 'messages.drafts.updateDevicesCount',
		},
	},
	"SAFE": {
		"MOVE": {
			"SAFE_ITEMS": 'safe.move',
		},
		"COPY": {
			"FILE": 'safe.copy.file',
		},
		"UPLOAD": {
			"PUBLIC_FILE": 'safe.upload.publicFile',
			"ENCRYPTED_CHUNKS": 'safe.upload.encryptedChunks',
		},
		"UPDATE": {
			"FILE": {
				"META": 'safe.update.file.meta',
				"THUMBNAIL128": 'safe.update.file.thumbnail128',
			},
			"FILES": {
				"COPIED": 'safe.update.files.updateCopied',
			},
		},
		"ADD_TO_SAFE": {
			"FILE": 'safe.add.to.safe.file',
		},
		"GET": {
			"OBJECT": 'safe.get.object',
			"OBJECT_WITH_RIGHTS": 'safe.get.object_with_rights',
			"USERS_WITH_ACCESS": 'safe.get.users_with_access',
			"USERS_WITH_ACCESS_TO_SAFE_ITEMS": 'safe.get.users_with_access_to_safe_items',

			"FOLDERS": 'safe.get.folders',
			"FOLDERS_WITH_RIGHTS": 'safe.get.folders_with_rights',
			"ALL_ANCESTORS_KEYS": 'safe.get.ancestors_with_keys',

			"FILES": 'safe.get.files',
			"FILES_METAS": 'safe.get.files_metas',
			"FILES_WITH_RIGHTS": 'safe.get.files_with_rights',
			"SHARED_FILE": 'safe.get.shared_file',
			"THUMBNAILS_128": 'safe.get.thumbnails128',

			"SAFE_LINKS": 'safe.get.safe_links',

			"SAFE_ITEMS_WITH_RIGHTS": 'safe.get.safe_iems_with_rights',
		},
		"BULK": {
			"DELETE": 'safe.bulk.delete',
		},
		"FOLDER": {
			"COPY": 'safe.folder.copy',
			"CREATE": 'safe.folder.create',
			"CREATE_MANY": 'safe.folder.create_many',
			"RENAME": 'safe.folder.rename',
			"GET": 'safe.folder.get',
			"GET_KEYS": 'safe.folder.get.keys',
			"UPDATE_COPIED": 'safe.folder.update.copied',
			"UPDATE_E_LAST_MODIFIED": 'safe.folder.update.eLastModified',
			"GET_CONTENT": 'safe.folder.get.content',
			"GET_NESTED_ITEMS_AMOUNT_AND_SIZE": 'safe.folder.get.nestedItemsAmountAndSize',
			"GET_SIZE": 'safe.folder.get.size',
		},
		"SAFE_LINKS": {
			"CREATE": 'safe.safeLinks.create',
			"RENAME": 'safe.safeLinks.rename',
			"UPDATE_COPIED": 'safe.safeLinks.updateCopied',
		},
		"RIGHTS": {
			"CHECK_ONE": 'safe.rights.check_one',
			"COLLECT": 'safe.rights.collect',
			"GET_FOR_MANY": 'safe.rights.get_for_many',
			"REVOKE": {
				"FOR_FILE": 'safe.rights.revoke.for_file',
				"FOR_FOLDER": 'safe.rights.revoke.for_folder',
				"FOR_LINK": 'safe.rights.revoke.for_link',
			},
			"REVOKE_ACCESS": 'safe.rights.revokeAccess',
		},
		"FAVORITES": {
			"MARK": 'safe.favorites.mark',
			"UNMARK": 'safe.favorites.unmark',
		},
	},
	"EXTERNAL_LINKS": {
		"INTERNAL": {
			"CREATE": 'externalLinks.internal.create',
			"GET_FOR_OWNER": 'externalLinks.internal.getForOwner',
			"REMOVE": 'externalLinks.internal.remove',
			"UPDATE": 'externalLinks.internal.update',
		},
		"EXTERNAL": {
			"GET_BASIC_INFO": 'externalLinks.external.getBasicInfo',
			"OPEN": 'externalLinks.external.open',
			"GET_FOLDER_CONTENT": 'externalLinks.external.getFolderContent',
		},
	},
	"NOTIFICATIONS": {
		"GET": 'notifications.get',
		"SET": 'notifications.set',
		"CHANNELS": {
			"STATE": {
				"SET": 'notifications.channels.state.set',
			},
		},
		"V2": {
			"GET": 'notifications.v2.get',
			"UPDATE": 'notifications.update',
			"REMOVE": 'notifications.remove',
			"CREATE_MANY": 'notifications.create.many',
		},
	},
	"BLOCKCHAIN": {
		"CREATE_CERTIFICATE": 'blockchain.newCertificate',
	},
	"RANDOM_DATA": {
		"GET": 'random.data.get',
	},
	"PERSONAL_INVITATION_CODE": {
		"CREATE": 'PersonalInvitationCode.create',
		"SEND_EMAILS": 'PersonalInvitationCode.sendEmails',
	},
	"PUSH_NOTIFICATIONS": {
		"IDS": {
			"UPSERT": 'pushNotifications.ids.upsert',
			"REMOVE": 'pushNotifications.ids.remove',
		},
	},
	"USER_CONNECTIONS": {
		"SET_USER_CONNECTION_STATUS": 'userConnections.status.set',
	},
}

"""
