from client import ShareKeyClient, Folder, File
from credentials import URL, EMAIL, METEOR_TOKEN, KEYRING
from pprint import pprint
import json
import base64


def choose(options, title):
    print()
    print(f"{title}:")
    for i, (name, option) in enumerate(options):
        print(f"{i:>3}: {name}")

    while True:
        try:
            n = int(input())

            if n < 0 or n >= len(options):
                raise ValueError("Index out of range")
            return options[n][1]
        except Exception as e:
            print(e)


def choose_channel(channels, contacts, id):
    contact_map = {
        contact["id"]: contact["fields"]["profile"]["names"] for contact in contacts
    }
    direct = [channel for channel in channels if channel["fields"]["isDirect"]]
    group = [channel for channel in channels if not channel["fields"]["isDirect"]]

    options = []
    for channel in direct:
        other_ids = [k for k in channel["fields"]["participants"] if k != id]
        if len(other_ids) != 1:
            pprint(other_ids, id)
            raise ValueError("Too many ids")
        other_id = other_ids[0]
        options.append((f"[D]: {contact_map[other_id]}", channel))

    for i, channel in enumerate(group):
        try:
            other_ids = [k for k in channel["fields"]["participants"] if k != id]
            names = ", ".join(
                contact_map[k] for k in channel["fields"]["participants"] if k != id
            )
        except Exception:
            names = "?"
        options.append(
            (f"[G]: {channel['fields']['eName'].decode()} ({names})", channel)
        )

    return choose(options, "Choose a Channel")


def choose_message(messages, contacts):
    contact_map = {
        contact["id"]: contact["fields"]["profile"]["names"] for contact in contacts
    }

    def get_timestamp(message):
        try:
            return int(message["fields"]["eTimestamp"].decode())
        except Exception:
            return 0

    if len(messages) == 0:
        return None

    messages.sort(key=get_timestamp)

    options = []
    for message in messages:
        if "eContent" in message["fields"] and not (
            "isDeleted" in message["fields"] and message["fields"]["isDeleted"]
        ):
            # text = message["fields"]["eContent"]["eText"]
            try:
                data = json.loads(message["fields"]["eContent"]["eText"])
                if "text" in data:
                    text = data["text"]
                else:
                    text = str(data)
            except:
                text = message["fields"]["eContent"]["eText"]
        else:
            text = "<deleted>"
        if message["fields"]["sender"] in contact_map:
            sender = contact_map[message["fields"]["sender"]]
        else:
            sender = "You"
        options.append((f"{sender} ({message['id']})\n\t{text}", message))

    return choose(options, "Choose a Message")


def edit_message():
    with ShareKeyClient(url=URL) as sharekey:
        sharekey.login_keyring(EMAIL, METEOR_TOKEN, KEYRING)

        # Fetch contacts
        contacts = sharekey.get_user_contacts()

        # Fetch channels
        channels = sharekey.get_user_channels()
        channel = choose_channel(channels, contacts, sharekey.id)

        # Fetch messages
        messages = sharekey.get_messages(channel)
        message = choose_message(messages, contacts)

        new_text = input("Please enter the new message text:\n")
        pprint(
            sharekey.edit_message(
                message,
                channel,
                {"text": new_text},
            )
        )


def view_message():
    with ShareKeyClient(url=URL) as sharekey:
        sharekey.login_keyring(EMAIL, METEOR_TOKEN, KEYRING)

        # Fetch contacts
        contacts = sharekey.get_user_contacts()

        contact_map = {contact["id"]: contact for contact in contacts}

        # Fetch channels
        channels = sharekey.get_user_channels()
        channel = choose_channel(channels, contacts, sharekey.id)

        # Fetch messages
        messages_enc = sharekey.skws.sub("messages.getForChannel", channel["id"], 100)
        messages = [
            sharekey.decrypt_all(json.loads(json.dumps(message)), channel["key"])
            for message in messages_enc
        ]

        message = choose_message(messages, contacts)

        info = {
            "channel": channel["key"],
            "participants": [
                contact_map[p] if p in contact_map else p
                for p in channel["fields"]["participants"]
            ],
            "messages": [],
        }

        for m in messages_enc:
            if m["id"] == message["id"]:
                info["messages"].append({"encrypted": m, "plaintext": message})
        pprint(info)


def delete_message():
    with ShareKeyClient(url=URL) as sharekey:
        sharekey.login_keyring(EMAIL, METEOR_TOKEN, KEYRING)

        # Fetch contacts
        contacts = sharekey.get_user_contacts()

        # Fetch channels
        channels = sharekey.get_user_channels()
        channel = choose_channel(channels, contacts, sharekey.id)

        # Fetch messages
        messages = sharekey.get_messages(channel)
        message = choose_message(messages, contacts)

        pprint(sharekey.delete_message(message))


def break_app():
    with ShareKeyClient(url=URL) as sharekey:
        sharekey.login_keyring(EMAIL, METEOR_TOKEN, KEYRING)

        # Fetch contacts
        contacts = sharekey.get_user_contacts()

        # Fetch channels
        channels = sharekey.get_user_channels()
        channel = choose_channel(channels, contacts, sharekey.id)

        pprint(sharekey.send_message(channel, {"break": "app"}))


def email_info():
    with ShareKeyClient(url=URL) as sharekey:
        email = input("Please enter an e-mail address:\n")
        info = sharekey.get_user_by_email(email)
        if info is None:
            print("User not in database")
        else:
            pprint(info)


def is_shared(message):
    try:
        data = json.loads(message["fields"]["eContent"]["eText"])
        if "folders" in data or "files" in data:
            return True
    except Exception as e:
        print(e)
    return False


def recover_file_tree():
    with ShareKeyClient(url=URL) as sharekey:
        sharekey.login_keyring(EMAIL, METEOR_TOKEN, KEYRING)

        # Fetch contacts
        contacts = sharekey.contacts
        contact_map = {
            contact["id"]: contact["fields"]["profile"]["names"] for contact in contacts
        }

        roots = {}

        # Fetch channels
        channels = sharekey.get_user_channels()
        for channel in channels:
            for message in sharekey.get_messages(channel):
                if is_shared(message):
                    data = json.loads(message["fields"]["eContent"]["eText"])
                    if "folders" in data:
                        for folder_data in data["folders"]:
                            folder = Folder.from_id(
                                sharekey,
                                folder_data["_id"],
                                encrypt_sk=base64.b64decode(
                                    folder_data["ECDHSK"]["$binary"]
                                ),
                            )
                            while folder.parent is not None:
                                folder = folder.parent

                            if folder.owner() not in roots:
                                roots[folder.owner()] = set()
                            roots[folder.owner()].add(folder)

                    if "files" in data:
                        for file_data in data["files"]:
                            folder = File.from_id(
                                sharekey,
                                file_data["_id"],
                                encrypt_sk=base64.b64decode(
                                    file_data["ECDHSK"]["$binary"]
                                ),
                            )
                            while folder.parent is not None:
                                folder = folder.parent

                            if folder.owner() not in roots:
                                roots[folder.owner()] = set()
                            roots[folder.owner()].add(folder)

        for owner, items in roots.items():
            if owner in contact_map:
                owner = contact_map[owner]
            elif owner == sharekey.id:
                owner = "You"

            print(f"Directories owned by {owner}:")
            for item in items:
                print(item)
            print()


if __name__ == "__main__":
    functions = [
        ("View Message Details", view_message),
        ("Edit a Message", edit_message),
        ("Delete a Message", delete_message),
        ("Email Info", email_info),
        ("Break app", break_app),
        ("Recover File Tree", recover_file_tree),
        ("Quit", None),
    ]

    while True:
        f = choose(functions, "Choose a function")
        if f is None:
            break
        f()
