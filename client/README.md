# Python Client
This is a python client used to test different aspects of the sharekey protocol

## Setup
Install [python-tweetnacl](https://github.com/warner/python-tweetnacl) (not in pip unfortunately, but uses exactly same crypto as library used with sharekey)

Create a file called `credentials.py` which contains the following fields:
```python
URL = "XXX" # The URL to the websocket used by the application
EMAIL = "XXX" # Your Email Address
METEOR_TOKEN = "XXX" # Meteor.loginToken from localStorage
KEYRING = { # eMainKeyRing from localStorage
    "ECDHPK":{"$binary":"XXX"},
    "ECDHSK":{"$binary":"XXX"},
    "ECDSASK":{"$binary":"XXX"},
    "ECDSAPK":{"$binary":"XXX"},
    "passphrase":"XXX"
}
```
- `URL`: This value can be found by entering the developer tools and checking the URL for the websocket connection in the Network tab. For example:
  - Local deployment: `ws://localhost:3000/sockjs/151/o6amzvso/websocket`
  - Production: `wss://app.sharekey.com/sockjs/866/uryj_3m7/websocket`
- `EMAIL`: The email used to sign up to sharekey
- `METEOR_TOKEN`: Token used to resume meteor session, can be found in browser's local storage with key `Meteor.loginToken`. This value changes over time and currently has to be kept up-to-date manually
- `KEYRING`: The decrypted keyring containing all of your keys, can be found in browser's local storage with key `eMainKeyRing`. Does not change over time, should be kept secret (Don't leak it on github, @pascscha)



## Functionality:
Run `python3 main.py` which gives you a basic CLI

### Examples:
#### Edit Message
```
$ python3 main.py         

Choose a function:
  0: Edit a Message
  1: Delete a Message
  2: Email Info
  3: Quit
0

Choose a Channel:
  0: [D]: Test2 Test2
  1: [G]: Test Channel (Test2 Test2)
1

Choose a Message:
  0: You (c57RwHoLPAataxqRWZysJq4W)
	Hi
  1: You (Pr3iCkp7Y2F5EXNastkzPEKS)
	1
  2: You (ou2Sug2KD5bANED2ZtDzFr22)
	2
  3: You (cwjubtW2D6XGRpJX82MXiDH9)
	3
  4: You (hAkXKDaMs8rtLMThEFfvHPgD)
	<deleted>
  5: You (XaBsTmvQuAeu5L2BqRgMtp4s)
	This is a test edit
  6: Test2 Test2 (h2MrsmLYjpCyBDgfKeYLh7C8)
	<deleted>
  7: You (KpE9mRjgRzCasbr847kN7mPC)
	new Message
7

Please enter the new message text:
This message was edited by my python script

{'data': {'message': 'successfully edited', 'status': 200},
 'updatedChannelId': 'qfguGkH326ZXPRC45'}
```

#### Delete Message
```
$ python3 main.py

Choose a function:
  0: Edit a Message
  1: Delete a Message
  2: Email Info
  3: Quit
1

Choose a Channel:
  0: [D]: Test2 Test2
  1: [G]: Test Channel (Test2 Test2)
1

Choose a Message:
  0: You (c57RwHoLPAataxqRWZysJq4W)
	Hi
  1: You (Pr3iCkp7Y2F5EXNastkzPEKS)
	1
  2: You (ou2Sug2KD5bANED2ZtDzFr22)
	2
  3: You (cwjubtW2D6XGRpJX82MXiDH9)
	3
  4: You (hAkXKDaMs8rtLMThEFfvHPgD)
	<deleted>
  5: You (XaBsTmvQuAeu5L2BqRgMtp4s)
	This is a test edit
  6: Test2 Test2 (h2MrsmLYjpCyBDgfKeYLh7C8)
	<deleted>	
  7: You (KpE9mRjgRzCasbr847kN7mPC)
	This message was edited by my python script
7
{'data': {'message': 'successfully deleted',
          'updatedChannelId': 'qfguGkH326ZXPRC45'},
 'status': 200}
```

#### Check if Email exists
```
$ python3 main.py

Choose a function:
  0: Edit a Message
  1: Delete a Message
  2: Email Info
  3: Quit
2
Please enter an e-mail address:
test3@pascscha.ch
{'PID': 'X48ZGRF8',
 '_id': 'DzyZoohzMLdwjFwv8',
 'profile': {'avatar': False,
             'crypto': {'ECDHPK': {'$binary': '6JOtbMu9cx7ADtoDCIj/in5aij3TxoXfsZTdSv0l/1o='},
                        'ECDSAEncryptedSecretKey': {'$binary': 'b4TFGLMHtmpJChzPeMYa3Wfd7U3h1PkC987c8nDnHt8ri2ihv6lGHV7Qy8Qahe9UmeeepjeVxULt9YxiXB/AQk5uhMppkMPCbKe0gAFxq3I='},
                        'ECDSAPK': {'$binary': 'LiCyot1NBbUINcEovR/cuAUgmKHGioGs7l8sWfCFJDQ='},
                        'encryptedEmail': {'$binary': '6UisUjjzan1CHFxJH8BPqcgggh4JJMrxCGTiKmlSFObiGFkOaTjeyBJH+Ra4AcdywIGG38TztRY17+ntp7SjgzSbMDVjsKGVuv6Qj0KTxR2Y8T1ddc2A8fCzH1bL8MB1VJ86xeuWw1k='},
                        'nonceECDSA': {'$binary': 'NvxCk9vfxmjFigVBnzsAM6frlatCfZKu'},
                        'nonceEmail': {'$binary': 'L0yfgt2PX2zeaabGzGb2mWXYnzZsPK9j'}},
             'firstName': 'Test3',
             'isPublic': False,
             'isSharekeyTeam': False,
             'isVerified': False,
             'lastName': 'Test3',
             'names': 'Test3 Test3'},
 'revision': 9}

Choose a function:
  0: Edit a Message
  1: Delete a Message
  2: Email Info
  3: Quit
2
Please enter an e-mail address:
thisEmailDoesNotExist@pascscha.ch
User not in database
```
