#!/usr/bin/env python

import json
import os.path
from time import time

from pysnap.utils import (encrypt, decrypt, decrypt_story,
                          make_media_id, request)

MEDIA_IMAGE = 0
MEDIA_VIDEO = 1
MEDIA_VIDEO_NOAUDIO = 2

FRIEND_CONFIRMED = 0
FRIEND_UNCONFIRMED = 1
FRIEND_BLOCKED = 2
PRIVACY_EVERYONE = 0
PRIVACY_FRIENDS = 1


def getKey(item):
    return item['sts']


def is_video(data):
    return len(data) > 1 and data[0:2] == b'\x00\x00'


def is_image(data):
    return len(data) > 1 and data[0:2] == b'\xFF\xD8'


def is_zip(data):
    return len(data) > 1 and data[0:2] == 'PK'


def get_file_extension(media_type):
    if media_type in (MEDIA_VIDEO, MEDIA_VIDEO_NOAUDIO):
        return 'mp4'
    if media_type == MEDIA_IMAGE:
        return 'jpg'
    return ''


def get_media_type(data):
    if is_video(data):
        return MEDIA_VIDEO
    if is_image(data):
        return MEDIA_IMAGE
    return None


def _map_keys(snaps):
    return {
        u'id': snaps.get('id', None),
        u'm': snaps.get('m', None),
        u'sn': snaps.get('sn', None),
        u'rp': snaps.get('rp', None),
        u'st': snaps.get('st', None),
        u'sts': snaps.get('sts', None),
        u't': snaps.get('t', None),
        u'timer': snaps.get('timer', None),
        u'ts': snaps.get('ts', None)
    }


class Snapchat(object):
    """Construct a :class:`Snapchat` object used for communicating
    with the Snapchat API.

    Usage:

        from pysnap import Snapchat
        snapchat = Snapchat()
        snapchat.login('username', 'password')
        ...

    """
    def __init__(self):
        self.username = None
        self.auth_token = None
        self.qr_path = None

    def auth_token_login(self, username, auth_token):
        """Login to Snapchat account with exsisting auth_token
        Returns a dict containing user information on successful login, the
        data returned is the same as get_updates.
        :param username Snapchat username
        :param password Snapchat password
        """
        self.auth_token = auth_token
        r = self._request('loq/all_updates', {
            'username': username,
            'timestamp': time() * 1000
        })
        result = r.json()
        if 'auth_token' in result['updates_response']:
            self.auth_token = result['updates_response']['auth_token']
            self.qr_path = result['updates_response']['qr_path']
        if 'username' in result['updates_response']:
            self.username = username.lower()
        return result

    def _request(self, endpoint, data=None, files=None,
                 raise_for_status=True, req_type='post'):
        return request(endpoint, self.auth_token, data, files,
                       raise_for_status, req_type)

    def _unset_auth(self):
        self.username = None
        self.auth_token = None

    def login(self, username, password):
        """Login to Snapchat account
        Returns a dict containing user information on successful login, the
        data returned is similar to get_updates.

        :param username Snapchat username
        :param password Snapchat password
        """
        self._unset_auth()
        r = self._request('loq/login', {
            'username': username.lower(),
            'password': password,
            'timestamp': time() * 1000,
            'features_map': "[all_updates_friends_response]=1"
        })
        result = r.json()
        if 'auth_token' in result['updates_response']:
            self.auth_token = result['updates_response']['auth_token']
        if 'qr_path' in result['updates_response']:
            self.qr_path = result['updates_response']['qr_path']
        if 'username' in result['updates_response']:
            self.username = username.lower()
        return result

    def logout(self):
        """Logout of Snapchat account
        Returns true if logout was successful.
        """
        r = self._request('ph/logout', {'username': self.username})
        return len(r.content) == 0

    def get_updates(self):
        """Get user, friend and snap updates
        Returns a dict containing user, friends and snap information.
        """
        r = self._request('/loq/all_updates', {
            'username': self.username,
            'timestamp': time() * 1000
        })
        result = r.json()
        if 'auth_token' in result['updates_response']:
            self.auth_token = result['updates_response']['auth_token']
            self.qr_path = result['updates_response']['qr_path']
        return result

    def get_snaps(self):
        """Get snaps
        Returns a dict containing metadata for snaps
        """
        allsnaps = []
        updates = self.get_updates()
        for convo in [convo for convo in updates['conversations_response']]:
            allsnaps += [_map_keys(snaps) for snaps in
                         convo.get('pending_received_snaps', None)]
        return sorted(allsnaps, key=getKey)

    def get_friend_stories(self):
        """Get stories
        Returns a dict containing metadata for stories
        """
        r = self._request("loq/all_updates", {
            'username': self.username,
            'timestamp': time() * 1000
        })
        result = r.json()
        if 'auth_token' in result['updates_response']:
            self.auth_token = result['updates_response']['auth_token']
        stories = []
        story_groups = result['stories_response']['friend_stories']
        for group in story_groups:
            sender = group['username']
            for story in group['stories']:
                obj = story['story']
                obj['sender'] = sender
                stories.append(obj)
        return stories

    def get_story_blob(self, story_id, story_key, story_iv):
        """Get the image or video of a given snap
        Returns the decrypted image or a video of the given snap or None if
        data is invalid.

        :param story_id: Media id to fetch
        :param story_key: Encryption key of the story
        :param story_iv: Encryption IV of the story
        """
        r = self._request('bq/story_blob', {'story_id': story_id},
                          raise_for_status=False, req_type='get')
        data = decrypt_story(r.content, story_key.decode('base64'),
                             story_iv.decode('base64'))
        if any((is_image(data), is_video(data), is_zip(data))):
            return data
        return None

    def get_chat_media(self, id, chatid, key, iv):
        """Get the image send over snapchat chat
        Returns the decrypted image of the given snap or None if
        data is invalid.

        :param id: Snap id from chat to fetch
        :param chatid: Conversation id that the snap id is from
        :param key: Encryption key of the image
        :param iv: Encyption IV of the image
        """
        r = self._request('bq/chat_media', {
            'id': id,
            'username': self.username,
            'timestamp': time() * 1000,
            'conversation_id': chatid
        })
        data = decrypt_story(r.content, key.decode('base64'),
                             iv.decode('base64'))
        if any((is_image(data), is_video(data), is_zip(data))):
            return data
        return None

    def get_blob(self, snap_id):
        """Get the image or video of a given snap
        Returns the decrypted image or a video of the given snap or None if
        data is invalid.

        :param snap_id: Snap id to fetch
        """
        r = self._request('ph/blob', {
            'username': self.username,
            'id': snap_id
            }, raise_for_status=False)
        data = decrypt(r.content)
        if any((is_image(data), is_video(data), is_zip(data))):
            return data
        return None

    def send_events(self, events, data=None):
        """Send event data
        Returns true on success.

        :param events: List of events to send
        :param data: Additional data to send
        """
        if data is None:
            data = {}
        r = self._request('bq/update_snaps', {
            'username': self.username,
            'events': json.dumps(events),
            'json': json.dumps(data)
        })
        return len(r.content) == 0

    def mark_viewed(self, snap_id, view_duration=1):
        """Mark a snap as viewed
        Returns true on success.

        :param snap_id: Snap id to mark as viewed
        :param view_duration: Number of seconds snap was viewed
        """
        now = time()
        data = {snap_id: {u't': now, u'sv': view_duration}}
        events = [
            {
                u'eventName': u'SNAP_VIEW', u'params': {u'id': snap_id},
                u'ts': int(round(now)) - view_duration
            },
            {
                u'eventName': u'SNAP_EXPIRED', u'params': {u'id': snap_id},
                u'ts': int(round(now))
            }
        ]
        return self.send_events(events, data)

    def mark_screenshot(self, snap_id, view_duration=1):
        """Mark a snap as screenshotted
        Returns true on success.
        :param snap_id: Snap id to mark as viewed
        :param view_duration: Number of seconds snap was viewed
        """
        now = time()
        data = {snap_id: {u't': now, u'sv': view_duration, u'c': 3}}
        events = [
            {
                u'eventName': u'SNAP_SCREENSHOT', u'params': {u'id': snap_id},
                u'ts': int(round(now)) - view_duration
            }
        ]
        return self.send_events(events, data)

    def update_privacy(self, friends_only):
        """Set privacy settings
        Returns true on success.

        :param friends_only: True to allow snaps from friends only
        """
        setting = lambda f: PRIVACY_FRIENDS if f else PRIVACY_EVERYONE
        r = self._request('ph/settings', {
            'username': self.username,
            'action': 'updatePrivacy',
            'privacySetting': setting(friends_only)
        })
        return r.json().get('param') == str(setting(friends_only))

    def get_friends(self):
        """Get friends
        Returns a list of friends.
        """
        return self.get_updates()['friends_response'].get('friends', [])

    def get_best_friends(self):
        """Get best friends
        Returns a list of best friends.
        """
        return self.get_updates()['friends_response'].get('bests', [])

    def add_friend(self, username):
        """Add user as friend
        Returns JSON response.
        Expected messages:
            Success: '{username} is now your friend!'
            Pending: '{username} is private. Friend request sent.'
            Failure: 'Sorry! Couldn't find {username}'

        :param username: Username to add as a friend
        """
        r = self._request('ph/friend', {
            'action': 'add',
            'friend': username,
            'timestamp': time() * 1000,
            'username': self.username
        })
        return r.json()

    def delete_friend(self, username):
        """Remove user from friends
        Returns true on success.

        :param username: Username to remove from friends
        """
        r = self._request('ph/friend', {
            'action': 'delete',
            'friend': username,
            'username': self.username
        })
        return r.json().get('logged')

    def block(self, username):
        """Block a user
        Returns true on success.

        :param username: Username to block
        """
        r = self._request('ph/friend', {
            'action': 'block',
            'friend': username,
            'username': self.username
        })
        return r.json().get('message') == '{0} was blocked'.format(username)

    def unblock(self, username):
        """Unblock a user
        Returns true on success.

        :param username: Username to unblock
        """
        r = self._request('ph/friend', {
            'action': 'unblock',
            'friend': username,
            'username': self.username
        })
        return r.json().get('message') == '{0} was unblocked'.format(username)

    def clear_feed(self):
        """Clear the user's feed
        Returns true if feed was successfully cleared.
        """

        r = self._request('clear', {
            'username': self.username
        })

        return len(r.content) == 0

    def clear_convo(self, id):
        """Clears the conversation with a user

        :param id: Conversation id to clear
        """
        r = self._request('loq/clear_conversation', {
            'conversation_id': id,
            'timestamp': time() * 1000,
            'username': self.username
        })
        return r

    def get_blocked(self):
        """Find blocked users
        Returns a list of currently blocked users.
        """
        return [f for f in self.get_friends() if f['type'] == FRIEND_BLOCKED]

    def upload(self, path):
        """Upload media
        Returns the media ID on success. The media ID is used when sending
        the snap.
        """
        if not os.path.exists(path):
            raise ValueError('No such file: {0}'.format(path))

        with open(path, 'rb') as f:
            data = f.read()

        media_type = get_media_type(data)
        if media_type is None:
            raise ValueError('Could not determine media type for given data')

        media_id = make_media_id(self.username)
        r = self._request('ph/upload', {
            'username': self.username,
            'media_id': media_id,
            'type': media_type
            }, files={'data': encrypt(data)})

        return media_id if len(r.content) == 0 else None

    def send(self, media_id, recipients, time=5):
        """Send a snap. Requires a media_id returned by the upload method
        Returns true if the snap was sent successfully
        """
        r = self._request('loq/send', {
            'username': self.username,
            'media_id': media_id,
            'recipient': recipients,
            'time': time,
            'zipped': '0'
            })
        return len(r.content) == 0

    def send_to_story(self, media_id, time=5):
        """Post a snap to your story. Requires a media_id returned by the
        upload method.
        """
        r = self._request('bq/post_story', {
            'username': self.username,
            'timestamp': time() * 1000,
            'media_id': media_id,
            'client_id': media_id,
            'caption_text_display': '',
            'zipped': '0',
            'type': 0,
            'time': time
            })
        return r.content

    def send_typing_notification(self, susername):
        """Send the typing notification to the provided susername.
        """
        r = self._request('bq/chat_typing', {
            'username': self.username,
            'recipient_usernames': '["' + susername + '"]',
            'timestamp': time() * 1000
            })
        return r.content == ""

    def retry_post_story(self, data, caption="", time=10):
        """Post a snap to your story. Requires a data of the media

        :param data: The image/video data of the file to add to story
        :param caption: Not rendered by the receiver, but shows when
                        looking at my stories in the authentic app
        :param time: The length of time to display on the story
        """
        media_id = make_media_id(self.username)
        r = self._request('bq/retry_post_story', {
            'username': self.username,
            'timestamp': time() * 1000,
            'media_id': media_id,
            'client_id': media_id,
            'caption_text_display': caption,
            'zipped': int(is_zip(data)),
            'type': get_media_type(data),
            'time': time * 1000
            }, files={'data': encrypt(data)})
        return r.content

    def get_snaptag(self):
        """Returns the image data of the user's SnapTag
        """
        r = self._request('bq/snaptag_download', {
            'username': self.username,
            'image': self.qr_path,
            'timestamp': time() * 1000
            }, raise_for_status=False)
        data = decrypt(r.content)
        if any((is_image(data), is_video(data), is_zip(data))):
            return data
        return r.content
