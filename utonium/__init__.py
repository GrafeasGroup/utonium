from __future__ import annotations

import glob
import importlib
import logging
import re
import traceback
from dataclasses import asdict, dataclass
from os.path import basename, isfile, join
from pathlib import Path
from typing import Any, Callable, Optional

from slack_bolt import App
from slack_sdk.web.client import WebClient

log = logging.getLogger(__name__)


Plugin = dict[str, Any]


@dataclass
class Plugin:
    callable: Callable
    regex: str
    flags: int = None
    callback: Callable = None
    ignore_prefix: bool = False
    help: str = None
    interactive_friendly: bool = True

    def to_dict(self):
        return asdict(self)


class PluginManager:
    def __init__(
        self,
        command_prefixes: tuple | list,
        command_folder: Path,
        slack_app: App,
        interactive_mode: bool = False,
        reaction_added_callback: Callable = None,
    ) -> None:
        self.plugins: list[Plugin] = list()
        self.callbacks: list[Callable] = list()
        self.command_prefixes = command_prefixes
        self.command_folder = command_folder
        self.app = slack_app
        self.interactive_mode = interactive_mode
        self.cache = {}
        self.users_dict: dict[str, Any] = {}
        self.rooms_dict: dict[str, str] = {}

        def reaction_sinkhole(payload: Payload) -> None:
            """Absorb and ignore all reaction events if no handler is configured."""
            pass

        if not reaction_added_callback:
            log.warning("No reaction callback registered. Sinkholing all reactions.")
            self.reaction_added_callback = reaction_sinkhole
        else:
            self.reaction_added_callback = reaction_added_callback

        # let's kick this pig
        self.init()

    def init(self):
        """Ask Slack for information that is only known at runtime."""
        # Define the list of users (conversion ID <-> username)
        # 'Any' here is either a list or a str; mypy can't handle that.
        # See https://stackoverflow.com/a/62862029
        self.users_dict = {"ids_only": []}
        users = self.app.client.users_list()
        for user in users["members"]:
            if not user["deleted"]:
                # Extract the display name if available
                name = (
                    user.get("profile", {}).get("display_name")
                    or user.get("real_name")
                    or user["id"]
                )
                self.users_dict[user["id"]] = name
                self.users_dict[name] = user["id"]
                self.users_dict["ids_only"].append(user["id"])

        # Define the list of rooms (useful to retrieve the ID of the rooms,
        # knowing their name)
        self.rooms_dict = {}
        rooms = self.app.client.conversations_list()
        for room in rooms["channels"]:
            self.rooms_dict[room["id"]] = room["name"]
            self.rooms_dict[room["name"]] = room["id"]

        # Get information about ourselves
        own_data = self.app.client.auth_test().data

        # slack username
        self.MY_USERNAME: str = own_data.get("user")
        # slack internal user ID
        self.MY_ID: str = own_data.get("user_id")

    def try_get_command_text(self, message: str) -> Optional[str]:
        """Try to get the text content of a command.

        This checks if the message has one of the command prefixes.
        If yes, it returns the rest of the message without the prefix.
        If no, it returns `None`.
        """
        for prefix in self.command_prefixes:
            # Check if the message starts with the prefix
            if message.lower().startswith(prefix.lower()):
                # Remove the prefix from the message
                return message[len(prefix) :].strip()

        return None

    def get_plugin(self, message: str) -> Plugin | None | bool:
        """Get the plugin corresponding to the given message."""

        def test_plugin(plg, text: str) -> Plugin | None | bool:
            """Test if the plugin can handle the given text."""
            if re.search(plg.get("regex", None), text):
                if self.interactive_mode and not plg["interactive_friendly"]:
                    log.error(
                        f"Plugin {plg['callable']} cannot be run in"
                        f" interactive mode."
                    )
                    return False
                return plugin
            return None

        prefix_plugins = [
            plugin for plugin in self.plugins if not plugin["ignore_prefix"]
        ]

        # If the command has a prefix, look at the prefix plugins first
        if cmd_text := self.try_get_command_text(message):
            for plugin in prefix_plugins:
                result = test_plugin(plugin, cmd_text)
                if result is not None:
                    return result

        no_prefix_plugins = [
            plugin for plugin in self.plugins if plugin["ignore_prefix"]
        ]

        # Otherwise, look at plugins without the prefix
        for plugin in no_prefix_plugins:
            result = test_plugin(plugin, message)
            if result is not None:
                return result

        # the message we received doesn't match anything our plugins are
        # looking for.
        return None

    def process_plugin_callbacks(self, data: Payload) -> None:
        for func in self.callbacks:
            func(data)

    def register_plugin(
        self,
        callable: Callable,
        regex: str,
        flags=None,
        callback: Callable = None,
        ignore_prefix: bool = False,
        help: str = None,
        interactive_friendly: bool = True,
    ) -> None:
        regex = re.compile(regex, flags if flags else 0)
        self.plugins.append(
            {
                "callable": callable,
                "regex": regex,
                "ignore_prefix": ignore_prefix,
                "help": help,
                "interactive_friendly": interactive_friendly,
            }
        )
        if callback:
            self.callbacks.append(callback)
        log.info(f"Registered {str(callable)}")

    def find_plugins(self) -> list[str]:
        modules = glob.glob(join(self.command_folder, "*.py"))
        return [
            basename(f)[:-3]  # trim off the .py bit
            for f in modules
            if isfile(f) and not f.endswith("__init__.py")
        ]

    def load_plugin_file(self, name: str) -> None:
        """Attempt to import the requested file and load the plugin definition."""

        # The plugin definition is stored in a special variable called PLUGIN at the
        # top level of the module. If it's not there, raise an exception.
        module = importlib.import_module(f"{str(self.command_folder)}.{name}")
        definition = module.PLUGIN
        self.register_plugin(**definition.to_dict())

    def load_all_plugins(self):
        plugins = self.find_plugins()
        for plugin in plugins:
            try:
                self.load_plugin_file(plugin)
            except Exception as e:
                log.warning(f"Cannot load {plugin}: {e}")

    def process_message(self, payload: Payload):
        log.debug("Message received!")
        if len(payload) == 0:
            log.info("Unprocessable message. Ignoring.")
            return
        message = payload.get_text()

        if not message:
            # sometimes we'll get an object without text; just discard it.
            log.info("Unprocessable message. Ignoring.")
            return

        try:
            user_who_sent_message = self.users_dict[payload.get_user()]
        except KeyError:
            # This will trigger if an app posts, like the RSS feeds.
            return

        # is the message from... us?
        if (
            user_who_sent_message.lower() == self.MY_USERNAME.lower()
            or user_who_sent_message.lower() == self.MY_ID.lower()
        ):
            return

        log.debug(f"I received: {message} from {user_who_sent_message}")
        # search all the loaded plugins to see if any of the regex's match
        plugin = self.get_plugin(message)
        if plugin:
            plugin["callable"](payload)
        elif plugin is False:
            # we're in interactive mode and hit a locked plugin, so we just need
            # to skip the else block
            pass
        else:
            # we don't know what they were trying to do, so we fall through to here.
            # Let's only limit responses to things that look like they're trying
            # to use regular command syntax, though.
            # For example, trigger on "!hello" but not for "isn't bubbles great".
            if command_text := self.try_get_command_text(message):
                payload.say(f"Unknown command: `{command_text}`")

        # If a command needs to be able to see all traffic for historical reasons,
        # register a separate callback function in a class for the command. See
        # bubbles.commands.yell for an example implementation.
        self.process_plugin_callbacks(payload)

    def clean_text(self, text: str | list) -> str:
        """
        Take the trigger word out of the text.

        Examples:
            !test -> !test
            !test one -> !test one
            @bubbles test -> test
            @bubbles test one -> test one
        """
        if isinstance(text, list):
            text = " ".join(text)

        return self.try_get_command_text(text) or text

    def message_received(self, payload, client, context, body, say) -> None:
        if not payload.get("text"):
            # we got a message that is not really a message for some reason.
            return
        payload_obj = Payload(
            client=client,
            slack_payload=payload,
            say=say,
            context=context,
            slack_body=body,
            meta=self,
        )
        try:
            self.process_message(payload_obj)
        except:  # noqa: E722
            say(f"Computer says noooo: \n```\n{traceback.format_exc()}```")

    def reaction_received(self, payload, client, context, say) -> None:
        user_whose_message_has_been_reacted = self.users_dict[payload.get("item_user")]
        if not user_whose_message_has_been_reacted:
            # Sometimes we get partially formed reactions. Not entirely sure why.
            return
        payload_obj = Payload(
            client=client, slack_payload=payload, say=say, context=context, meta=self
        )
        try:
            self.reaction_added_callback(payload_obj)
        except:  # noqa: E722
            say(f"Computer says noooo: \n```\n{traceback.format_exc()}```")


class Payload:
    """Payload class for everything a command needs."""

    def __init__(
        self,
        # this should be a WebClient but some of our bots also define a
        # custom MockClient object, so the type hinting should accept
        # any class here.
        client: WebClient | Any = None,
        slack_payload: dict = None,
        slack_body: dict = None,
        say: Callable = None,
        context: dict = None,
        meta: PluginManager = None,
    ):
        self.client = client
        self._slack_payload = slack_payload
        self._slack_body = slack_body or {}
        self._say = say
        self.context = context
        self.meta = meta

        try:
            self.cleaned_text = self.meta.clean_text(self.get_text())
        except AttributeError:
            # Sometimes we're processing payloads without text.
            self.cleaned_text = None

    def __len__(self):
        return len(self._slack_payload)

    def get_cache(self, cache_name: str) -> dict:
        """
        Provide a shareable volatile cache for plugins.

        Some commands need to either store information for later
        or provide the ability to share information to other commands.
        The plugin manager provides a shared cache dict that can be
        used for this purpose.
        """
        if not self.meta.cache.get(cache_name):
            self.meta.cache[cache_name] = {}
        return self.meta.cache[cache_name]

    def say(self, *args, **kwargs):
        """Reply in the thread if the message was sent in a thread."""
        # Extract the thread that the message was posted in (if any)
        if self._slack_body:
            thread_ts = self._slack_body["event"].get("thread_ts")
        else:
            thread_ts = None
        return self._say(*args, thread_ts=thread_ts, **kwargs)

    def get_user(self) -> Optional[str]:
        """Get the user who sent the Slack message."""
        return self._slack_payload.get("user")

    def get_item_user(self) -> Optional[str]:
        """If this is a reaction_* obj, return the user whose content was reacted to."""
        return self._slack_payload.get("item_user")

    def is_reaction(self) -> bool:
        return self._slack_payload.get("reaction")

    def get_channel(self) -> Optional[str]:
        """Return the channel the message originated from."""
        return self._slack_payload.get("channel")

    def get_text(self) -> str:
        return self._slack_payload.get("text")

    def get_event_type(self) -> str:
        """
        Return the type of event that this payload is for.

        Expected types you might get are:
        - message
        - reaction_added
        - reaction_removed
        """
        return self._slack_payload.get("type")

    def get_reaction(self) -> Optional[str]:
        """
        If this is a reaction_* payload, return the emoji used.

        Example responses:
        - thumbsup
        - thumbsdown
        - blue_blog_onr
        """
        return self._slack_payload.get("reaction")

    def get_reaction_message(self) -> Optional[dict]:
        """
        If this is a reaction payload, look up the message that the reaction was for.

        This will return a full Slack response dict if the message is found or None.
        https://api.slack.com/methods/reactions.list

        Example response here:
        {
            'type': 'message',
            'channel': 'HIJKLM',
            'message': {
                'client_msg_id': '3456c594-3024-404d-9e08-3eb4fe0924c0',
                'type': 'message',
                'text': 'Sounds great, thanksss',
                'user': 'XYZABC',
                'ts': '1661965345.288219',
                'team': 'GFEDCBA',
                'blocks': [...],
                'reactions': [
                    {
                        'name': 'upvote',
                        'users': ['ABCDEFG'], 'count': 1
                    }
                ],
                'permalink': 'https://...'
            }
        }
        """
        resp = self.client.reactions_list(count=1, user=self.get_user())
        if not resp.get("ok"):
            return

        item_payload = self._slack_payload.get("item")
        if not item_payload:
            return

        target_reaction_ts = item_payload.get("ts")
        if not target_reaction_ts:
            return

        # short circuit for interactive mode
        if len(resp.get("items")) == 1 and resp["items"][0].get("channel") == "console":
            return resp["items"][0]

        for message in resp.get("items"):
            if message["message"]["ts"] == target_reaction_ts:
                return message

    def reaction_add(self, response: dict, name: str) -> Any:
        """
        Apply an emoji to a given Slack submission.

        Pass in the complete response from `say` and the name of an emoji.
        """
        return self.client.reactions_add(
            channel=response["channel"], timestamp=response["ts"], name=name
        )

    def update_message(self, response: dict, *args, **kwargs) -> Any:
        """
        Edit / update a given Slack submission.

        Pass in the complete response from `say` and your new content.
        """
        return self.client.chat_update(
            channel=response["channel"], ts=response["ts"], *args, **kwargs
        )

    def upload_file(
        self,
        file: str = None,
        title: Optional[str] = None,
        payload: Optional[dict] = None,
        content: str = None,
        filetype: str = None,  # https://api.slack.com/types/file#file_types
        initial_comment: str = None,
    ) -> Any:
        """Upload a file to a given Slack channel."""
        if (not file and not content) or (file and content):
            raise Exception("Must have either a file or content to post!")

        if not payload:
            payload = self._slack_payload
        if not title:
            title = "Just vibing."
        self.client.files_upload(
            channels=payload.get("channel"),
            file=file,
            content=content,
            filetype=filetype,
            title=title,
            as_user=True,
            initial_comment=initial_comment,
        )
