from __future__ import annotations

import glob
import importlib
import importlib.util
import logging
import re
import traceback
from dataclasses import asdict, dataclass
from os.path import basename, isfile, join
from pathlib import Path
from typing import Any, Callable, Optional

from slack_bolt import App
from slack_sdk.models import blocks
from slack_sdk.web.client import WebClient

log = logging.getLogger(__name__)

Plugin = dict[str, Any]

EVERYTHING_REGEX: str = r".*"


class UtoniumException(Exception):
    pass


@dataclass
class Plugin:
    # A standard function that takes a message event.
    func: Callable = None
    # A function that takes a Reaction Added / Reaction Removed event.
    reaction_func: Callable = None
    # A function that takes an Action (from Slack Blocks) event.
    block_kit_action_func: Callable = None

    # the default message regex
    regex: str = None
    # regex of emoji names (no colons) to watch for as reactions
    reaction_regex: str = None
    # regex to trigger the block_kit_action_func
    block_kit_action_regex: str = None

    # regex flags to modify the default regex
    flags: int = None
    # regex flags to modify the reaction regex
    reaction_regex_flags: int = None
    # regex flags to modify the action regex
    block_kit_action_regex_flags: int = None

    # a function that will be called on every event.
    callback: Callable = None
    # should this plugin trigger if the command prefix is not there?
    ignore_prefix: bool = False
    # should this plugin run in interactive mode?
    interactive_friendly: bool = True

    def get(self, item, default):
        return getattr(self, item, default)

    def to_dict(self) -> dict:
        """Return the plugin definition in Dict format."""
        return asdict(self)

    def get_primary_func(self):
        funcs = [self.func, self.reaction_func, self.block_kit_action_func]
        primary_func = next((option for option in funcs if option is not None), None)
        return primary_func

    def __doc__(self) -> Optional[str]:
        """
        Return the docstring of the plugin.

        Checks `func` first, then `reaction_func` and finally `block_kit_action_func`.
        If no docstring is found, None is returned.
        """
        pfunc = self.get_primary_func()
        return pfunc.__doc__ if pfunc.__doc__ else None

    def validate(self) -> None:
        """Make sure that there is a valid callable with a valid way to call it."""
        if not any([self.func, self.reaction_func, self.block_kit_action_func]):
            raise UtoniumException("Missing function to call!")
        if not any([self.regex, self.reaction_regex, self.block_kit_action_regex]):
            raise UtoniumException("Missing regex for plugin!")
        matched_sets = {
            self.func: self.regex,
            self.reaction_func: self.reaction_regex,
            self.block_kit_action_func: self.block_kit_action_regex,
        }
        for func, regex in matched_sets.items():
            if func and not regex:
                raise UtoniumException(f"No regex found for func {func}!")
            if not func and regex:
                raise UtoniumException("Found regex for missing function!")


class PluginManager:
    def __init__(
        self,
        command_prefixes: tuple | list,
        command_folder: Path,
        slack_app: App,
        interactive_mode: bool = False,
        users_dict: dict[str, Any] = None,
        rooms_dict: dict[str, str] = None,
    ) -> None:
        self.plugins: list[Plugin] = list()
        self.reaction_plugins: list[Plugin] = list()
        self.block_kit_action_plugins: list[Plugin] = list()
        self.callbacks: list[Callable] = list()
        self.command_prefixes = command_prefixes
        self.command_folder = command_folder
        self.app = slack_app
        self.interactive_mode = interactive_mode
        self.cache = {}
        self.users_dict: dict[str, Any] = users_dict
        self.rooms_dict: dict[str, str] = rooms_dict

        # let's kick this pig
        self.init()

    def init(self):
        """Ask Slack for information that is only known at runtime."""
        if not self.users_dict:
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

        if not self.rooms_dict:
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

    def get_plugin(self, payload: Payload) -> Plugin | None | bool:
        """Get the plugin corresponding to the given message."""

        def test_plugin(plg: Plugin, text: str) -> Plugin | None | bool:
            """Test if the plugin can handle the given text."""
            if re.search(plg.regex, text):
                if self.interactive_mode and not plg.interactive_friendly:
                    log.error(
                        f"Plugin {plg['func']} cannot be run in" f" interactive mode."
                    )
                    return False
                return plugin
            return None

        message = payload.get_text()

        prefix_plugins = [plugin for plugin in self.plugins if not plugin.ignore_prefix]

        # If the command has a prefix, look at the prefix plugins first
        if cmd_text := self.try_get_command_text(message):
            for plugin in prefix_plugins:
                result = test_plugin(plugin, cmd_text)
                if result is not None:
                    return result

        no_prefix_plugins = [plugin for plugin in self.plugins if plugin.ignore_prefix]

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

    def register_plugin(self, plg: Plugin) -> None:
        if plg.regex:
            plg.regex = re.compile(plg.regex, plg.flags or 0)
        if plg.reaction_regex:
            plg.reaction_regex = re.compile(
                plg.reaction_regex, plg.reaction_regex_flags or 0
            )
        if plg.block_kit_action_regex:
            plg.block_kit_action_regex = re.compile(
                plg.block_kit_action_regex, plg.block_kit_action_regex_flags or 0
            )

        if plg.func:
            self.plugins.append(plg)
        if plg.reaction_func:
            self.reaction_plugins.append(plg)
        if plg.block_kit_action_func:
            self.block_kit_action_plugins.append(plg)
        if plg.callback:
            self.callbacks.append(plg.callback)

        plg_func = next(
            (
                option
                for option in [plg.func, plg.reaction_func, plg.block_kit_action_func]
                if option is not None
            ),
            None,
        )
        log.info(f"Registered {plg_func.__name__}")

    def find_plugins(self) -> list[str]:
        modules = glob.glob(join(self.command_folder, "*.py"))
        return [f for f in modules if isfile(f) and not f.endswith("__init__.py")]

    def load_plugin_file(self, name: str) -> None:
        """
        Attempt to import the requested file and load the plugin definition.

        The plugin will come in the format of "python/path/to/file.py", which
        we can pass directly to importlib and let it figure it out.
        """

        # The plugin definition is stored in a special variable called PLUGIN at the
        # top level of the module. If it's not there, raise an exception.
        spec = importlib.util.spec_from_file_location(basename(name)[:-3], name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        definition: Plugin = module.PLUGIN
        # Ensure it has all the necessary pieces and raise an exception if not
        definition.validate()

        self.register_plugin(definition)

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

        # intercept help message so we can generate it ourselves
        if self.clean_text(message) == "help":
            self.send_help_message(payload)
            return

        # search all the loaded plugins to see if any of the regex's match
        plugin = self.get_plugin(payload)
        if plugin:
            plugin.func(payload)
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

    def send_help_message(self, payload: Payload) -> None:
        def format_text(data: dict) -> list[blocks.Block]:
            message_blocks = [
                blocks.HeaderBlock(text="Help is on the way!"),
                blocks.SectionBlock(
                    text="Here all the commands that are currently loaded:"
                ),
                blocks.DividerBlock(),
            ]

            for name, docstring in data.items():
                message_blocks += [
                    blocks.SectionBlock(
                        fields=[
                            blocks.MarkdownTextObject(text=f"*{name}*"),
                            blocks.MarkdownTextObject(text=docstring),
                        ]
                    )
                ]

            return message_blocks

        plugins_with_help = dict()
        for plugin in self.plugins:
            if plugin.__doc__() is not None:
                # grab the name of the command and the help string.
                func = plugin.get_primary_func()
                if hasattr(func, "__name__"):
                    # we're looking at a function.
                    # <function myfunc at 0x7f28aa33e8b0>
                    plugin_name = func.__name__
                else:
                    # we're looking at a class.
                    # <bound method MyPlugin.myfunc of
                    # <__main__.MyPlugin object at 0x7f28aa408070>>
                    plugin_name = func.__class__.name__
                plugins_with_help[plugin_name] = plugin.__doc__()
        # sort that sucker alphabetically
        plugins_with_help = {
            key: value for key, value in sorted(plugins_with_help.items())
        }
        payload.say(blocks=format_text(plugins_with_help))

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

        for plugin in self.reaction_plugins:
            if re.search(plugin.reaction_regex, payload_obj.get_reaction()):
                if self.interactive_mode and not plugin.interactive_friendly:
                    log.error(
                        f"Plugin {plugin.reaction_func} cannot be run in"
                        f" interactive mode."
                    )
                try:
                    plugin.reaction_func(payload_obj)
                except:  # noqa: E722
                    say(f"Computer says noooo: \n```\n{traceback.format_exc()}```")

    def action_received(self, payload, client, context, say) -> None:
        payload_obj = Payload(
            client=client, slack_payload=payload, say=say, context=context, meta=self
        )

        if not payload_obj.get_block_kit_action():
            # something's wonky or it's a link button. Just return so that all is good.
            return

        for plugin in self.block_kit_action_plugins:
            if re.search(
                plugin.block_kit_action_regex, payload_obj.get_block_kit_action()
            ):
                if self.interactive_mode and not plugin.interactive_friendly:
                    log.error(
                        f"Plugin {plugin.block_kit_action_func} cannot be run in"
                        f" interactive mode."
                    )
                try:
                    plugin.block_kit_action_func(payload_obj)
                    # We should only receive one action at a time and each
                    # action should only trigger one thing.
                    return
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

    def is_block_kit_action(self) -> bool:
        return self.get_event_type() in [
            "block_actions",
            "interactive_message",
            "button",
        ]

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

    def get_block_kit_action(self) -> Optional[str]:
        """If this is a block kit action, return the value of the action."""
        if not self.is_block_kit_action():
            return
        # If it's an action, it should have the following structure
        # https://api.slack.com/reference/interaction-payloads/block-actions#examples
        return self._slack_payload["actions"][0].get("value")

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
