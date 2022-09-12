![Image of Professor Utonium, from 1998's Powerpuff Girls](https://i.imgur.com/1VsbPXJ.png)

<h1 align="center">utonium</h1>

<p align="center">
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

The Slack handler to handle all of Slack.

Working with Slack is sometimes extremely painful. We've been working with Slack bots for a few years now, and although things like [Slack Bolt](https://github.com/SlackAPI/bolt-python) (and its accompanying [documentation](https://slack.dev/bolt-python/concepts)) has made a lot of it easier, this comes with its own issues, of which namely is cleanly adding more functionality. A single file with a command or two gets the job done, but what happens if you want to have _lots_ of commands? That's where `utonium` comes in.

`utonium` handles two very specific things by giving you:

1. a plugin management system to automatically detect and load in plugin files from a configurable location
2. a `Payload` object that plays nicely with Python's type hinting with lots of helper functions on it

## Installing

Adding `utonium` to a `slack-bolt` project is fairly hassle-free, though there are some things you'll need to figure out beforehand, like "where am I going to put my plugin folder".

- Add utonium to your project
  - For [Poetry](https://python-poetry.org/), add the following line manually to your `pyproject.toml`: `utonium = { git = "https://github.com/GrafeasGroup/utonium.git", branch = "main" }`, then run `poetry install` to make the magic happen.
- Identify where you're going to put your commands. The convention is a folder called `commands` located at the top level of your app. For example: `yourapp.commands`.
- Instantiate the plugin system and hook up the official listeners.

Here's an example `main.py` file that gets all the important information. How much of this you use (or change) is up to you.

```python
import os
from pathlib import Path

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import utonium


app = App(
    # get these from Slack
    signing_secret=os.environ.get("slack_signing_secret"),
    token=os.environ.get("slack_oauth_token"),
)

# There is an overloaded __get__ in the underlying Bolt app, so this type
# doesn't resolve cleanly.
ME: str = app.client.auth_test().data["user_id"]  # type: ignore
USERNAME = os.environ.get("username", "YourAppsSlackUsername")


@app.event("message")
def handle_message(ack, payload, client, context, say, body: dict):
    ack()
    plugin_manager.message_received(payload, client, context, body, say)

    
@app.event("reaction_added")
@app.event("reaction_removed")
def reaction_added(ack, payload, client, context, say):
    ack()
    plugin_manager.reaction_received(payload, client, context, say)


if __name__ == "__main__":
    plugin_manager = utonium.PluginManager(
        command_prefixes=("!", f"@{USERNAME}", f"<@{ME}>"),
        command_folder=Path("yourapp/commands/"),
        slack_app=app,
    )
    plugin_manager.load_all_plugins()
    SocketModeHandler(app, os.environ.get("slack_websocket_token")).start()
```

## Commands (Plugins)

Add commands, one per file, inside your `commands` folder. Each command file has the following structure:

```python
# yourapp/commands/ping.py
from utonium import Payload, Plugin


# Every command has one entry point, and that entry point takes in exactly
# one thing: the Payload. It's included here as a type hint so that we can
# take advantage of the type hinting in our editor.
def ping(payload: Payload) -> None:
    # The Payload has a lot of very useful things attached to it and will
    # always attempt to act on the message that triggered it, so in this
    # case `payload.say` will post a message to the channel that the message
    # was received in, like the original functionality of the `say` command.
    # However, this version is _thread aware_, which the original version
    # is not, and if it is called from inside a thread then it will respond
    # as a message inside the thread as well.
    #
    # You can also pass any other attributes or variables that the original
    # `say` command would expect to this call and they'll be handled
    # appropriately.
    payload.say("PONG!")

# Each command file must define a variable called `PLUGIN` at the bottom.
# This contains all the information needed to actually load the file and
# route messages to it when they're detected. In this case, this will run
# the `ping` function defined above when a message matching the regex is
# found. When the `help` command is run, the string passed there will be
# shown. If you omit the `help` attribute, the command will still work but
# it will not be listed in the `help` menu by default. You can override
# the built-in help command by writing your own with the name `help.py`.
# See `utonium.Plugin` for all of the attributes that can be set here.
PLUGIN = Plugin(callable=ping, regex=r"^ping$", help="!ping - PONG")
```

Depending on your logging settings, when you start your app, you should see one line of console output for each command loaded. By default, it looks like this:

```
2022-09-11 22:02:59,131 | INFO | register_plugin | Registered <function ping at 0x7f090b9f6b90>
2022-09-11 22:02:59,132 | INFO | register_plugin | Registered <function help at 0x7f090b0e3640>
```

## Pre-commit

Blossom uses `pre-commit` to help us keep everything clean. After you check out the repo and run `poetry install`, run `pre-commit install` to configure the system. The first time that you run `git commit`, it will create a small venv specifically for checking commits based on our toolset. All of these are installed as part of the regular project so that you can run them as you go -- don't get taken by surprise when you go to commit! The toolchain as written invokes the following tools:

- seed-isort-config
  - This sets .isort.cfg with all of the third-party modules that are in use.
- isort
  - Searches Python files for imports that are in the wrong order, then offers you the option of fixing them.
- black
  - Opinionated code formatter; automatically fixes issues.
- flake8
  - formatting checker and linter; does not automatically fix issues.

If an issue is detected when you run `git commit`, the action will be aborted and you'll receive a message about what needs to be fixed before committing.
