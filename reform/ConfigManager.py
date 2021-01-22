import json
import logging
import os
import time

from reform import ReformSettings, SecretsManager
from pyee import EventEmitter
from collections import MutableMapping
from functools import reduce

ee = EventEmitter()


class ConfigManager:
    def __init__(self, args):
        self.args = args
        self.logger = logging.getLogger(__name__)
        self.logger.debug("ARGS: %s" % (json.dumps(args)))
        self.settings = ReformSettings.ReformSettings()

        cf = ReformSettings.ReformSettings.reform_quadrant_config_file
        if "cipher" in self.args and self.args["cipher"]:
            cf = ReformSettings.ReformSettings.reform_quadrant_secret_file

        self.default_config_file = "%s/configs/defaults/config.json" % (
            self.settings.GetReformRoot()
        )

        self.config_file = "%s/configs/%s/%s" % (
            self.settings.GetReformRoot(),
            self.args["env"],
            cf,
        )

        if not os.path.exists(self.config_file):
            self.logger.warn(
                "'%s' file does not exists, creating it" % (self.config_file)
            )
            with open(self.config_file, "w+") as f:
                f.write(json.dumps({}, indent=4, sort_keys=True))
            f.close()

    def delete(d, keys):
        if "." in keys:
            key, rest = keys.split(".", 1)
            ConfigManager.delete(d[key], rest, item)
        else:
            if keys not in d:
                logging.getLogger(__name__).info("Missing %s from %s" % (keys, d))
                exit(-3)
            logging.getLogger(__name__).info("Removing %s from %s" % (keys, d))
            del d[keys]

    def put(d, keys, item):
        if "." in keys:
            key, rest = keys.split(".", 1)
            if key not in d:
                d[key] = {}
            logging.getLogger(__name__).debug("Found %s in %s" % (key, d))
            ConfigManager.put(d[key], rest, item)
        else:
            d[keys] = item

    def deep_merge(d1, d2):
        """
        Update two dicts of dicts recursively,
        if either mapping has leaves that are non-dicts,
        the second's leaf overwrites the first's.
        """
        for k, v in d1.copy().items():
            if k in d2:
                if all(isinstance(e, MutableMapping) for e in (v, d2[k])):
                    d2[k] = ConfigManager.deep_merge(v, d2[k])

            if k == "*":
                for _k, _v in d2.items():
                    if all(isinstance(e, MutableMapping) for e in (v, d2[_k])):
                        d2[_k] = ConfigManager.deep_merge(v, d2[_k])
                del d1[k]
        d3 = d1.copy()
        d3.update(d2)
        return d3

    def get_merge_configs(self):
        configs = {}
        defaults = {}
        if "cipher" not in self.args or not self.args["cipher"]:
            if os.path.exists(self.default_config_file):
                with open(self.default_config_file, "r+") as f:
                    # Read file contents
                    defaults = json.loads(f.read())

        with open(self.config_file, "r+") as f:
            # Read file contents
            configs = reduce(ConfigManager.deep_merge, (defaults, json.loads(f.read())))
        return configs

    def get(configs, attribute):
        if "." in attribute:
            key, rest = attribute.split(".", 1)
            if key in configs:
                return ConfigManager.get(configs[key], rest)
            else:
                logging.getLogger(__name__).warn(
                    "ConfigManager.get: Did not find %s in %s" % (key, configs)
                )
        else:
            if attribute in configs:
                return configs[attribute]
            else:
                logging.getLogger(__name__).warn(
                    "ConfigManager.get: Did not find %s in %s" % (attribute, configs)
                )
        return {}

    def read(self):
        c = False
        configs = self.get_merge_configs()
        # print(json.dumps(configs, indent=4, sort_keys=True))
        self.logger.debug(
            "get_merge_configs: %s=%s" % (self.config_file, json.dumps(configs))
        )
        try:
            c = ConfigManager.get(configs, self.args["attribute"])
            if c is not None:
                self.logger.info("Current Value: '%s'" % (c))
            else:
                self.logger.info(
                    "Value '%s' doesn't exists." % (self.args["attribute"])
                )
        except:
            self.logger.warn("Value '%s' doesn't exists." % (self.args["attribute"]))

        # Emit the event to hook onto it
        ee.emit("ConfigManager.read", self.args["attribute"], c)

        if self.args["cipher"] is not None:
            c = SecretsManager.SecretsManager(
                {"key": self.args["env"], "cipher": self.args["cipher"]}
            ).secretDecoderRing(c)

        return c

    def upsert(self):
        with open(self.config_file, "r+") as f:
            # Read file contents
            configs = json.loads(f.read())

            try:
                c = ConfigManager.get(configs, self.args["attribute"])
                if not c is None:
                    self.logger.debug("Current Value: '%s'" % (c))
                else:
                    self.logger.info(
                        "Value '%s' doesn't already exists, adding"
                        % (self.args["attribute"])
                    )
            except:
                self.logger.info(
                    "Value '%s' doesn't already exists, adding"
                    % (self.args["attribute"])
                )

            ConfigManager.put(configs, self.args["attribute"], self.args["value"])

            # Go to start of file and write it out
            f.truncate()
            f.seek(0)
            f.write(json.dumps(configs, indent=4, sort_keys=True))

            # Emit the event to hook onto it
            ee.emit("ConfigManager.upsert", self)
            return True

    def delete(self):
        result = False
        with open(self.config_file, "r+") as f:
            # Read file contents
            configs = json.loads(f.read())

            try:
                c = ConfigManager.get(configs, self.args["attribute"])
                if not c is None:
                    self.logger.debug("Removing Value: '%s'" % (c))
                    ConfigManager.delete(configs, self.args["attribute"])
                else:
                    self.logger.error(
                        "Value '%s' doesn't already exists" % (self.args["attribute"])
                    )
            except:
                self.logger.info(
                    "Value '%s' doesn't already exists, adding"
                    % (self.args["attribute"])
                )

            # Go to start of file and write it outf
            f.seek(0)
            f.truncate()
            f.write(json.dumps(configs, indent=4, sort_keys=True))
            # Emit the event to hook onto it
            ee.emit("ConfigManager.delete", self)
            result = True
        return result

    def delete_config(self):
        if os.path.exists(self.config_file):
            os.remove(self.config_file)
            return True
        return False

    def __del__(self):
        # Emit the event to hook onto it
        ee.emit("ConfigManager.finish", self)
