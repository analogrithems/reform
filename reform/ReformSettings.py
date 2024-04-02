import configparser
import os
import logging
import yaml
from reform.ReformSettingsError import ReformSettingsError
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

class ReformSettings:
    """
    This class is used to store settings for the reform tool. Such as the bucket
    to store keys in, where the project root is, keys that have been generated
    and more.

    We should store the reform settings in the root of the project in a file
    called .reform
    """

    reform_settings_file = ".reform"
    reform_quadrant_config_file = "config.yaml"
    reform_quadrant_secret_file = "secrets.yaml"
    reform_settings_path = ""
    changed = False

    def __init__(self):
        """
        To find the reform settings we will check the current, if the file is not
        found, we will go up a directory.  We will continue to check our parent
        directory until a file is found or we reach root and raise an error
        """
        self.reform_settings_path = ReformSettings.find_settings_file(os.getcwd())
        if self.reform_settings_path is not False:
            self.config = configparser.ConfigParser()
            self.config.read(self.reform_settings_path)
        self.logger = logging.getLogger(__name__)

    def projects(self):
        if self.reform_settings_path is not False:
            project_dir = "%s/projects" % (self.GetReformRoot())
            all_subdirs = os.listdir(project_dir)
            return all_subdirs
        else:
            return []

    def find_settings_file(cwd):
        _file = "%s/%s" % (cwd, ReformSettings.reform_settings_file)
        if os.path.exists(_file):
            return _file
        else:
            if cwd == "/":
                """
                The file wasn't found and we reached root, raise error and exit
                """
                return False

            # Get parent directory
            return ReformSettings.find_settings_file(os.path.dirname(cwd))

    def get_quadrants(self):
        if self.reform_settings_path is not False:
            q = self.config.sections()
            return q
        else:
            return []

    def get_config(self, section=False, key=False):
        if section and key and self.config.has_option(section, key):
            self.logger.debug("Getting Specific Value: %s/%s" % (section, key))
            return self.config.get(section, key)
        else:
            self.logger.debug("No Value: %s/%s" % (section, key))
        return self.config

    def set_config_section(self, section, settings):

        try:
            self.config.add_section(section)
        except configparser.DuplicateSectionError:
            pass

        for k, v in settings.items():
            self.changed = True
            self.config.set(section, k, v)

    def GetReformRoot(self):
        return os.path.dirname(self.reform_settings_path)

    def InitReform(path):
        """
        Create a new reform project at the given path location
        """
        c = configparser.ConfigParser()
        c.add_section("global")
        reform_settings_path = "%s/%s" % (path, ReformSettings.reform_settings_file)
        if not os.path.exists(reform_settings_path):
            with open(reform_settings_path, "w+") as configfile:
                c.write(configfile)
            configfile.close()

        folders = ["configs", "modules", "projects"]
        for f in folders:
            os.makedirs("%s/%s" % (path, f), 0o755, True)

    def NewQuadrant(self, bucket, quadrant, region):

        # Step 1) make configs/${quadrant}/config.yaml if not exists
        quadrant_dir = "%s/configs/%s" % (self.GetReformRoot(), quadrant)
        os.makedirs(quadrant_dir, 0o755, True)

        config_file = "%s/%s" % (quadrant_dir, self.reform_quadrant_config_file)
        if not os.path.exists(config_file):
            config = {"state": {"bucket": bucket, "encrypt": True, "region": region}}

            with open(config_file, "w+") as _config_file:
                _config_file.write(
                    yaml.dump(config, Dumper=Dumper)
                )
            _config_file.close()

    def __del__(self):
        # Save changes on exit
        if self.changed:
            with open(self.reform_settings_path, "w+") as configfile:
                self.logger.debug(
                    "Serialize settings: %s to %s"
                    % (self.config, self.reform_settings_path)
                )
                self.config.write(configfile)
            configfile.close()
