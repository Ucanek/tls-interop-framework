from pathlib import Path
import unittest

import yaml
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPOSITORY_ROOT / ".coderabbit.yaml"


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects silently overwritten mapping keys."""


def construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)

    return mapping


UniqueKeyLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


class CodeRabbitConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config_text = CONFIG_PATH.read_text(encoding="utf-8")
        cls.config = yaml.safe_load(cls.config_text)

    def test_configuration_is_valid_yaml_without_duplicate_keys(self):
        strictly_loaded_config = yaml.load(
            self.config_text,
            Loader=UniqueKeyLoader,
        )

        self.assertIsInstance(strictly_loaded_config, dict)
        self.assertEqual(strictly_loaded_config, self.config)

    def test_reviews_use_the_assertive_profile_and_czech_locale(self):
        self.assertEqual(self.config["language"], "cs-CZ")
        self.assertEqual(self.config["reviews"]["profile"], "assertive")

    def test_automatic_reviews_run_only_for_non_draft_pull_requests(self):
        auto_review = self.config["reviews"]["auto_review"]

        self.assertIs(auto_review["enabled"], True)
        self.assertIs(auto_review["drafts"], False)

    def test_path_filters_exclude_expected_generated_artifacts(self):
        path_filters = self.config["reviews"]["path_filters"]

        self.assertCountEqual(
            path_filters,
            ["!interop_proto/**", "!debug_logs/**", "!certs/**"],
        )

    def test_path_filters_are_unique_negative_recursive_patterns(self):
        path_filters = self.config["reviews"]["path_filters"]

        self.assertEqual(len(path_filters), len(set(path_filters)))
        for path_filter in path_filters:
            with self.subTest(path_filter=path_filter):
                self.assertIsInstance(path_filter, str)
                self.assertTrue(path_filter.startswith("!"))
                self.assertTrue(path_filter.endswith("/**"))
                self.assertNotIn("//", path_filter)
                filtered_directory = path_filter.removeprefix("!").removesuffix("/**")
                self.assertGreater(len(filtered_directory), 0)

    def test_chat_automatically_replies(self):
        self.assertIs(self.config["chat"]["auto_reply"], True)


if __name__ == "__main__":
    unittest.main()
