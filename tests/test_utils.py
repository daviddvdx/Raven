from core.utils import parse_int_csv, slugify


def test_parse_int_csv_ignores_invalid_items():
    assert parse_int_csv("200,abc,404") == {200, 404}


def test_slugify():
    assert slugify("Example Project!") == "example-project"
