from core.interactive import InteractiveSession


def session_with_answers(answers):
    iterator = iter(answers)
    return InteractiveSession(input_func=lambda _prompt: next(iterator, ""))


def test_ask_yes_no_accepts_french_and_english():
    session = session_with_answers(["oui", "n"])
    assert session.ask_yes_no("Continuer ?") is True
    assert session.ask_yes_no("Continuer ?", default=True) is False


def test_ask_yes_no_uses_default_on_empty():
    session = session_with_answers([""])
    assert session.ask_yes_no("Continuer ?", default=True) is True


def test_ask_int_retries_out_of_range():
    session = session_with_answers(["99", "4"])
    assert session.ask_int("Noise", min_value=1, max_value=10, default=3) == 4


def test_ask_choice_retries_invalid_value():
    session = session_with_answers(["loud", "quiet"])
    assert session.ask_choice("Profile", ["quiet", "balanced", "deep"], "quiet") == "quiet"
