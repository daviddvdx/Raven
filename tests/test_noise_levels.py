from core.noise_guard import is_noise_allowed_for_yes, noise_level_config, requires_strong_confirmation_for_noise


def test_noise_1_disables_fuzz():
    config = noise_level_config(1)
    assert config["allow_fuzz"] is False
    assert config["allow_post"] is False


def test_noise_10_requires_strong_confirmation():
    assert requires_strong_confirmation_for_noise(10) is True


def test_yes_cannot_accept_aggressive_noise():
    assert is_noise_allowed_for_yes(9) is False
    assert is_noise_allowed_for_yes(3) is True
