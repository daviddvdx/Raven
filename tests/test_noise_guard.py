from core.noise_guard import NoiseGuard, get_noise_profile


def test_quiet_profile_defaults():
    profile = get_noise_profile()
    assert profile["requests_per_second"] == 1
    assert profile["threads"] == 1


def test_noise_guard_pauses_on_429_ratio():
    guard = NoiseGuard("quiet")
    guard.observe_result(429)
    assert guard.should_pause() is True
    assert guard.messages
