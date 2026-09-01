from solve import decode_archive


def test_known_archive_decode():
    hex_blob = "ff9ec1aa51fb319b033871d8bf94d79830e1535f06cc1c2bf5b986c9c4d071c94ad3bc01ccd5674e846e270e46aef6a80e5f8b20aab11a84e7fb1cc1ece0bb69d2f302"
    ops = [11, 9, 10, 8, 0, 12, 16, 14, 6]
    assert decode_archive(hex_blob, ops) == "COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_Bz556NYuf7SooE1i}"
