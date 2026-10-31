from app import cli, csvimport, link, redact, server, tools


def test_short_hash_is_stable_and_short():
    assert redact.short_hash("item-1") == redact.short_hash("item-1")
    assert len(redact.short_hash("item-1")) == 8 and "item-1" not in redact.short_hash("item-1")


def test_clean_text_masks_numbers_and_control_chars():
    assert redact.clean_text("Acct\x00 1234 5678 9012", "") == "Acct •••9012"
    assert redact.clean_text("TFSA AB12CD34", "AB12CD34") == "TFSA •••CD34"
    assert len(redact.clean_text("x" * 1000)) == redact.MAX_TEXT


def test_modules_share_one_implementation():
    for module in (cli, link, server, tools):
        assert module.short_hash is redact.short_hash
    for module in (cli, csvimport, tools):
        assert module.clean_text is redact.clean_text
    assert not hasattr(tools, "_short") and not hasattr(csvimport, "_text")


def test_clean_text_replaces_links_and_emails():
    out = redact.clean_text("see https://evil.example/x?a=1 or www.evil.example, mail bob.smith+x@evil.co.uk now")
    assert out == "see [link] or [link] mail [email] now"
    assert redact.cut("x" * 100, 60) == "x" * 59 + "…" and redact.cut("short", 60) == "short"
