import json
from datetime import date
from types import SimpleNamespace

import plaid
import pytest

from app import plaid_client
from app.plaid_client import PlaidError, RealPlaid


def make_real():
    return RealPlaid("sandbox", ["CA"], client_id="cid", secret="sec")


def test_api_exception_maps_to_plaid_error_without_secrets():
    exc = plaid.ApiException(status=400, reason="Bad Request")
    exc.body = json.dumps(
        {"error_code": "ITEM_LOGIN_REQUIRED", "display_message": "Please relink", "request_id": "r", "secret": "s3"}
    )
    real = make_real()

    def boom(_request, **_kwargs):
        raise exc

    with pytest.raises(PlaidError) as caught:
        real._call(boom, object())
    assert caught.value.code == "ITEM_LOGIN_REQUIRED"
    assert caught.value.message == "Please relink"
    assert "s3" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


def test_unparseable_error_body_is_generic():
    exc = plaid.ApiException(status=500, reason="x")
    exc.body = "<html>oops access-token-123</html>"
    err = plaid_client._translate(exc)
    assert err.code == "UNKNOWN" and "access-token" not in str(err)


def test_link_token_request_shape():
    real = make_real()
    captured = {}

    def fake_create(request, **_kwargs):
        captured["req"] = request
        return {"link_token": "link-abc"}

    real._api = SimpleNamespace(link_token_create=fake_create)
    assert real.create_link_token() == "link-abc"
    req = captured["req"]
    assert [str(p.value) for p in req.products] == ["investments"]
    assert [str(p.value) for p in req.required_if_supported_products] == ["transactions"]
    assert not {"optional_products", "additional_consented_products", "access_token"} & set(req.to_dict())
    assert [str(c.value) for c in req.country_codes] == ["CA"]
    assert req.language == "en"
    assert req.client_name == "personal-finance-mcp"
    assert req.user.client_user_id == "owner"
    assert not hasattr(req, "redirect_uri") or "redirect_uri" not in req.to_dict()


def test_interface_has_no_money_movement():
    names = {n for n in dir(RealPlaid) if not n.startswith("_")}
    assert not {n for n in names if any(w in n for w in ("transfer", "payment", "auth", "sweep", "investments_move"))}


def test_every_call_has_a_request_timeout():
    real = make_real()
    seen = {}

    def spy(request, **kwargs):
        seen.update(kwargs)
        return {}

    real._call(spy, object())
    assert seen == {"_request_timeout": plaid_client.REQUEST_TIMEOUT}
    assert 0 < plaid_client.REQUEST_TIMEOUT <= 30


def test_only_investments_and_transactions_are_ever_requested():
    assert plaid_client.PRODUCTS == ["investments"]
    assert plaid_client.REQUIRED_IF_SUPPORTED_PRODUCTS == ["transactions"]


def test_update_mode_link_token_sends_access_token_and_no_products():
    real = make_real()
    captured = {}

    def fake_create(request, **_kwargs):
        captured["req"] = request
        return {"link_token": "link-update"}

    real._api = SimpleNamespace(link_token_create=fake_create)
    assert real.create_link_token("access-sandbox-existing") == "link-update"
    sent = captured["req"].to_dict()
    assert sent["access_token"] == "access-sandbox-existing"
    assert not {"products", "required_if_supported_products", "optional_products"} & set(sent)
    assert sent["user"] == {"client_user_id": "owner"} and sent["client_name"] == "personal-finance-mcp"


def test_investment_transactions_pages_merge_and_dedupe_securities():
    real = make_real()
    pages = [
        {"investment_transactions": [{"n": 1}, {"n": 2}], "total_investment_transactions": 3,
         "securities": [{"security_id": "a"}, {"security_id": "b"}]},
        {"investment_transactions": [{"n": 3}], "total_investment_transactions": 3,
         "securities": [{"security_id": "b"}, {"security_id": "c"}]},
    ]
    offsets = []

    def fake_get(request, **_kwargs):
        offsets.append(request.options.offset)
        return SimpleNamespace(to_dict=lambda page=pages[len(offsets) - 1]: page)

    real._api = SimpleNamespace(investments_transactions_get=fake_get)
    out = real.investments_transactions_get("tok", date(2024, 1, 1), date(2024, 2, 1))
    assert offsets == [0, 2]
    assert [t["n"] for t in out["investment_transactions"]] == [1, 2, 3]
    assert [s["security_id"] for s in out["securities"]] == ["a", "b", "c"]


def test_translate_uses_error_message_when_display_message_is_null():
    import json as _json
    import plaid as _plaid
    from app import plaid_client
    exc = _plaid.ApiException(status=400)
    exc.body = _json.dumps({"error_code": "INVALID_FIELD", "display_message": None,
                            "error_message": "client_name must be at most 30 characters for access-sandbox-abc-123"}).encode()
    err = plaid_client._translate(exc)
    assert err.code == "INVALID_FIELD"
    assert "client_name" in str(err) and "access-sandbox" not in str(err)
