import json
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

    def boom(_request):
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

    def fake_create(request):
        captured["req"] = request
        return {"link_token": "link-abc"}

    real._api = SimpleNamespace(link_token_create=fake_create)
    assert real.create_link_token() == "link-abc"
    req = captured["req"]
    assert [str(p.value) for p in req.products] == ["investments", "transactions"]
    assert [str(c.value) for c in req.country_codes] == ["CA"]
    assert req.language == "en"
    assert req.client_name == "personal-finance-mcp"
    assert req.user.client_user_id == "owner"
    assert not hasattr(req, "redirect_uri") or "redirect_uri" not in req.to_dict()


def test_interface_has_no_money_movement():
    names = {n for n in dir(RealPlaid) if not n.startswith("_")}
    assert not {n for n in names if any(w in n for w in ("transfer", "payment", "auth", "sweep", "investments_move"))}
