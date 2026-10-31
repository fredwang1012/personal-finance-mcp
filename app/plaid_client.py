"""Thin read-only wrapper over plaid-python. Only investments and transactions are ever requested, and no
money-movement endpoint is wrapped. Methods return plain dicts so callers and test fakes share one shape."""
import json
import re
from datetime import date
from typing import Any, Protocol

import plaid
from plaid.api import plaid_api
from plaid.model.accounts_get_request import AccountsGetRequest
from plaid.model.country_code import CountryCode
from plaid.model.investments_holdings_get_request import InvestmentsHoldingsGetRequest
from plaid.model.investments_transactions_get_request import InvestmentsTransactionsGetRequest
from plaid.model.investments_transactions_get_request_options import InvestmentsTransactionsGetRequestOptions
from plaid.model.item_get_request import ItemGetRequest
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.item_remove_request import ItemRemoveRequest
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.transactions_sync_request import TransactionsSyncRequest

from app import secrets
from app.redact import clean_text

# Investments is required; transactions is used only where the institution supports it, so an institution without
# Transactions still links. These two are the only products ever requested.
PRODUCTS = ["investments"]
REQUIRED_IF_SUPPORTED_PRODUCTS = ["transactions"]
CLIENT_NAME = "personal-finance-mcp"
TOKEN_SHAPE = re.compile(r"(?:access|link|public)-[a-z]+-[\w-]+")
LOCAL_USER_ID = "owner"
_PAGE = 500
REQUEST_TIMEOUT = 30  # seconds, passed to every Plaid call


class PlaidError(Exception):
    """A Plaid API failure. Carries only Plaid's error code and display message, never request data."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class PlaidAPI(Protocol):
    def create_link_token(self, access_token: str | None = None) -> str: ...  # access_token: update mode
    def exchange_public_token(self, public_token: str) -> tuple[str, str]: ...  # (access_token, item_id)
    def accounts_get(self, access_token: str) -> dict[str, Any]: ...
    def investments_holdings_get(self, access_token: str) -> dict[str, Any]: ...
    def investments_transactions_get(self, access_token: str, start: date, end: date) -> dict[str, Any]: ...
    def transactions_sync(self, access_token: str, cursor: str | None = None) -> dict[str, Any]: ...
    def item_get(self, access_token: str) -> dict[str, Any]: ...
    def item_remove(self, access_token: str) -> None: ...


def _translate(exc: plaid.ApiException) -> PlaidError:
    code, message = "UNKNOWN", "Plaid request failed"
    try:
        body = json.loads(exc.body or "{}")
        code = body.get("error_code") or code
        # display_message is meant for end users and is often null; error_message says which field or key is wrong.
        # Plaid's messages carry no secrets, but they are cleaned and capped since they can reach model context.
        message = body.get("display_message") or body.get("error_message") or message
        message = TOKEN_SHAPE.sub("[redacted]", clean_text(str(message)))[:200]
    except (ValueError, TypeError, AttributeError):
        pass
    return PlaidError(code, message)


class RealPlaid:
    def __init__(self, env: str, country_codes: list[str], client_id: str | None = None, secret: str | None = None):
        host = {"sandbox": plaid.Environment.Sandbox, "production": plaid.Environment.Production}[env]
        config = plaid.Configuration(
            host=host,
            api_key={
                "clientId": client_id or secrets.get_client_id(),
                "secret": secret or secrets.get_plaid_secret(env),
            },
        )
        self._api = plaid_api.PlaidApi(plaid.ApiClient(config))
        self._country_codes = country_codes

    @classmethod
    def from_settings(cls, settings) -> "RealPlaid":
        return cls(settings.plaid_env, settings.country_codes)

    def _call(self, method, request):
        try:
            return method(request, _request_timeout=REQUEST_TIMEOUT)
        except plaid.ApiException as exc:
            raise _translate(exc) from None  # `from None` drops the original, whose text can include the body

    def create_link_token(self, access_token: str | None = None) -> str:
        """A Link token for a new Item, or, given an existing Item's access_token, for update mode (re-authenticate
        that Item). Update mode omits products, as Plaid requires, and creates no new Item."""
        if access_token:
            mode = {"access_token": access_token}
        else:
            mode = {
                "products": [Products(p) for p in PRODUCTS],
                "required_if_supported_products": [Products(p) for p in REQUIRED_IF_SUPPORTED_PRODUCTS],
            }
        request = LinkTokenCreateRequest(
            client_name=CLIENT_NAME,
            language="en",
            country_codes=[CountryCode(c) for c in self._country_codes],
            user=LinkTokenCreateRequestUser(client_user_id=LOCAL_USER_ID),
            **mode,
        )
        return self._call(self._api.link_token_create, request)["link_token"]

    def exchange_public_token(self, public_token: str) -> tuple[str, str]:
        response = self._call(
            self._api.item_public_token_exchange, ItemPublicTokenExchangeRequest(public_token=public_token)
        )
        return response["access_token"], response["item_id"]

    def accounts_get(self, access_token: str) -> dict[str, Any]:
        return self._call(self._api.accounts_get, AccountsGetRequest(access_token=access_token)).to_dict()

    def investments_holdings_get(self, access_token: str) -> dict[str, Any]:
        return self._call(
            self._api.investments_holdings_get, InvestmentsHoldingsGetRequest(access_token=access_token)
        ).to_dict()

    def investments_transactions_get(self, access_token: str, start: date, end: date) -> dict[str, Any]:
        result: dict[str, Any] | None = None
        while True:
            offset = len(result["investment_transactions"]) if result else 0
            page = self._call(
                self._api.investments_transactions_get,
                InvestmentsTransactionsGetRequest(
                    access_token=access_token,
                    start_date=start,
                    end_date=end,
                    options=InvestmentsTransactionsGetRequestOptions(count=_PAGE, offset=offset),
                ),
            ).to_dict()
            if result is None:
                result = page
                result["securities"] = list(result.get("securities") or [])
                seen = {s.get("security_id") for s in result["securities"]}
            else:
                result["investment_transactions"].extend(page["investment_transactions"])
                for security in page.get("securities") or []:
                    if security.get("security_id") not in seen:
                        seen.add(security.get("security_id"))
                        result["securities"].append(security)
            fetched = len(result["investment_transactions"])
            if not page["investment_transactions"] or fetched >= page["total_investment_transactions"]:
                return result

    def transactions_sync(self, access_token: str, cursor: str | None = None) -> dict[str, Any]:
        extra = {"cursor": cursor} if cursor else {}
        return self._call(
            self._api.transactions_sync, TransactionsSyncRequest(access_token=access_token, **extra)
        ).to_dict()

    def item_get(self, access_token: str) -> dict[str, Any]:
        return self._call(self._api.item_get, ItemGetRequest(access_token=access_token)).to_dict()

    def item_remove(self, access_token: str) -> None:
        self._call(self._api.item_remove, ItemRemoveRequest(access_token=access_token))
