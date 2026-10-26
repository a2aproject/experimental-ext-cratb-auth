# SPDX-License-Identifier: Apache-2.0
import time
from typing import Any, Dict, List, Optional
import jwt
from pydantic import BaseModel


class KitchenError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class KitchenState(BaseModel):
    ingredients: Dict[str, int] = {
        "cheese": 10,
        "gluten_free_bread": 5,
        "gluten_free_tortilla": 10,
        "butter": 20,
    }
    appliances: Dict[str, Dict[str, Any]] = {
        "oven": {"state": "idle", "temp_f": 0},
        "griddle": {"state": "idle", "temp_f": 0},
    }
    prepared_dishes: List[Dict[str, Any]] = []


class KitchenMCPServer:
    """
    Python HTTP MCP Server modeling the Kitchen domain (Stage 1).
    Enforces OAuth 2.0 JWT Bearer token authentication with scope checking.
    """
    def __init__(
        self,
        prm_url: str = "http://localhost:8081/.well-known/prm.json",
        # Dev-only demo secret. Real deployments MUST provision >=32 bytes and inject via config.
        jwt_signing_key: Optional[str] = "dev-only-demo-secret-change-me-32bytes-min",
    ) -> None:
        self.state = KitchenState()
        self.prm_url = prm_url
        self.jwt_signing_key = jwt_signing_key

    def _verify_bearer_token(
        self, auth_header: Optional[str], required_scope: str
    ) -> Dict[str, Any]:
        if not auth_header or not auth_header.startswith("Bearer "):
            raise KitchenError(
                f'Unauthorized: Missing Bearer token. See PRM at {self.prm_url}',
                status_code=401,
            )
        token = auth_header.split("Bearer ")[1].strip()
        try:
            payload = jwt.decode(
                token,
                key=self.jwt_signing_key,
                algorithms=["HS256"],
            )
        except Exception as e:
            raise KitchenError(f"Unauthorized: Invalid token ({str(e)})", status_code=401)

        scopes = payload.get("scope", "").split()
        if required_scope not in scopes:
            raise KitchenError(
                f"Forbidden: Token lacks required scope '{required_scope}'",
                status_code=403,
            )
        return payload

    def list_ingredients(self, auth_header: Optional[str] = None) -> Dict[str, int]:
        self._verify_bearer_token(auth_header, "kitchen:enter")
        return self.state.ingredients

    def retrieve_ingredient(
        self, name: str, quantity: int = 1, auth_header: Optional[str] = None
    ) -> Dict[str, Any]:
        self._verify_bearer_token(auth_header, "kitchen:enter")
        available = self.state.ingredients.get(name, 0)
        if available < quantity:
            raise KitchenError(
                f"Out of stock: requested {quantity} of '{name}', but only {available} available",
                status_code=409,
            )
        self.state.ingredients[name] -= quantity
        return {"ingredient": name, "quantity": quantity, "remaining": self.state.ingredients[name]}

    def use_appliance(
        self,
        appliance_name: str,
        action: str,
        temp_f: int = 0,
        auth_header: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._verify_bearer_token(auth_header, "kitchen:appliances:use")
        if appliance_name not in self.state.appliances:
            raise KitchenError(f"Appliance '{appliance_name}' not found", status_code=404)

        app = self.state.appliances[appliance_name]
        app["state"] = action
        if temp_f > 0:
            app["temp_f"] = temp_f
        return {"appliance": appliance_name, "status": app}

    def prepare_dish(
        self, dish_name: str, ingredients: List[str], auth_header: Optional[str] = None
    ) -> Dict[str, Any]:
        self._verify_bearer_token(auth_header, "kitchen:appliances:use")
        for ing in ingredients:
            if self.state.ingredients.get(ing, 0) <= 0:
                raise KitchenError(
                    f"Cannot prepare dish '{dish_name}': ingredient '{ing}' is depleted",
                    status_code=409,
                )
            self.state.ingredients[ing] -= 1

        dish = {
            "dish_name": dish_name,
            "ingredients": ingredients,
            "prepared_at": int(time.time()),
        }
        self.state.prepared_dishes.append(dish)
        return dish
