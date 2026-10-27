# SPDX-License-Identifier: Apache-2.0
"""Kitchen resource backend.

Enforces scope permissions and keeps the ingredient inventory in memory.
"""

from enum import Enum
from typing import Any, Dict, List


class KitchenScope(str, Enum):
    """Kitchen access scopes."""

    ENTER = "kitchen:enter"
    APPLIANCES_USE = "kitchen:appliances:use"


class KitchenError(Exception):
    """Raised for kitchen access denial or resource conflicts."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class KitchenAPI:
    """Kitchen resource operations with scope enforcement."""

    def __init__(self) -> None:
        self._ingredients: Dict[str, int] = {
            "cheese": 10,
            "gluten_free_bread": 0,
            "gluten_free_tortilla": 10,
            "butter": 20,
        }

    def _require_scope(self, granted_scopes: List[str], required: KitchenScope) -> None:
        """Validate presence of required scope."""
        if required.value not in granted_scopes:
            raise KitchenError(
                f"Missing required scope '{required.value}'", status_code=403
            )

    def list_ingredients(self, granted_scopes: List[str]) -> Dict[str, int]:
        """Return inventory of ingredients."""
        self._require_scope(granted_scopes, KitchenScope.ENTER)
        return dict(self._ingredients)

    def prepare_dish(
        self, dish_name: str, ingredients: List[str], granted_scopes: List[str]
    ) -> Dict[str, Any]:
        """Prepare dish by consuming ingredients from inventory."""
        self._require_scope(granted_scopes, KitchenScope.APPLIANCES_USE)

        for ingredient in ingredients:
            if self._ingredients.get(ingredient, 0) <= 0:
                raise KitchenError(
                    f"Cannot prepare '{dish_name}': ingredient '{ingredient}' is depleted",
                    status_code=409,
                )

        for ingredient in ingredients:
            self._ingredients[ingredient] -= 1

        return {"dish_name": dish_name, "ingredients": ingredients}


# Shared in-memory kitchen instance.
kitchen = KitchenAPI()
