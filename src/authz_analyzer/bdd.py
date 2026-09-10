from collections.abc import Iterable, Mapping
from enum import StrEnum

type Variable = str
type NodeRef = int
type Level = int
type Node = tuple[Level, NodeRef, NodeRef]
type ITEKey = tuple[NodeRef, NodeRef, NodeRef]
type ITERequest = tuple[ITEKey, int]
type PendingITE = tuple[Level, ITERequest, ITERequest]


class BDDOperation(StrEnum):
    NOT = "not"
    AND = "and"
    OR = "or"
    XOR = "xor"
    IMPLIES = "implies"
    EQUIV = "equiv"
    ITE = "ite"


class BDDNodeLimitError(RuntimeError):
    pass


class BinaryDecisionDiagram:
    """Reduced ordered BDD manager with complemented edges.

    Node references are manager-local signed integers. Reference `1` is true,
    `-1` is false, and negating any reference complements its function.
    """

    TRUE = 1
    FALSE = -1

    def __init__(
        self,
        variables: Iterable[Variable] = (),
        *,
        max_nodes: int | None = None,
        max_computed_cache_entries: int | None = None,
    ) -> None:
        if max_nodes is not None and max_nodes < 0:
            raise ValueError("max_nodes must be non-negative")
        if (
            max_computed_cache_entries is not None
            and max_computed_cache_entries < 0
        ):
            raise ValueError("max_computed_cache_entries must be non-negative")
        self._variables = tuple(variables)
        if any(not isinstance(variable, str) for variable in self._variables):
            raise TypeError("BDD variables must be strings")
        if len(set(self._variables)) != len(self._variables):
            raise ValueError("BDD variables must be unique")

        self._max_nodes = max_nodes
        self._max_computed_cache_entries = max_computed_cache_entries
        self._levels = {
            variable: level for level, variable in enumerate(self._variables)
        }
        self._nodes: list[Node] = [
            (0, 0, 0),
            (len(self._variables), 0, 0),
        ]
        self._unique: dict[Node, NodeRef] = {}
        self._computed: dict[ITEKey, NodeRef] = {}

    @property
    def node_count(self) -> int:
        return len(self._nodes) - 2

    @property
    def variables(self) -> tuple[Variable, ...]:
        return self._variables

    def clear_computed_cache(self) -> None:
        self._computed.clear()

    def statistics(self) -> dict[str, int]:
        return {
            "node_count": self.node_count,
            "computed_cache_size": len(self._computed),
        }

    def _level_of_var(self, variable: Variable) -> Level:
        try:
            return self._levels[variable]
        except KeyError:
            raise ValueError(f"Undeclared variable: {variable}") from None

    def var(self, variable: Variable) -> NodeRef:
        return self._find_or_add(
            self._level_of_var(variable), self.FALSE, self.TRUE
        )

    def _find_or_add(self, level: Level, low: NodeRef, high: NodeRef) -> NodeRef:
        if not 0 <= level < len(self._variables):
            raise ValueError(f"Invalid level: {level}")
        self._validate_ref(low)
        self._validate_ref(high)

        complement = 1
        if high < 0:
            low, high, complement = -low, -high, -1
        if low == high:
            return complement * low

        for child in (low, high):
            if abs(child) != self.TRUE and self._nodes[abs(child)][0] <= level:
                raise ValueError("BDD children must be ordered after their parent")

        node = (level, low, high)
        existing = self._unique.get(node)
        if existing is not None:
            return complement * existing

        if self._max_nodes is not None and self.node_count >= self._max_nodes:
            raise BDDNodeLimitError(f"BDD node limit exceeded: {self._max_nodes}")
        ref = len(self._nodes)
        self._nodes.append(node)
        self._unique[node] = ref
        return complement * ref

    def apply(
        self,
        operation: BDDOperation,
        *operands: NodeRef,
    ) -> NodeRef:
        if not isinstance(operation, BDDOperation):
            raise TypeError("operation must be a BDDOperation")
        if operation is BDDOperation.NOT:
            arity = 1
        elif operation is BDDOperation.ITE:
            arity = 3
        else:
            arity = 2
        if len(operands) != arity:
            raise ValueError(
                f"{operation} requires {arity} operands, got {len(operands)}"
            )
        for ref in operands:
            self._validate_ref(ref)

        if operation is BDDOperation.NOT:
            return -operands[0]

        first, second = operands[:2]
        if operation in {
            BDDOperation.AND,
            BDDOperation.OR,
            BDDOperation.XOR,
            BDDOperation.EQUIV,
        } and first > second:
            first, second = second, first
        if operation is BDDOperation.AND:
            return self._ite(first, second, self.FALSE)
        if operation is BDDOperation.OR:
            return self._ite(first, self.TRUE, second)
        if operation is BDDOperation.XOR:
            return self._ite(first, -second, second)
        if operation is BDDOperation.IMPLIES:
            return self._ite(first, second, self.TRUE)
        if operation is BDDOperation.EQUIV:
            return self._ite(first, second, -second)
        return self._ite(first, second, operands[2])

    def _ite(
        self, condition: NodeRef, then_ref: NodeRef, else_ref: NodeRef
    ) -> NodeRef:
        root_key, root_sign = self._normalize_ite(condition, then_ref, else_ref)
        results: dict[ITEKey, NodeRef] = {}
        pending: dict[ITEKey, PendingITE] = {}
        stack = [(root_key, False)]

        # Resolve the dependency graph in postorder without Python recursion.
        while stack:
            key, expanded = stack.pop()
            if key in results:
                continue
            immediate = self._ite_reduction(key)
            if immediate is not None:
                results[key] = immediate
                continue
            cached = self._computed.get(key)
            if cached is not None:
                results[key] = cached
                continue
            if expanded:
                level, low_request, high_request = pending.pop(key)
                low_key, low_sign = low_request
                high_key, high_sign = high_request
                low = low_sign * results[low_key]
                high = high_sign * results[high_key]
                result = self._find_or_add(level, low, high)
                self._cache_computed(key, result)
                results[key] = result
                continue

            condition_ref, then_ref, else_ref = key
            level = min(
                self._nodes[abs(condition_ref)][0],
                self._nodes[abs(then_ref)][0],
                self._nodes[abs(else_ref)][0],
            )
            condition_low, condition_high = self._top_cofactor(
                condition_ref, level
            )
            then_low, then_high = self._top_cofactor(then_ref, level)
            else_low, else_high = self._top_cofactor(else_ref, level)
            low_request = self._normalize_ite(
                condition_low, then_low, else_low
            )
            high_request = self._normalize_ite(
                condition_high, then_high, else_high
            )
            pending[key] = (level, low_request, high_request)
            stack.append((key, True))
            stack.append((high_request[0], False))
            stack.append((low_request[0], False))

        return root_sign * results[root_key]

    def _cache_computed(
        self, key: ITEKey, result: NodeRef
    ) -> None:
        limit = self._max_computed_cache_entries
        if limit == 0:
            return
        if limit is not None and len(self._computed) >= limit:
            self._computed.clear()
        self._computed[key] = result

    def _normalize_ite(
        self, condition: NodeRef, then: NodeRef, otherwise: NodeRef
    ) -> ITERequest:
        if condition < 0:
            condition, then, otherwise = -condition, otherwise, then
        sign = 1
        if then < 0 and otherwise < 0:
            then, otherwise, sign = -then, -otherwise, -1
        return (condition, then, otherwise), sign

    def _ite_reduction(
        self, key: ITEKey
    ) -> NodeRef | None:
        condition, then, otherwise = key
        if condition == self.TRUE:
            return then
        if then == otherwise:
            return then
        if then == self.TRUE and otherwise == self.FALSE:
            return condition
        if then == self.FALSE and otherwise == self.TRUE:
            return -condition
        return None

    def _top_cofactor(self, ref: NodeRef, level: Level) -> tuple[NodeRef, NodeRef]:
        if abs(ref) == self.TRUE:
            return ref, ref
        ref_level, low, high = self._nodes[abs(ref)]
        if level < ref_level:
            return ref, ref
        return (-low, -high) if ref < 0 else (low, high)

    def restrict(
        self, root: NodeRef, assignments: Mapping[Variable, bool]
    ) -> NodeRef:
        self._validate_ref(root)
        if any(type(value) is not bool for value in assignments.values()):
            raise TypeError("BDD assignments must contain boolean values")
        values = {
            self._level_of_var(variable): value
            for variable, value in assignments.items()
        }
        if not values or abs(root) == self.TRUE:
            return root

        memo: dict[int, NodeRef] = {self.TRUE: self.TRUE}
        stack = [(abs(root), False)]

        def resolved(ref: NodeRef) -> NodeRef:
            result = memo[abs(ref)]
            return -result if ref < 0 else result

        while stack:
            index, expanded = stack.pop()
            if index in memo:
                continue
            level, low, high = self._nodes[index]
            if expanded:
                if level in values:
                    memo[index] = resolved(high if values[level] else low)
                else:
                    memo[index] = self._find_or_add(
                        level, resolved(low), resolved(high)
                    )
                continue
            stack.append((index, True))
            for child in (high, low):
                if abs(child) not in memo:
                    stack.append((abs(child), False))

        return resolved(root)

    def support(self, root: NodeRef) -> tuple[Variable, ...]:
        self._validate_ref(root)
        levels: set[Level] = set()
        visited: set[int] = set()
        stack = [abs(root)]
        while stack:
            index = stack.pop()
            if index in visited or index == self.TRUE:
                continue
            visited.add(index)
            level, low, high = self._nodes[index]
            levels.add(level)
            stack.extend((abs(high), abs(low)))
        return tuple(self._variables[level] for level in sorted(levels))

    def is_satisfiable(self, root: NodeRef) -> bool:
        self._validate_ref(root)
        return root != self.FALSE

    def pick_sat(self, root: NodeRef) -> dict[Variable, bool] | None:
        """Return a partial witness, deterministically preferring false branches."""
        self._validate_ref(root)
        if root == self.FALSE:
            return None

        assignment: dict[Variable, bool] = {}
        while root != self.TRUE:
            level, low, high = self._nodes[abs(root)]
            if root < 0:
                low, high = -low, -high
            value = low == self.FALSE
            assignment[self._variables[level]] = value
            root = high if value else low
        return assignment

    def exists(self, root: NodeRef, variables: Iterable[Variable]) -> NodeRef:
        return self._quantify(root, variables, for_all=False)

    def forall(self, root: NodeRef, variables: Iterable[Variable]) -> NodeRef:
        return self._quantify(root, variables, for_all=True)

    def _quantify(
        self, root: NodeRef, variables: Iterable[Variable], *, for_all: bool
    ) -> NodeRef:
        self._validate_ref(root)
        levels = {self._level_of_var(variable) for variable in variables}
        if not levels or abs(root) == self.TRUE:
            return root

        memo = {self.TRUE: self.TRUE, self.FALSE: self.FALSE}
        stack = [(root, False)]
        while stack:
            ref, expanded = stack.pop()
            if ref in memo:
                continue
            level, raw_low, raw_high = self._nodes[abs(ref)]
            low, high = (
                (-raw_low, -raw_high) if ref < 0 else (raw_low, raw_high)
            )
            if expanded:
                new_low, new_high = memo[low], memo[high]
                if level in levels:
                    memo[ref] = (
                        self._ite(new_low, new_high, self.FALSE)
                        if for_all
                        else self._ite(new_low, self.TRUE, new_high)
                    )
                else:
                    memo[ref] = self._find_or_add(level, new_low, new_high)
                continue
            stack.append((ref, True))
            if high not in memo:
                stack.append((high, False))
            if low not in memo:
                stack.append((low, False))
        return memo[root]

    def evaluate(self, root: NodeRef, assignment: Mapping[Variable, bool]) -> bool:
        self._validate_ref(root)
        ref = root
        while abs(ref) != self.TRUE:
            level, low, high = self._nodes[abs(ref)]
            if ref < 0:
                low, high = -low, -high
            variable = self._variables[level]
            try:
                value = assignment[variable]
            except KeyError:
                raise ValueError(
                    f"Missing assignment for variable: {variable}"
                ) from None
            if type(value) is not bool:
                raise TypeError("BDD assignments must contain boolean values")
            ref = high if value else low
        return ref == self.TRUE

    def _validate_ref(self, ref: NodeRef) -> None:
        if (
            not isinstance(ref, int)
            or isinstance(ref, bool)
            or not 1 <= abs(ref) < len(self._nodes)
        ):
            raise ValueError(f"No node with ID: {ref}")
