from __future__ import annotations
from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import List, Iterable, Dict, Any
import sys
import os

# ============================
# Utilidades de interfaz (CLI)
# ============================

def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") not in {"dumb", None}

class UI:
    OK = "\x1b[32m" if supports_color() else ""
    BAD = "\x1b[31m" if supports_color() else ""
    INFO = "\x1b[36m" if supports_color() else ""
    EMPH = "\x1b[35m" if supports_color() else ""
    BOLD = "\x1b[1m" if supports_color() else ""
    RESET = "\x1b[0m" if supports_color() else ""

    @staticmethod
    def ok(text: str) -> str:
        return f"{UI.OK}{text}{UI.RESET}"

    @staticmethod
    def bad(text: str) -> str:
        return f"{UI.BAD}{text}{UI.RESET}"

    @staticmethod
    def info(text: str) -> str:
        return f"{UI.INFO}{text}{UI.RESET}"

    @staticmethod
    def emph(text: str) -> str:
        return f"{UI.EMPH}{text}{UI.RESET}"

    @staticmethod
    def bold(text: str) -> str:
        return f"{UI.BOLD}{text}{UI.RESET}"

    @staticmethod
    def title(text: str) -> None:
        bar = "═" * (len(text) + 2)
        print(UI.emph(f"╔{bar}╗"))
        print(UI.emph(f"║ {UI.bold(text)} ║"))
        print(UI.emph(f"╚{bar}╝"))

    @staticmethod
    def clear() -> None:
        try:
            os.system("cls" if os.name == "nt" else "clear")
        except Exception:
            pass

# ===============
# Núcleo de reglas
# ===============

class Rule(ABC):
    """Interfaz base de una Regla lógica."""
    name: str = ""

    @abstractmethod
    def evaluate(self, password: str) -> bool:
        """Evalúa una contraseña (True/False)."""
        raise NotImplementedError

    def leaves(self) -> List["Rule"]:
        return [self]

    def __and__(self, other: "Rule") -> "And":
        return And([self, other])

    def __or__(self, other: "Rule") -> "Or":
        return Or([self, other])

    def __invert__(self) -> "Not":
        return Not(self)


@dataclass
class AlwaysTrue(Rule):
    name: str = "TRUE"

    def evaluate(self, password: str) -> bool:
        return True


@dataclass
class HasLetter(Rule):
    name: str = "letra"

    def evaluate(self, password: str) -> bool:
        return any(ch.isalpha() for ch in password)


@dataclass
class HasDigit(Rule):
    name: str = "numero"

    def evaluate(self, password: str) -> bool:
        return any(ch.isdigit() for ch in password)


@dataclass
class HasUpper(Rule):
    name: str = "mayuscula"

    def evaluate(self, password: str) -> bool:
        return any(ch.isupper() for ch in password)


@dataclass
class HasLower(Rule):
    name: str = "minuscula"

    def evaluate(self, password: str) -> bool:
        return any(ch.islower() for ch in password)


@dataclass
class NoSymbols(Rule):
    name: str = "sin_simbolos"

    def evaluate(self, password: str) -> bool:
        return all(ch.isalnum() for ch in password)


@dataclass
class HasSymbol(Rule):
    name: str = "simbolo"

    def evaluate(self, password: str) -> bool:
        return any(not ch.isalnum() for ch in password)


@dataclass
class MinLength(Rule):
    k: int
    name: str = "min"

    def __post_init__(self):
        self.name = f"min:{self.k}"

    def evaluate(self, password: str) -> bool:
        return len(password) >= self.k


@dataclass
class MaxLength(Rule):
    k: int
    name: str = "max"

    def __post_init__(self):
        self.name = f"max:{self.k}"

    def evaluate(self, password: str) -> bool:
        return len(password) <= self.k


@dataclass
class ContainsText(Rule):
    text: str
    ignore_case: bool = False
    name: str = "incluye"

    def __post_init__(self):
        suf = " (i)" if self.ignore_case else ""
        self.name = f'incluye:"{self.text}"{suf}'

    def evaluate(self, password: str) -> bool:
        haystack = password.lower() if self.ignore_case else password
        needle = self.text.lower() if self.ignore_case else self.text
        return needle in haystack


@dataclass
class NotContainsText(Rule):
    text: str
    ignore_case: bool = False
    name: str = "excluye"

    def __post_init__(self):
        suf = " (i)" if self.ignore_case else ""
        self.name = f'excluye:"{self.text}"{suf}'

    def evaluate(self, password: str) -> bool:
        haystack = password.lower() if self.ignore_case else password
        needle = self.text.lower() if self.ignore_case else self.text
        return needle not in haystack


@dataclass
class And(Rule):
    rules: List[Rule]
    name: str = "AND"

    def evaluate(self, password: str) -> bool:
        return all(r.evaluate(password) for r in self.rules)

    def leaves(self) -> List[Rule]:
        out: List[Rule] = []
        for r in self.rules:
            out.extend(r.leaves())
        return out


@dataclass
class Or(Rule):
    rules: List[Rule]
    name: str = "OR"

    def evaluate(self, password: str) -> bool:
        return any(r.evaluate(password) for r in self.rules)

    def leaves(self) -> List[Rule]:
        out: List[Rule] = []
        for r in self.rules:
            out.extend(r.leaves())
        return out


@dataclass
class Not(Rule):
    rule: Rule
    name: str = "NOT"

    def evaluate(self, password: str) -> bool:
        return not self.rule.evaluate(password)

    def leaves(self) -> List[Rule]:
        return self.rule.leaves()


@dataclass
class EvalNode:
    value: bool
    label: str
    children: List["EvalNode"]

    def pretty(self, prefix: str = "") -> List[str]:
        icon = UI.ok("✔") if self.value else UI.bad("✘")
        lines = [f"{prefix}[{icon}] {self.label}"]
        for i, ch in enumerate(self.children):
            is_last = i == len(self.children) - 1
            branch = "└─ " if is_last else "├─ "
            child_prefix = prefix + ("   " if is_last else "│  ")
            sub = ch.pretty("")
            if sub:
                lines.append(prefix + branch + sub[0])
                for rest in sub[1:]:
                    lines.append(child_prefix + rest)
        return lines


def build_eval_tree(rule: Rule, password: str) -> EvalNode:
    if isinstance(rule, And):
        kids = [build_eval_tree(r, password) for r in rule.rules]
        return EvalNode(all(k.value for k in kids), "AND", kids)
    if isinstance(rule, Or):
        kids = [build_eval_tree(r, password) for r in rule.rules]
        return EvalNode(any(k.value for k in kids), "OR", kids)
    if isinstance(rule, Not):
        kid = build_eval_tree(rule.rule, password)
        return EvalNode(not kid.value, "NOT", [kid])
    val = rule.evaluate(password)
    return EvalNode(val, rule.name, [])


def print_table(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print(UI.info("(sin datos)"))
        return
    keys = [k for k in rows[0].keys() if k != "password"]
    atoms = sorted([k for k in keys if k != "valid"])
    cols = ["password"] + atoms + ["valid"]

    def fmt(v: Any) -> str:
        if isinstance(v, bool):
            return UI.ok("✔") if v else UI.bad("✘")
        return str(v)

    widths = {c: max(len(c), max(len(fmt(r.get(c, ""))) for r in rows)) for c in cols}

    header = " | ".join(UI.bold(c.ljust(widths[c])) for c in cols)
    print(header)
    print(UI.info("-" * len(header)))

    for r in rows:
        out = []
        for c in cols:
            val = fmt(r.get(c, ""))
            out.append(val.ljust(widths[c]))
        print(" | ".join(out))


def rule_to_text(rule: Rule) -> str:
    if isinstance(rule, And):
        return "AND(" + ", ".join(rule_to_text(r) for r in rule.rules) + ")"
    if isinstance(rule, Or):
        return "OR(" + ", ".join(rule_to_text(r) for r in rule.rules) + ")"
    if isinstance(rule, Not):
        return "NOT(" + rule_to_text(rule.rule) + ")"
    return rule.name


# -------------- Orquestador --------------
@dataclass
class PasswordValidator:
    rule: Rule

    def check(self, password: str) -> Dict[str, Any]:
        leaves = self.rule.leaves()
        detail = {r.name: r.evaluate(password) for r in leaves}
        overall = self.rule.evaluate(password)
        detail["valid"] = overall
        return detail

    def check_many(self, passwords: Iterable[str]) -> List[Dict[str, Any]]:
        result = []
        for pw in passwords:
            row = {"password": pw}
            row.update(self.check(pw))
            result.append(row)
            
        return result


def ask_yes_no(prompt: str, default: bool | None = None) -> bool:
    while True:
        suf = " [S/n]" if default is True else (" [s/N]" if default is False else " [s/n]")
        ans = input(prompt + suf + ": ").strip().lower()
        if not ans and default is not None:
            return default
        if ans in ("s", "si", "sí", "y", "yes"):  # español/inglés
            return True
        if ans in ("n", "no"):
            return False
        print(UI.bad("→ Responde con 's' o 'n'."))


def ask_int(prompt: str, allow_empty: bool = True) -> int | None:
    while True:
        ans = input(prompt + (" (ENTER para omitir)" if allow_empty else "") + ": ").strip()
        if not ans and allow_empty:
            return None
        if ans.isdigit():
            return int(ans)
        print(UI.bad("→ Ingresa un número entero válido."))


def ask_choice(prompt: str, choices: Dict[str, str], default: str | None = None) -> str:
    ks = "/".join(choices.keys())
    while True:
        ans = input(f"{prompt} [{ks}]" + (f" (ENTER={default})" if default else "") + ": ").strip()
        if not ans and default:
            return default
        if ans in choices:
            return ans
        print(UI.bad("→ Opción inválida."))


def build_rule_quick() -> Rule:
    UI.title("Constructor rápido de regla")
    rules: List[Rule] = []

    if ask_yes_no("¿Requiere al menos 1 letra?", True):
        rules.append(HasLetter())
    if ask_yes_no("¿Requiere al menos 1 número?", True):
        rules.append(HasDigit())
    if ask_yes_no("¿Requiere al menos 1 mayúscula?", False):
        rules.append(HasUpper())
    if ask_yes_no("¿Requiere al menos 1 minúscula?", False):
        rules.append(HasLower())

    print(UI.info("\nSímbolos:"))
    print("  1) Prohibir símbolos (solo alfanumérico)")
    print("  2) Exigir al menos 1 símbolo")
    print("  3) No aplicar condición sobre símbolos")
    choice = ask_choice("Elige", {"1": "NoSymbols", "2": "HasSymbol", "3": "None"}, default="3")
    if choice == "1":
        rules.append(NoSymbols())
    elif choice == "2":
        rules.append(HasSymbol())

    kmin = ask_int("Longitud mínima")
    if kmin is not None:
        rules.append(MinLength(kmin))
    kmax = ask_int("Longitud máxima")
    if kmax is not None:
        rules.append(MaxLength(kmax))

    # Búsquedas de texto con opción de ignorar mayúsculas/minúsculas
    if ask_yes_no("¿Deseas agregar condiciones de 'incluye/excluye' texto?", False):
        ignore = ask_yes_no("¿Ignorar mayúsculas/minúsculas al buscar?", True)
        contains = input("Texto obligatorio (ENTER para omitir): ").strip()
        if contains:
            rules.append(ContainsText(contains, ignore_case=ignore))
        not_contains = input("Texto a excluir (ENTER para omitir): ").strip()
        if not_contains:
            rules.append(NotContainsText(not_contains, ignore_case=ignore))

    if not rules:
        print(UI.info("No agregaste condiciones; la regla será TRUE (siempre válida)."))
        return AlwaysTrue()
    return And(rules) if len(rules) > 1 else rules[0]

DEFAULT_RULE: Rule = And([HasLetter(), HasDigit(), MinLength(8), NoSymbols()])
DEFAULT_PASSWORDS = [
    "abc12345",
    "abcdefg",
    "12345678",
    "abc123!@#",
    "Py3",
    "Python123",
]


def run_demo(validator: PasswordValidator) -> None:
    UI.title("DEMOSTRACIÓN")
    print(UI.info("Regla actual:"), UI.bold(rule_to_text(validator.rule)))
    rows = validator.check_many(DEFAULT_PASSWORDS)
    print_table(rows)
    sample = DEFAULT_PASSWORDS[0]
    print(f"\nÁrbol para: {UI.emph(sample)}")
    tree = build_eval_tree(validator.rule, sample)
    for ln in tree.pretty():
        print(ln)


def run_manual(validator: PasswordValidator) -> None:
    UI.title("PRUEBA MANUAL")
    print(UI.info("Regla actual:"), UI.bold(rule_to_text(validator.rule)))
    print(UI.info("(ENTER sin escribir nada para terminar)"))
    while True:
        pw = input("Escribe la contraseña a evaluar: ").strip()
        if pw == "":
            break
        row = validator.check(pw)
        rows = [{"password": pw, **row}]
        print_table(rows)
        print("Árbol de evaluación:")
        tree = build_eval_tree(validator.rule, pw)
        for ln in tree.pretty():
            print(ln)
        print()

# -------------- MENÚ PRINCIPAL --------------

def main() -> None:
    rule: Rule = DEFAULT_RULE
    validator = PasswordValidator(rule)

    while True:
        UI.clear()
        UI.title("Validador lógico de contraseñas")
        print(UI.info("Regla actual:"), UI.bold(rule_to_text(validator.rule)))
        print()
        print("1) Ver demostración")
        print("2) Probar manualmente")
        print("3) Cambiar regla (constructor rápido)")
        print("4) Salir")
        opt = input(UI.emph("Elige una opción [1-4]: ")).strip()

        if opt == "1":
            UI.clear()
            run_demo(validator)
            input(UI.info("\nPresiona ENTER para continuar..."))
        elif opt == "2":
            UI.clear()
            run_manual(validator)
            input(UI.info("\nPresiona ENTER para continuar..."))
        elif opt == "3":
            UI.clear()
            rule = build_rule_quick()
            validator = PasswordValidator(rule)
            print("\n" + UI.ok("✔ Regla actualizada a:"), UI.bold(rule_to_text(rule)))
            print(UI.info("\nAhora pasamos directamente a PRUEBA MANUAL..."))
            run_manual(validator)
            input(UI.info("\nPresiona ENTER para volver al menú..."))
        elif opt == "4":
            print(UI.info("Adiós!"))
            return
        else:
            print(UI.bad("Opción no válida."))
            input(UI.info("\nPresiona ENTER para continuar..."))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + UI.info("Interrumpido por el usuario."))
        sys.exit(0)
