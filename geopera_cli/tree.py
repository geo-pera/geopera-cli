"""Structured command tree generated from the kernel operation registry.

Every operation id maps to a nested command that mirrors the kernel namespace:

    catalog.search                       -> geopera catalog search
    orders.archive.place                 -> geopera orders archive place
    orders.tasking.templates.save        -> geopera orders tasking templates save

Scalar request-body fields become ``--flags``; arrays of scalars become
repeatable flags; anything complex (nested objects, etc.) is supplied with
``--json`` (inline, ``@file``, or ``-`` for stdin). Flags override keys parsed
from ``--json``, so simple calls use flags and rich payloads use ``--json``.

The tree is built from a spec snapshot bundled in the package (``spec.json``),
so it is offline and fast and refreshes with each release. The raw
``geopera op <id>`` command remains as a hidden escape hatch for scripting and
any operation not yet in the snapshot.

Operation ids are guaranteed collision-free as a tree: no id is a prefix of
another, so every id is an unambiguous leaf and no name is both a group and a
command.
"""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from importlib import resources
from typing import Any

import click

from . import auth, client

# ---------------------------------------------------------------------------
# Spec loading + schema helpers
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _spec() -> dict:
    with resources.files("geopera_cli").joinpath("spec.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def _deref(spec: dict, node: Any) -> dict:
    """Resolve a single ``$ref`` against ``components.schemas`` (one hop)."""
    if isinstance(node, dict) and "$ref" in node:
        name = node["$ref"].split("/")[-1]
        return spec.get("components", {}).get("schemas", {}).get(name, {}) or {}
    return node if isinstance(node, dict) else {}


def _unwrap_nullable(prop: dict) -> dict:
    """Collapse a ``{anyOf: [<real>, {type: null}]}`` wrapper to ``<real>``."""
    if "type" not in prop and "anyOf" in prop:
        for branch in prop["anyOf"]:
            if isinstance(branch, dict) and branch.get("type") and branch["type"] != "null":
                return branch
    return prop


def _scalar(prop: dict):
    """Map a scalar/array-of-scalar schema to ``(click_type, is_multiple)``.

    Returns ``(None, False)`` for anything that must be supplied via ``--json``.
    ``"bool"`` is returned as a sentinel for boolean flags.
    """
    prop = _unwrap_nullable(prop)
    t = prop.get("type")
    if t == "string":
        return click.STRING, False
    if t == "integer":
        return click.INT, False
    if t == "number":
        return click.FLOAT, False
    if t == "boolean":
        return "bool", False
    if t == "array":
        item = _unwrap_nullable(prop.get("items", {}) or {})
        mapping = {"string": click.STRING, "integer": click.INT, "number": click.FLOAT}
        if item.get("type") in mapping:
            return mapping[item["type"]], True
    return None, False


def _fields(spec: dict, op: dict) -> list[dict]:
    """Derive the flaggable scalar fields from an operation's request body."""
    schema = (
        op.get("requestBody", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema")
    )
    schema = _deref(spec, schema)
    if "properties" not in schema and "anyOf" in schema:
        for branch in schema["anyOf"]:
            cand = _deref(spec, branch)
            if cand.get("properties"):
                schema = cand
                break
    props = schema.get("properties", {}) or {}
    required = set(schema.get("required", []) or [])
    fields: list[dict] = []
    for name, raw in props.items():
        ctype, multiple = _scalar(_deref(spec, raw))
        if ctype is None:
            continue  # complex field — only reachable via --json
        fields.append(
            {
                "orig": name,
                "flag": name.replace("_", "-"),
                "pyname": "f_" + name,
                "type": ctype,
                "multiple": multiple,
                "required": name in required,
                "help": (_unwrap_nullable(_deref(spec, raw)).get("description") or "").strip(),
            }
        )
    return fields


# ---------------------------------------------------------------------------
# Body resolution + error handling
# ---------------------------------------------------------------------------

def _read_json(arg: str) -> Any:
    if arg == "-":
        raw = sys.stdin.read()
    elif arg.startswith("@"):
        try:
            with open(arg[1:], encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            _fail(f"Cannot read {arg}: {exc}")
    else:
        raw = arg
    raw = raw.strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _fail(f"Invalid --json body: {exc}")


def _fail(message: str, code: int = 1):
    click.secho(f"Error: {message}", fg="red", err=True)
    raise SystemExit(code)


def _emit(value: Any) -> None:
    click.echo(json.dumps(value, indent=2, default=str))


# ---------------------------------------------------------------------------
# Command + group construction
# ---------------------------------------------------------------------------

def _make_leaf(op_id: str, summary: str, fields: list[dict]) -> click.Command:
    def callback(**kw: Any) -> None:
        profile = kw.pop("_profile", None)
        api_url = kw.pop("_api_url", None)
        json_body = kw.pop("_json", None)

        body: dict[str, Any] = {}
        if json_body:
            parsed = _read_json(json_body)
            if isinstance(parsed, dict):
                body = parsed
            else:
                _fail("--json must be a JSON object for this command.")

        for f in fields:
            v = kw.get(f["pyname"])
            if v is None or (f["multiple"] and not v):
                continue
            body[f["orig"]] = list(v) if f["multiple"] else v

        try:
            ctx = auth.load_context(profile, api_url)
            result = client.invoke_op(ctx, op_id, body)
        except auth.AuthError as exc:
            _fail(str(exc))
        except client.OpError as exc:
            detail = exc.detail.get("detail") or exc.detail.get("title")
            msg = f"[{exc.status}] {exc.message}"
            if detail and detail != exc.message:
                msg += f" — {detail}"
            _fail(msg, code=2)
        _emit(result)

    params: list[click.Parameter] = [
        click.Option(
            ["--json", "_json"],
            default=None,
            metavar="JSON",
            help="Full JSON body (inline, @file, or - for stdin). Flags override its keys.",
        )
    ]
    for f in fields:
        help_txt = ((f["help"] + (" [required]" if f["required"] else "")).strip()) or None
        if f["type"] == "bool":
            params.append(
                click.Option([f"--{f['flag']}/--no-{f['flag']}", f["pyname"]], default=None, help=help_txt)
            )
        else:
            params.append(
                click.Option(
                    [f"--{f['flag']}", f["pyname"]],
                    type=f["type"],
                    multiple=f["multiple"],
                    default=() if f["multiple"] else None,
                    help=help_txt,
                )
            )
    params.append(click.Option(["--profile", "_profile"], default=None, help="Stored identity (env: GEOPERA_PROFILE)."))
    params.append(click.Option(["--api-url", "_api_url"], default=None, help="API base URL override (env: GEOPERA_API_URL)."))

    help_text = summary or f"Invoke {op_id}."
    help_text += f"\n\nOperation: {op_id}"
    return click.Command(op_id.split(".")[-1].replace("_", "-"), params=params, callback=callback, help=help_text)


def _ensure_group(parent: click.Group, segments: list[str]) -> click.Group:
    node = parent
    for seg in segments:
        name = seg.replace("_", "-")
        existing = node.commands.get(name)
        if existing is None:
            existing = click.Group(name, help=f"`{seg}` operations.")
            node.add_command(existing)
        node = existing  # type: ignore[assignment]
    return node


def build_tree(root: click.Group) -> None:
    """Attach the generated ``resource action`` command tree to ``root``.

    Customer operations only — admin/internal (``admin:*`` scope) operations are
    excluded from the tree (they remain reachable via ``geopera op`` for the rare
    privileged caller).
    """
    spec = _spec()
    ops: list[tuple[str, dict]] = []
    for path, methods in spec.get("paths", {}).items():
        if not path.startswith("/v1/op/"):
            continue
        op = next(iter(methods.values()))
        if str(op.get("x-required-scope", "")).startswith("admin:"):
            continue
        ops.append((path[len("/v1/op/") :], op))

    for op_id, op in sorted(ops):
        segments = op_id.split(".")
        group = _ensure_group(root, segments[:-1])
        group.add_command(_make_leaf(op_id, (op.get("summary") or "").strip(), _fields(spec, op)))
