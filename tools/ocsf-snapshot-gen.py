#!/usr/bin/env python3
"""Generates the OCSF 1.9.0 schema snapshot (koru-store OCSF mapping tests) from the
official schema API.

Usage:
    python3 -I tools/ocsf-snapshot-gen.py <input-dir> <profile> > \
        crates/koru-store/tests/data/ocsf-1.9.0-snapshot.json

`<profile>` is the `profiles=` query value the inputs were downloaded with (`host` for the committed snapshot).

The input directory holds the responses downloaded by hand from
https://schema.ocsf.io/1.9.0/api (one request per class, object and the data types):
`classes/<name>.json` (`/classes/<name>?profiles=`), `objects/<name>.json`
(`/objects/<name>?profiles=`) and `data-types.json` (`/data_types`). The script never
touches the network and reads the inputs only as JSON data. Each input's SHA-256 digest is
written into the output.

The committed snapshot was downloaded with `profiles=host`: the `host` profile adds the `actor`
and `device` attributes to the classes (needed as the process source in network activity);
the osint, cloud etc. profiles are not included, so their required fields do not count as
requirements. An empty profile would leave network activity without `actor` or `device`.

Output: per class and object, attribute names, base types (int, str, bool, float, obj, any),
whether they are arrays, the required attributes, the `at_least_one`/`just_one` constraints
and the fixed value sets (`enum`). The tests check the mapping output against this snapshot.
"""

import hashlib
import json
import os
import sys

CLASSES = ["file_activity", "process_activity", "network_activity", "detection_finding"]
OBJECTS = [
    "metadata", "product", "device", "actor", "process", "file", "user", "network_endpoint",
    "network_connection_info", "finding_info", "analytic", "attack", "technique", "sub_technique",
    "tactic", "evidences", "container", "image", "observable", "reporter",
]


def base_types(data_types):
    result = {}
    for name, t in data_types.get("attributes", data_types).items():
        result[name] = t.get("type") or name
    return result


def root_type(name, mapping):
    seen = set()
    while name in mapping and mapping[name] != name and name not in seen:
        seen.add(name)
        name = mapping[name]
    return name


MODES = {
    "integer_t": "int", "long_t": "int", "string_t": "str", "boolean_t": "bool", "float_t": "float",
    "json_t": "any", "object_t": "obj",
}


def attributes(doc, mapping):
    result = {}
    for name, v in doc["attributes"].items():
        root = root_type(v.get("type", "string_t"), mapping)
        o = {"mode": MODES.get(root, "any"), "array": bool(v.get("is_array", False)), "requirement": v.get("requirement")}
        if v.get("object_type"):
            o["object"] = v["object_type"]
        if v.get("enum"):
            o["enum"] = sorted(v["enum"].keys(), key=lambda x: int(x) if x.lstrip("-").isdigit() else 0)
        result[name] = o
    return result


def doc_summary(doc):
    o = attributes(doc, doc["_mapping"])
    return {
        "required": sorted(k for k, v in o.items() if v["requirement"] == "required"),
        "at_least_one": sorted((doc.get("constraints") or {}).get("at_least_one", [])),
        "exactly_one": sorted((doc.get("constraints") or {}).get("just_one", [])),
        "attributes": dict(sorted(o.items())),
    }


def read(path):
    with open(path, "rb") as f:
        raw = f.read()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    directory = sys.argv[1]
    profile = sys.argv[2]
    data_types, digest = read(os.path.join(directory, "data-types.json"))
    digests = {"data-types.json": digest}
    mapping = base_types(data_types)
    output = {"ocsf_version": "1.9.0", "source": "https://schema.ocsf.io/1.9.0/api (profiles=" + profile + ")", "input_digests": digests,
              "classes": {}, "objects": {}}
    for name in CLASSES:
        doc, digest = read(os.path.join(directory, "classes", name + ".json"))
        digests["classes/" + name + ".json"] = digest
        doc["_mapping"] = mapping
        o = doc_summary(doc)
        o["class_uid"] = doc["uid"]
        o["category_uid"] = doc["category_uid"]
        o["name"] = doc["caption"]
        output["classes"][name] = o
    for name in OBJECTS:
        doc, digest = read(os.path.join(directory, "objects", name + ".json"))
        digests["objects/" + name + ".json"] = digest
        doc["_mapping"] = mapping
        output["objects"][name] = doc_summary(doc)
    json.dump(output, sys.stdout, ensure_ascii=False, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
