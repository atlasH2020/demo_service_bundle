import json
from pathlib import Path


def load_json_template(name):
    file = Path(f"api/templates/{name}.json")
    data = file.read_text()
    return json.loads(data)


def strip_private_meta(object):
    if isinstance(object, list):
        result = [{key: value for key, value in i.items() if not key.startswith("_")} for i in object]
    else:
        result = {key: value for key, value in object.items() if not key.startswith("_")}
    return result
