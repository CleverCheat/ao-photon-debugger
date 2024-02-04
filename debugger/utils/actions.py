import base64
import json
import os

from debugger.ressources.events import events
from debugger.ressources.operations import operations

for folder in ["sniff", "sniff/events", "sniff/requests", "sniff/responses"]:
    os.makedirs(folder, exist_ok=True)


def JSONizer(obj):
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("utf-8")
    else:
        raise TypeError(f"Unserializable type: {type(obj)}")


class Actions:
    @classmethod
    def on_event(cls, data):
        intersection_set = {252, 253}.intersection(data.parameters)
        if not intersection_set:
            return

        code = next(iter(intersection_set))

        code_label = events.get(data.parameters[code], "Unknown")
        file_path = os.path.join("sniff/events", f"{code_label}.json")
        json_data = {"parameters": data.parameters}

        if os.path.exists(file_path):
            with open(file_path, "r+") as f:
                try:
                    existing_data = json.load(f)
                except json.decoder.JSONDecodeError:
                    existing_data = []
        else:
            existing_data = []

        existing_data.append(json_data)

        with open(file_path, "w") as f:
            json.dump(existing_data, f, indent=4, default=JSONizer)

    @classmethod
    def on_request(cls, data):
        intersection_set = {252, 253}.intersection(data.parameters)
        if not intersection_set:
            return

        code = next(iter(intersection_set))

        code_label = operations.get(data.parameters[code], "Unknown")
        file_path = os.path.join("sniff/requests", f"{code_label}.json")
        json_data = {"parameters": data.parameters}

        if os.path.exists(file_path):
            with open(file_path, "r+") as f:
                try:
                    existing_data = json.load(f)
                except json.decoder.JSONDecodeError:
                    existing_data = []
        else:
            existing_data = []

        existing_data.append(json_data)

        with open(file_path, "w") as f:
            json.dump(existing_data, f, indent=4, default=JSONizer)

    @classmethod
    def on_response(cls, data):
        pass
