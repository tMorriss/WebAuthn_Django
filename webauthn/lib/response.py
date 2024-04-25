import json


class Response:
    @staticmethod
    def json(code, msg, data=None):
        response = {
            "statusCode": code,
            "statusMessage": msg
        }
        if data is not None:
            response.update(data)

        return json.dumps(response)

    @staticmethod
    def success(data):
        return Response.json("2000", "success", data)

    @staticmethod
    def format_error(msg):
        return Response.json("4001", "Format Error (" + msg + ")")

    @staticmethod
    def invalid_value_error(msg):
        return Response.json("4002", "Invalid Value Error (" + msg + ")")

    @staticmethod
    def unsupported_error(msg):
        return Response.json("4003", "Unsupported Error (" + msg + ")")

    @staticmethod
    def internal_server_error(msg):
        return Response.json("5001", "Internal Server Error (" + msg + ")")
